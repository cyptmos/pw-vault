import argparse, base64, sys, os, getpass, json, uuid, time
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from utils import print_error, print_msg, print_password

SALT_SIZE = 16
VAULT_PATH = Path(os.getenv('VAULT_PATH', '.vault.pw'))
ARGON2_PARAMS = {
    "iterations": 3,
    "lanes": 4,
    "memory_cost": 64 * 1024,
    "length": 32
}

class VaultContext:
    """Handles Vault context, crypto and file I/O"""
    
    def __init__(self, path: Path):
        # File path the vault.pw file will be created / read from
        self.path: Path = path

        # crypto salt bytes from the vault.pw file
        self.salt: bytes = None

        # Fernet crypto key
        self.key: Fernet = None

        # Decrypted vault
        self.data = None

    def load_file(self):
        """Attempt to load the vault.pw file. Create one if it doesn't exist."""
        if self.path.exists():
            return self._authenticate()
        return self._create_vault()

    def _authenticate(self):
        """Load the Vault file. Check file. Read file and attempt to decrypt."""

        # Read bytes from the specified vault.pw file path
        raw_vault = self.path.read_bytes()

        # Check for file Corruption. 
        # TODO: CCurrently 32 reflects the key size. Change this to reflect base size of encrypted data within a new vault file.
        if len(raw_vault) < 32:
            self.path.unlink()
            print_error("Vault appears corrupted. Vault Deleted!")
            sys.exit(1)

        # Obtain the salt from the start of the file.
        self.salt = raw_vault[:SALT_SIZE]

        # Encrypted data should be the rest of the file.
        encrypted_data = raw_vault[SALT_SIZE:]

        # Ask user for their password using getpass and encode it to byte string. 
        # NOTE: This will store a password string in memory until GC can take it away. 
        vault_password = getpass.getpass("Enter Your Password: ").encode()

        # Attempt to get key using salt and password.
        self.key = self._get_key(vault_password, self.salt)

        # Try decrypt the data. If this fails at this stage, File I/O has failed or 
        # more likely the user has entered an incorrect password
        try:
            self.data = json.loads(self.key.decrypt(encrypted_data))
        except InvalidToken:
            print_error("Invalid Password!")
            sys.exit(1)

        # This will only delete the reference to the byte string, not the value. Better then nothing lol.
        del vault_password

    def _create_vault(self):
        """Creates a new vault.pw file"""
        print_msg("Creating new vault....")

        # Get new vault password 
        p1 = getpass.getpass("Enter a new vault password: ").encode()
        p2 = getpass.getpass("Re-enter the password: ").encode()

        # Confirm both match
        if p1 != p2:
            print_error("Passwords do not match!")
            sys.exit(1)

        # Generate new salt
        self.salt = os.urandom(SALT_SIZE)

        # generate new key
        self.key = self._get_key(p1, self.salt)

        # create base empty dict
        # TODO: This should be constructed elsewhere to allow for dict changes outside of this class
        self.data = {"version": 0.1, "accounts": {}}

        # Write changes to file
        self.save()

    def save(self):
        """Basic atomic file saving. NOTE: No metadata preservation"""
        # TODO: Work on a metadata preservation solution. I would assume linux users are only using this with the correct user premissions. 

        # Encrypt data in class
        encrypted_data = self.key.encrypt(json.dumps(self.data, indent=4).encode())

        # Create a temp file
        temp = self.path.with_suffix('.tmp')

        # Write to temp file
        temp.write_bytes(self.salt + encrypted_data)

        # replace original with temp
        os.replace(temp, self.path)

    def _get_key(self, password: bytes, salt: bytes) -> Fernet:
        """Generate a Fernet object using kdf"""
        # This might be a good place to implement other encryption types

        # Generate Argon2 object using salt and argon_params
        kdf = Argon2id(salt=salt, **ARGON2_PARAMS)

        # Return Fernet object. 
        return Fernet(base64.urlsafe_b64encode(kdf.derive(password)))
    
def handle_get(args, vault: VaultContext):
    service = args.service.lower()
    account = vault.data["accounts"].get(service)

    if not account:
        print_error(f"No account for {service} located!")

        # Its not an error if the account doesnt exist, we will just return to 0
        return

    if args.password_only:
        # print password without a \n. For testing, I would assume this would only really be used in piping a password in. 
        print(account['password'], end='')
    else:
        # TODO: Add the last updated time in here. Testing of this presentation first.
        print_msg(f"Service: {service}")
        print_msg(f"User:    {account['username'] or "None"}")
        print_msg(f"Email:   {account['email'] or "None"}")
        print_password(account['password'])

def handle_create(args, vault: VaultContext):
    service = args.service.lower()

    if service in vault.data['accounts']:
        print_error("Service already exists! Use 'update'.")
        return
    
    new_password = getpass.getpass(f"{service} Password: ")

    vault.data['accounts'][service] = {
        # ID field for use in future plans. maybe multiple services and/or cloud integration
        "id": str(uuid.uuid4()),
        "username": args.username or None,
        "email": args.email or None,
        "password": new_password,
        "created_at": time.time(),
        "updated_at": time.time()
    }

    vault.save()
    print_msg(f"{service} added to vault!")

    # once again, GC should get this.
    del new_password

def handle_update(args, vault: VaultContext):
    service = args.service.lower()
    account = vault.data["accounts"].get(service)

    if not account:
        print_error(f"No account for {service} located!")
        return
    
    if args.username is not None:
        vault.data['accounts'][service]['username'] = args.username

    if args.email is not None:
        vault.data['accounts'][service]['email'] = args.email

    if args.password:
        # I should probs delete these references after use however the GC should clear this. 
        new_password_1 = getpass.getpass(f"New {service} password: ")
        new_password_2 = getpass.getpass(f"New {service} password: ")

        if new_password_1 != new_password_2:
            print_error("Passwords do not match!")
            sys.exit(1)
        
        vault.data['accounts'][service]['password'] = new_password_1

    # Anytime the update func is called on a service, it should update the updated at time
    vault.data['accounts'][service]['updated_at'] = time.time()

    vault.save()
    print_msg(f"{service} updated!")
    
def handle_delete(args, vault: VaultContext):
    service = args.service.lower()
    account = vault.data["accounts"].get(service)

    if not account:
        print_error(f"No account for {service} located!")
        return
    
    vault.data["accounts"].pop(service)
    vault.save()

    print_msg(f"{service} deleted!")

def handle_list(args, vault: VaultContext):
    # TODO: List all accounts for east piping.
    # TODO: List all accounts with certain credentials
    # TODO: Search accounts?
    for account, _ in vault.data["accounts"].items():
        print_msg(account)

def main():
    # Init the parser
    parser = argparse.ArgumentParser(
            prog='PW Vault',
            description='A simple password vault application written in Python.')

    subparsers = parser.add_subparsers(dest="command", required=True)

    # "create" command subparser
    create_parser = subparsers.add_parser('create', help="Create an entry")
    create_parser.add_argument("service", type=str, help="Provide a service name")
    create_parser.add_argument("-e","--email", type=str, help="Provide an email")
    create_parser.add_argument("-u","--username", type=str, help="Provide the username")

    # The following is INSECURE as the value is held in plain text bash history. Only for testing. 
    # create_parser.add_argument("-p","--password", type=str, help="Provide the password")

    # "get" command subparser
    get_parser = subparsers.add_parser('get', help="Get an Account")
    get_parser.add_argument("service", type=str, help="Provide a service name to get")
    get_parser.add_argument("-p", "--password-only", action='store_true') 

    # "update" command subparser
    update_parser = subparsers.add_parser('update', help="Update an account")
    update_parser.add_argument("service", type=str, help="Provide a service name")
    update_parser.add_argument("-e","--email", type=str, help="Provide an email")
    update_parser.add_argument("-u","--username", type=str, help="Provide the username")
    update_parser.add_argument("-p", "--password", action='store_true', help="Indicate if the password needs to be changed") 

    # "delete" command subparser
    delete_parser = subparsers.add_parser('delete', help="Delete an Account")
    delete_parser.add_argument("service", type=str, help="Provide a service name to delete")

    # "list" command subparser
    list_parser = subparsers.add_parser('list', help="List all services")


    args = parser.parse_args()

    # Init vault context
    vm = VaultContext(VAULT_PATH)
    vm.load_file()

    # parser commands mapped to functions
    commands = {
        "create": handle_create,
        "get": handle_get,
        "update": handle_update,
        "delete": handle_delete,
        "list": handle_list
    }
    
    handler = commands.get(args.command)

    if handler:
        handler(args, vm)

    return 0

if __name__ == "__main__":
    main()