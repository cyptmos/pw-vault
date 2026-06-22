import argparse, base64, sys, os, getpass, json, uuid, time, requests, struct
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from config import *
from utils import (
    print_error,
    print_msg,
    print_password,
    generate_complex_password,
    generate_common_password,
    generate_safe_password,
    save_api_token,
    get_api_token,
    get_default_vault_path,
    api_push_binary,
    api_pull_binary,
    get_valid_api_token
)

VAULT_PATH = get_default_vault_path()

class VaultContext:
    """Handles Vault context, crypto and file I/O"""
    
    def __init__(self, path: Path):
        # File path the vault.pw file will be created / read from
        self.path: Path = path

        # Crypto salt bytes from the vault.pw file
        self.salt: bytes = None

        # Crypto nonce value
        self.nonce: bytes = None

        # Crypto key
        self.key: AESGCM = None

        # Decrypted vault
        self.data = None

        # Accociated metadata
        self.metadata = None

        # private vault values
        self._file_header = b'PWVLT'
        self._container_version = 1
        self._header_size = 4

    def load_file(self):
        """Attempt to load the vault.pw file. Create one if it doesn't exist."""
        if self.path.exists():
            return self._authenticate()
        return self._create_vault()

    def _authenticate(self):
        """Load the Vault file. Check file. Read file and attempt to decrypt."""

        # Read bytes from the specified vault.pw file path
        raw_vault = self.path.read_bytes()

        # check for file integrity issues
        if len(raw_vault) < len(self._file_header) + 1 + self._header_size:
            raise ValueError("Vault appears corrupted!")

        # To track where we are at in the binary file
        offset = 0

        # First, get the fileheader and update the offset. 
        file_header = raw_vault[offset:offset + len(self._file_header)]
        offset += len(self._file_header)

        # Check the file header is correct, otherwise this might be the wrong file.
        if file_header != self._file_header:
            raise ValueError("Vault file is either wrong or corrupted!")
        
        # Now get the container version and update the offset
        container_version = raw_vault[offset]
        offset += 1

        # Check if the container version is correct
        if container_version != self._container_version:
            raise ValueError("Vault file version mismatch!")
        
        # Get the header information by first determining how much binary data it is. 
        header_length = struct.unpack(">I", raw_vault[offset:offset + self._header_size])[0]
        offset += self._header_size

        if header_length <= 0:
            raise ValueError("Invalid vault header length!")

        if offset + header_length > len(raw_vault):
            raise ValueError("Vault header length exceeds file size!")

        # Get the header data
        raw_metadata = raw_vault[offset:offset + header_length]
        self.metadata = json.loads(raw_metadata.decode("utf-8"))

        offset += header_length

        # Encrypted data should be the rest of the file.
        encrypted_data = raw_vault[offset:]

        if not encrypted_data:
            raise ValueError("No encrypted data!")

        # Obtain salt and nonce
        self.salt = base64.urlsafe_b64decode(self.metadata['salt'])
        self.nonce = base64.urlsafe_b64decode(self.metadata['cipher']['nonce'])

        # Ask user for their password using getpass and encode it to byte string. 
        vault_password = getpass.getpass("Enter Your Password: ").encode()

        # Attempt to get key using password.
        self.key = self._get_key(vault_password, self.salt, self.metadata)

        # Try decrypt the data. If this fails at this stage, File I/O has failed or 
        # more likely the user has entered an incorrect password
        try:

            decrypted_data = self.key.decrypt(self.nonce, encrypted_data, raw_metadata)
            self.data = json.loads(decrypted_data.decode("utf-8"))
        except InvalidTag:
            print_error("Invalid password or vault file has been tampered with!")
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

        # Vault metadata fields:
        vault_id = str(uuid.uuid4())
        kdf_params = {
            "iterations": 1,
            "lanes": 4,
            "memory_cost": 64 * 1024,
            "length": 32
        }

        # Generate nonce
        self.nonce = os.urandom(12)

        # Generate new salt
        self.salt = os.urandom(16)

        # Build the vault header
        self.metadata = {
            "vault_id": vault_id,
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
            "kdf": {
                "name": "argon2id",
                "params": kdf_params,
            },
            "salt": base64.urlsafe_b64encode(self.salt).decode("ascii"),
            "cipher": {
                "name": "aesgcm",
                "nonce": base64.urlsafe_b64encode(self.nonce).decode("ascii")
            }
        }

        # generate new key
        self.key = self._get_key(p1, self.salt, self.metadata)

        # create base empty dict
        self.data = {
            "version": APP_VERSION, 
            "presets": {"username": None, "email": None},
            "sync": {
                "server_version_token": None,
                "server_content_hash": None,
                "last_synced_at": None
            },
            "accounts": {}}

        # Write changes to file
        self.save()

    def save(self):
        """Basic atomic file saving."""

        # AES-GCM requires a fresh nonce for every encryption with the same key.
        self.nonce = os.urandom(12)
        self.metadata["cipher"]["nonce"] = base64.urlsafe_b64encode(self.nonce).decode("ascii")

        # Update the "updated_at" metadata
        self.metadata["updated_at"] = int(time.time())

        # Make sure the file path exists!
        self.path.parent.mkdir(parents=True, exist_ok=True)

        _encoded_data = json.dumps(self.data, indent=4).encode("utf-8")
        _encoded_metadata = json.dumps(self.metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")

        # pack the length into an big-endian (">") unsigned ("I") int (4 bytes) binary string
        _header_length = struct.pack(">I", len(_encoded_metadata))

        # Encrypt data in class
        encrypted_data = self.key.encrypt(self.nonce, _encoded_data, _encoded_metadata)

        # Create a temp file
        temp = self.path.with_suffix('.tmp')

        # Write to temp file
        temp.write_bytes(self._file_header + bytes([self._container_version]) + _header_length + _encoded_metadata + encrypted_data)

        # replace original with temp
        os.replace(temp, self.path)

    def _get_key(self, password: bytes, salt: bytes, metadata: dict) -> AESGCM:
        """Generate a AES object using kdf"""

        # Setup the kdf with the header info
        kdf = Argon2id(salt=salt, **metadata['kdf']['params'])

        return AESGCM(kdf.derive(password))
        # Return Fernet object. 
        #return Fernet(base64.urlsafe_b64encode(kdf.derive(password)))
    
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
    
    new_password = None

    if args.generate_password:
        new_password = generate_complex_password()
    else:
        new_password = getpass.getpass(f"{service} Password: ")

    vault.data['accounts'][service] = {
        # ID field for use in future plans. maybe multiple services and/or cloud integration
        "id": str(uuid.uuid4()),
        "password": new_password,
        "created_at": time.time(),
        "updated_at": time.time()
    }

    if args.use_presets:
        vault.data['accounts'][service]["username"] = vault.data['presets']['username'] or None
        vault.data['accounts'][service]["email"] = vault.data['presets']['email'] or None
    else:
        vault.data['accounts'][service]["username"] = args.username or None
        vault.data['accounts'][service]["email"] = args.email or None

    vault.save()
    print_msg(f"{service} added to vault!")

    # once again, GC should get this. Should consider manual byte array
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
    
    if not vault.data["accounts"]:
        print_error(f"No accounts located!")
        return

    for account, _ in vault.data["accounts"].items():
        print(account)

def handle_generate(args, vault: VaultContext):
    """Generate random passwords"""
    if args.safe:
        if args.password_only:
            print(f"{generate_safe_password()}", end="")
            return
        print_msg(f"{generate_safe_password()}")
        return
    
    if args.common:
        if args.password_only:
            print(f"{generate_common_password()}", end="")
            return
        print_msg(f"{generate_common_password()}")
        return
    
    if args.password_only:
        # print password without a \n
        print(f"{generate_complex_password()}", end="")
        return
    
    print_msg(f"{generate_complex_password()}")
    return

def handle_preset(args, vault: VaultContext):
    """Handles preset data in the vault, allowing for quick account creation"""
    if args.username is not None:
        vault.data['presets']["username"] = args.username
        print_msg(f"{args.username} set as a preset username")

    if args.email is not None:
        vault.data['presets']["email"] = args.email
        print_msg(f"{args.email} set as a preset email")

    vault.save()
    
def handle_sync(args, vault: VaultContext):
    """Handle API related functions."""
    if args.new_token:
        token = input("Enter the api token here: ")
        save_api_token(token)
        return

    if args.push:
        token = get_valid_api_token()
        
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(f"{SERVER_API_URL}/api/v1/vault/", headers=headers)

        if response.status_code == 404:
            # No server vault exists yet. First upload is okay.
            api_push_binary(token, vault)
            return

        if response.status_code == 200:
            server = response.json()

            local_sync = vault.data.get("sync", {})
            local_server_version = local_sync.get("server_version_token")

            if local_server_version is None:
                raise Exception("Server already has a vault, but this local vault has never synced. Pull first or resolve manually.")

            if server["version_token"] != local_server_version:
                raise Exception("Server vault has changed. Pull first before pushing.")

            api_push_binary(token, vault)
            return

        if response.status_code in (401, 403):
            raise Exception("Unauthorised token!")

        raise Exception(f"Unexpected server response: {response.status_code}")

    if args.pull:
        token = get_valid_api_token()

        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{SERVER_API_URL}/api/v1/vault/", headers=headers, timeout=15)

        if response.status_code == 404:
            raise Exception("No server vault exists. Try pushing first.")

        if response.status_code in (401, 403):
            raise Exception("Unauthorised token!")

        if response.status_code != 200:
            raise Exception(f"Unexpected server response: {response.status_code}")

        server = response.json()

        local_sync = vault.data.get("sync", {})
        local_server_version = local_sync.get("server_version_token")

        if local_server_version == server["version_token"]:
            print_msg("Local file already up to date with server.")
            return

        api_pull_binary(token, vault, server)

        print_msg("Vault pulled from server.")
        return


def main():
    # Init the parser
    parser = argparse.ArgumentParser(
            prog='PW Vault',
            description='A simple password vault application written in Python.')

    subparsers = parser.add_subparsers(dest="command", required=True)

    # "create" command subparser
    create_parser = subparsers.add_parser('create', help="Create an entry.")
    create_parser.add_argument("service", type=str, help="Provide a service name.")
    create_parser.add_argument("-e","--email", type=str, help="Provide an email.")
    create_parser.add_argument("-u","--username", type=str, help="Provide the username.")
    create_parser.add_argument("-s","--use-presets", action='store_true', help="Use saved presets to create the account.")
    create_parser.add_argument("-g","--generate-password", action='store_true', help="Automatically generate a strong complex password")

    # "get" command subparser
    get_parser = subparsers.add_parser('get', help="Get an Account.")
    get_parser.add_argument("service", type=str, help="Provide a service name to get.")
    get_parser.add_argument("-p", "--password-only", action='store_true', help="Output only the password.") 

    # "update" command subparser
    update_parser = subparsers.add_parser('update', help="Update an account")
    update_parser.add_argument("service", type=str, help="Provide a service name")
    update_parser.add_argument("-e","--email", type=str, help="Provide an email")
    update_parser.add_argument("-u","--username", type=str, help="Provide the username")
    # TODO: Change this to avoid confusion with other -p commands
    update_parser.add_argument("-P", "--password", action='store_true', help="Indicate if the password needs to be changed") 

    # "delete" command subparser
    delete_parser = subparsers.add_parser('delete', help="Delete an Account")
    delete_parser.add_argument("service", type=str, help="Provide a service name to delete")

    # "list" command subparser
    list_parser = subparsers.add_parser('list', help="List all services")

    # "generate" command subparser
    generate_parser = subparsers.add_parser('generate', help="Generate a secure 24-character password")
    generate_parser.add_argument("-c", "--common", action='store_true', help="Adhere to common service password requirements. 16-characters")
    generate_parser.add_argument("-s", "--safe", action='store_true', help="Use only 'safe' characters such as letters and numbers")
    generate_parser.add_argument("-p", "--password-only", action='store_true', help="Output only the password.")

    # "presets" command subparser
    preset_parser = subparsers.add_parser("set-preset", help="Setup default usernames and emails for generated accounts")
    preset_parser.add_argument("-u", "--username", type=str, help="Set the default username")
    preset_parser.add_argument("-e", "--email", type=str, help="Set the default email")

    # "sync" command subparser
    sync_parser = subparsers.add_parser("sync", help="Connect to PW Vault clould service for password vault sync.")
    sync_parser.add_argument("-n", "--new-token", action="store_true", help="Updates the API token.")
    sync_parser.add_argument("-p", "--push", action="store_true", help="Push local vault to the server.")
    sync_parser.add_argument("-u", "--pull", action="store_true", help="Pull latest vault from server.")

    # Arg parser
    args = parser.parse_args()

    # functions that dont require vault decryption
    if args.command == "generate":
        handle_generate(args, None)
        return 0

    if args.command == "sync" and args.new_token:
        handle_sync(args, None)
        return 0


    # Init vault context
    vm = VaultContext(VAULT_PATH)
    vm.load_file()

    # parser commands mapped to functions
    commands = {
        "create": handle_create,
        "get": handle_get,
        "update": handle_update,
        "delete": handle_delete,
        "list": handle_list, 
        "set-preset": handle_preset,
        "sync": handle_sync
    }
    
    handler = commands.get(args.command)

    if handler:
        handler(args, vm)

    return 0

if __name__ == "__main__":
    main()