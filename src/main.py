import argparse, sys, getpass, uuid, time, requests
from config import *
from crypto import VaultContext
from utils import (
    print_error,
    print_msg,
    print_password,
    generate_complex_password,
    generate_common_password,
    generate_safe_password,
    save_api_token,
    get_valid_api_token,
    get_default_vault_path,
    api_push_binary,
    api_pull_binary,
)

VAULT_PATH = get_default_vault_path()

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
    if not vault.data["accounts"]:
        print_error(f"No accounts located!")
        return

    for account, _ in vault.data["accounts"].items():
        print(account)

def handle_generate(args):
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
        handle_generate(args)
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