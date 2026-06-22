import os, sys, string, secrets, keyring, json, stat, requests, hashlib
from keyring.errors import KeyringError
from pathlib import Path
from platformdirs import user_config_dir, user_data_dir
from config import *


def print_error(error_msg: str) -> None:
    print(f"[ERROR]: {error_msg}", file=sys.stderr)

def print_msg(msg: str) -> None:
    print(f"[PWVAULT]: {msg}")

def print_password(password: str) -> None:
    if len(password) > 6:
        first = password[:2]
        last = password[-2:]
        print(f"[PWVAULT]: Password: {first}**********{last}")
    else:
        print(f"[PWVAULT]: Password: {password[0]}**********")

def generate_complex_password() -> string:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(24))
    return password

def generate_common_password() -> string:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*();"
    password = ''.join(secrets.choice(alphabet) for i in range(16))
    return password

def generate_safe_password() -> string:
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(16))
    return password

def get_default_vault_path() -> Path:
    """Determines where to store the vault file based on operating system"""
    # Check for user specified vault path.
    env_path = os.getenv('VAULT_PATH')
    if env_path:
        return Path(env_path)
    
    # Use standard OS location
    data_dir = Path(user_data_dir(APP_NAME, APP_AUTHOR, APP_VERSION))
    
    # Ensure the directory exists 
    data_dir.mkdir(parents=True, exist_ok=True)
    
    return data_dir / ".vault.pw"

def _get_token_file() -> Path:
    env_path = os.getenv('TOKEN_PATH')
    if env_path:
        return Path(env_path)
    
    config_dir = Path(user_config_dir(APP_NAME, APP_AUTHOR))
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "token.json"

def get_api_token() -> str | None:
    # 1. Environment override
    token = os.getenv("TOKEN_ENV_VAR")
    if token:
        return token

    # 2. OS keyring
    try:
        token = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
        if token:
            return token
    except KeyringError:
        pass
    except Exception:
        pass

    # 3. Local fallback file
    token_file = _get_token_file()
    if token_file.exists():
        try:
            data = json.loads(token_file.read_text())
            return data.get("api_token")
        except Exception:
            return None

    return None

def save_api_token(api_token: str) -> None:

    # First try OS keyring
    try:
        keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, api_token)
        return
    except KeyringError:
        pass
    except Exception:
        pass

    # Fallback to local file with restrictive permissions
    token_file = _get_token_file()
    token_file.write_text(json.dumps({"api_token": api_token}, indent=4))

    # Owner read/write only: chmod 600
    token_file.chmod(stat.S_IRUSR | stat.S_IWUSR)

def api_push_binary(api_token: str, vault) -> bool:
    # Get the uuid of the encrypted binary for server sync conflicts.
    version_token = vault.data.get("sync", {}).get("server_version_token")

    # Setup request headers
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/octet-stream",
    }

    # Use token if present
    if version_token:
        headers["X-Version-Token"] = version_token

    # PUT request to server with header and encrypted binary vault. Short timeout to avoid infinite hang. 
    response = requests.put(
        url=f"{SERVER_API_URL}/api/v1/vault/data/",
        data=vault.path.read_bytes(),
        headers=headers,
        timeout=15,
    )

    # See if we got a response
    try:
        response_data = response.json()
    except ValueError:
        response_data = {}

    # Update the sync data with our recieved inforamtion. 
    if response.status_code in (200, 201):
        vault.data.setdefault("sync", {})
        vault.data["sync"]["server_version_token"] = response_data["version_token"]
        vault.data["sync"]["server_content_hash"] = response_data["content_hash"]
        vault.data["sync"]["last_synced_at"] = response_data.get("updated_at")
        vault.save()
        return True


    if response.status_code == 409:
        raise Exception("Server has a newer/different vault. Pull first or resolve conflict.")

    raise Exception(response_data.get("detail", f"Upload failed: HTTP {response.status_code}"))

def api_pull_binary(api_token: str, vault, server_metadata: dict) -> bool:
    headers = {
        "Authorization": f"Bearer {api_token}",
    }

    response = requests.get(
        url=f"{SERVER_API_URL}/api/v1/vault/data/",
        headers=headers,
        timeout=15,
    )

    if response.status_code == 404:
        raise Exception("No vault exists on the server.")

    if response.status_code in (401, 403):
        raise Exception("Unauthorised token!")

    if response.status_code != 200:
        try:
            response_data = response.json()
        except ValueError:
            response_data = {}
        raise Exception(response_data.get("detail", f"Download failed: HTTP {response.status_code}"))

    downloaded = response.content

    downloaded_hash = hashlib.sha256(downloaded).hexdigest()
    if downloaded_hash != server_metadata["content_hash"]:
        raise Exception("Downloaded vault hash does not match server metadata. Refusing to replace local vault.")

    temp_path = vault.path.with_suffix(".download.tmp")
    temp_path.write_bytes(downloaded)

    # At minimum, replace only after hash verification.
    # Later: instantiate a temporary VaultContext and test decrypt before replacing.
    os.replace(temp_path, vault.path)

    return True

def get_valid_api_token() -> str:
    token = get_api_token()

    if token is None:
        raise ValueError("No API token. Please add a new API token first.")

    if len(token) != 47 or not token.startswith("pwv_"):
        raise ValueError("Token is invalid!")

    return token