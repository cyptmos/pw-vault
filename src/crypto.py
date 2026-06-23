import base64, sys, os, getpass, json, uuid, time, struct
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from config import *
from utils import (
    print_error,
    print_msg,
)


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