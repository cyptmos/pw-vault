# 🔐 PW Vault (Password Vault)

A lightweight CLI password manager built with Unix environments in mind. Designed for users who want to pipe credentials into other applications or store account data locally.

⚠️ Disclaimer: This project was developed as a personal security tool. While it implements standard cryptographic functions (Argon2id, Fernet/AES), Always evaluate your own security needs before using my personal project for sensitive data.

## Features
- Argon2id to derive encryption keys.
- AES-GCM
- Atomic saves.
- Support for piping into other CLI tools.

## How To Use
By default, PW Vault inits an encrypted vault file in the OS standard application data directory upon the first execution of any command.

### Custom Vault Location
You can override the default storage location by setting the VAULT_PATH environment variable. This is useful for keeping separate vaults or storing your vault on a secure external drive.

    export VAULT_PATH="./my_secret_vault.pw"
    ./pw-vault list

### Adding a New Account
To add a service, provide the service name and optional flags for the username and email. The application will prompt you for the password to ensure it is not saved in your shell history.

    ./pw-vault create github -u my_username -e user@example.com

If you wish for a complex password to be generated instead, use the -g flag. 

    ./pw-vault create github -u my_username -e user@example.com -g

If you use the same username and / or email address, a preset can be generated, allowing quick account creation.

    ./pw-vault create github -s -g 

### Updating an Account
You can update specific fields without affecting others. To trigger a password change prompt, use the -P flag.

    ./pw-vault update github -u new_username -P

### Get Account Data
You can get account data by specifing the service.

    ./pw-vault get github

For use in scripts or Unix pipelines, use the --password-only (or -p) flag. This outputs the raw password to stdout without any labels or metadata, allowing you to pipe it directly to your clipboard or another application.

    ./pw-vault get github -p | .......

### List All Accounts
Provide the "list" command to view a list of services

    ./pw-vault list

### Deleting an Account
To permenently delete a service, use the delete command. 

    ./pw-vault delete github

### Generating Passwords
The application will generate secure passwords depending on requirements.
⚠️ WARNING: this outputs a generated password to the stdout ⚠️

    ./pw-vault generate

### Setting presets
If you use the same username and or email address, this can be presaved and used during account creation.

    ./pw-vault set-preset -u my_username -e user@example.com

### WIP: Syncing with cloud ⚠️. 
Web application comming soon! To add your API token, use the following:

    ./pw-vault sync -n

Token storage is operating system dependent, with Windows and MacOS storing keys in the OS credential store. Linux is a little more tricky. If a credential store is not avaliable, a json file with chmod 600 premissions in the user directory. To push your vault to the server, call:

    ./pw-vault sync -p

To get the latest vault from the server:

    ./pw-vault sync -u

## 🥅 Goals
- [x] Basic CRUD CLI functionality
- [x] Secure local file I/O
- [x] Automated Password Generation and account presets
- [ ] Notes and Secure File storage
- [x] Cloud Sync through web application
- [ ] Optional 2FA support