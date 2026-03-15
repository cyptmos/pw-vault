# 🔐 PW Vault (Password Vault)

A lightweight CLI password manager built with Unix environments in mind. Designed for users who want to pipe credentials into other applications or store account data locally.

⚠️ Disclaimer: This project was developed as a personal security tool. While it implements industry-standard cryptographic functions (Argon2id, Fernet/AES), Always evaluate your own security needs before using my personal project for sensitive data ⚠️.

## Features
- Argon2id to derive encryption keys.
- Fernet (AES-128 in CBC mode with HMAC).
- Atomic saves.
- Support for --password-only flags to allow seamless piping into other CLI tools.


## 🥅 Goals

- [x] Basic CRUD CLI functionality
- [x] Secure local file I/O
- [ ] Automated Password Generation
- [ ] Cloud Sync: Remote vault retrieval
- [ ] Notes and Secure File storage
- [ ] Web client / server architecture
- [ ] Optional 2FA support