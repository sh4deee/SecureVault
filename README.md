# SecretVault - Encrypted Personal Data Manager with USB Support

**SecretVault** is a secure, console-based personal data manager written in Python.  
It encrypts and stores user credentials, passwords, and sensitive data with strong cryptographic methods, and supports saving data locally or on removable USB drives for portability and security.

---

## Features

- User sign-up and login with password hashing (bcrypt) and username hashing (SHA-256).
- Data encryption and decryption using modern cryptographic standards (libsodium/NaCl and HKDF).
- Secure storage of encrypted data, keys, and authentication info in JSON files.
- Support for local storage or external USB drives (Windows-only USB detection and management).
- Manage encrypted user data: add, view, update, delete entries.
- Change password functionality with re-encryption.
- Export user data to text files with overwrite protection.
- Transfer user data to USB and securely wipe local copies.
- Interactive CLI menu with clear options and help/FAQ.
- Automatic backup of authentication and key files.
- Modular code with separation between USB management and main logic.

---

## Files Created by the Program

SecretVault maintains the following files (all JSON format):

| File Name          | Purpose                                  |
|--------------------|------------------------------------------|
| `AUTH.json`        | Stores bcrypt-hashed passwords + salts + timestamps |
| `AUTH_BACKUP.json` | Backup of AUTH.json                      |
| `KEY.json`         | Stores base64-encoded encryption keys and salts |
| `KEY_BACKUP.json`  | Backup of KEY.json                       |
| `DATABASE.json`    | Stores encrypted user data entries      |

---
## How to Run

1. **Clone the repository:**

```bash
git clone https://github.com/YourUsername/SecretVault.git
cd SecretVault
