**SecretVault** is a secure, console-based personal data manager written in Python.  
It encrypts and stores user credentials, passwords, and sensitive data with strong cryptographic methods, supporting both local and removable USB storage for portability and security.

---

## Features

- User sign-up and login with bcrypt password hashing and SHA-256 username hashing.
- Data encryption and decryption with libsodium/NaCl SecretBox and HKDF key derivation.
- Secure JSON storage of encrypted data, keys, and authentication info.
- Support for local storage or external USB drives (Windows-only USB detection/management).
- Manage encrypted user data: add, view, update, delete entries.
- Change password with secure re-encryption.
- Export user data to text files with overwrite protection.
- Transfer user data to USB and securely wipe local copies.
- Interactive CLI menu with clear options and help/FAQ.
- Automatic backup of authentication and key files.
- Modular codebase separating USB handling from main logic.

---

## Files Created by the Program

| File Name           | Purpose                                              |
|---------------------|------------------------------------------------------|
| AUTH.json         | Stores bcrypt-hashed passwords + salts + timestamps |
| AUTH_BACKUP.json  | Backup of AUTH.json                                  |
| KEY.json          | Stores base64-encoded encryption keys and salts    |
| KEY_BACKUP.json   | Backup of KEY.json                                   |
| DATABASE.json     | Stores encrypted user data entries                   |

---

## Project Structure

```plaintext
SecretVault/
├── run.py           # Main launcher script; checks dependencies, installs missing ones, runs program
├── main.py          # Core application logic (authentication, encryption, CLI menus, data management)
├── usb_monitor.py   # USB drive detection and management (Windows-specific)
├── AUTH.json        # User authentication data file (created on first run)
├── AUTH_BACKUP.json # Backup auth data file
├── KEY.json         # Encryption key data file
├── KEY_BACKUP.json  # Backup key data file
├── DATABASE.json    # Encrypted user data file
└── README.md        # This file
```

---

## How to Run

1. **Clone the repository:**

```bash
git clone https://github.com/sh4deee/SecretVault.git
cd SecretVault
```
Make sure Python 3.7 or higher is installed.

Run the launcher script run.py. It will:

Check if all required Python libraries are installed.

Prompt to install missing third-party modules (cryptography, colorama, pynacl, bcrypt, pywin32).

Automatically install missing dependencies if you confirm.

Launch the SecretVault application once dependencies are ready.

bash
Copy
Edit
python run.py
Usage Overview
Upon running, you will be presented with a menu to sign up or log in.

Choose to store your encrypted data locally or on a removable USB drive.

Use the intuitive CLI to add, view, edit, or delete your encrypted entries.

Change your password securely, which re-encrypts your data.

Export your data to text files or transfer and wipe data securely from the device.

Access help/FAQ anytime from the menu.

Dependencies
Python 3.7+

cryptography (for HKDF, hashing)

pynacl (libsodium SecretBox encryption)

bcrypt (password hashing)

colorama (optional, for colored CLI output)

pywin32 (Windows USB drive detection)

The run.py script handles dependency checking and installation automatically.

Platform Support
Tested on Windows (USB detection uses Windows API).

Local storage works cross-platform (Linux, macOS) if USB features are disabled/removed.

Thank you for using SecretVault — your secure personal data vault.
