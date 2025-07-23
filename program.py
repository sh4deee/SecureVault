import base64
import hashlib
from hashlib import pbkdf2_hmac
import json
import os
import threading
import time
import bcrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import nacl.utils
from nacl.secret import SecretBox
from usb_monitor import USBManager

class Program:
    def __init__(self, use_usb=False, usb_root=None):
        # USB related
        self.use_usb = use_usb        # bool, default False
        self.usb_root = usb_root      # string or None

        self.base_folder = "secretvault"  # or "SaveVault" if renamed later
        self.base_path = os.path.join(os.getcwd(), self.base_folder)

        # Ensure local base folder exists
        os.makedirs(self.base_path, exist_ok=True)

        # Define full paths inside base path (local)
        self.database_file = os.path.join(self.base_path, "DATABASE.json")
        self.auth_file = os.path.join(self.base_path, "AUTH.json")
        self.auth_backup_file = os.path.join(self.base_path, "AUTH_BACKUP.json")
        self.key_file = os.path.join(self.base_path, "KEY.json")
        self.key_backup_file = os.path.join(self.base_path, "KEY_BACKUP.json")

        # Load local data JSON files
        self.database_dec = self.load_data_json(self.database_file)
        self.auth_dec = self.load_data_json(self.auth_file, self.auth_backup_file)
        self.key_dec = self.load_data_json(self.key_file, self.key_backup_file)

        self.secretvault_dir = None
        self.active_database_file = None
        self.active_auth_file = None
        self.active_auth_backup_file = None
        self.active_key_file = None
        self.active_key_backup_file = None

        self.active_auth_dec = None
        self.active_key_dec = None
        self.active_database_dec = None

        # USB Manager and USB sets
        self.usb_manager = USBManager()
        self.usb_data = set()
        self.useable_usb = set()  # subset of usb_data that are writable
        self.usb_connected = False

        # Start USB monitor in a daemon thread (non-blocking)
        self.usb_thread = threading.Thread(target=self.usb_monitor, daemon=True)
        self.usb_thread.start()

    def clear_and_print_logo(self):
        os.system('cls' if os.name == 'nt' else 'clear')


        width = 80  # fixed terminal width fallback

        title = "SECURE VAULT v1.0"
        separator = "=" * width

        banner_lines = [
            "    _____                         _    __            ____ ",
            "   / ___/___  _______  __________| |  / /___ ___  __/ / /_",
            "   \\__ \\/ _ \\/ ___/ / / / ___/ _ \\ | / / __ `/ / / / / __/",
            "  ___/ /  __/ /__/ /_/ / /  /  __/ |/ / /_/ / /_/ / / /_  ",
            " /____/\\___/\\___/\\__,_/_/   \\___/|___/\\__,_/\\__,_/_/\\__/  ",
        ]

        print(separator + "\n")
        for line in banner_lines:
            print(line.center(width))
        print("\n" + title.center(width) + "\n")
        print(separator)



    def path_exist(self, file_path):
        """Check if the file exists."""
        return os.path.exists(file_path)

    def save_data_json(self, data, file):
        with open(file, "w") as f:
            json.dump(data, f, indent=4)

    def load_data_json(self, *files):
        """
        Load and merge JSON data from multiple files inside a folder.

        If `self.usb_root` is set, uses it as the root folder path;
        otherwise defaults to a local 'secretvault' folder in the current directory.
        Automatically creates missing files with empty JSON objects (`{}`).
        Corrupt files are reset to empty JSON and an error message is printed.

        Args:
            *files (str): Filenames to load and merge.

        Returns:
            dict or None: Merged JSON data from all files, or None if no data was loaded.
        """
        import os
        import json

        folder = os.path.join(self.usb_root, "secretvault") if self.usb_root else "secretvault"
        os.makedirs(folder, exist_ok=True)

        merged_data = {}

        for filename in files:
            filepath = os.path.join(folder, filename)

            # Create empty JSON file if missing
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    json.dump({}, f, indent=4)

            try:
                with open(filepath, 'r') as f:
                    file_data = json.load(f)

                for key, value in file_data.items():
                    if key in merged_data and isinstance(merged_data[key], dict) and isinstance(value, dict):
                        merged_data[key].update(value)
                    else:
                        merged_data[key] = value

            except (json.JSONDecodeError, IOError) as e:
                print(f"[!] Error loading {filepath}: {e}")
                # Reset corrupt file to empty JSON
                with open(filepath, 'w') as f:
                    json.dump({}, f, indent=4)

        return merged_data if merged_data else None

    def load_usb_data(self):
        """
        Detect and load JSON data files (AUTH.json, KEY.json, DATA.json) from all connected USB 'secretvault' folders.

        Uses `find_secretvault()` to locate all relevant USB folders.
        For each found folder, attempts to load and merge data from the three JSON files if they exist.

        Returns:
            tuple of dict or None:
                - usb_auth_data (dict): Merged authentication data from all USB folders, or empty dict if none found.
                - usb_key_data (dict): Merged key data from all USB folders, or empty dict if none found.
                - usb_data_data (dict): Merged user data from all USB folders, or empty dict if none found.

            Returns (None, None, None) if no 'secretvault' folders are found.

        Notes:
            - Each data type is aggregated by updating the corresponding dictionary.
            - If JSON files are missing or empty, they are skipped silently.
        """

        sv_folders = self.find_secretvault()
        if not sv_folders:
            return None, None, None  # No USB folders found, just return nothing

        usb_auth_data = {}
        usb_key_data = {}
        usb_data_data = {}

        for sv_folder in sv_folders:
            auth_path = os.path.join(sv_folder, "AUTH.json")
            key_path = os.path.join(sv_folder, "KEY.json")
            data_path = os.path.join(sv_folder, "DATA.json")

            if os.path.exists(auth_path):
                auth_data = self.load_data_json(auth_path)  
                if auth_data:
                    usb_auth_data.update(auth_data)

            if os.path.exists(key_path):
                key_data = self.load_data_json(key_path)
                if key_data:
                    usb_key_data.update(key_data)

            if os.path.exists(data_path):
                data_data = self.load_data_json(data_path)
                if data_data:
                    usb_data_data.update(data_data)

        return usb_auth_data, usb_key_data, usb_data_data



    def usb_monitor(self, poll_interval=2):
        """
        Continuously monitor USB drives, updating the list of usable USB drives every `poll_interval` seconds.

        Checks all currently connected removable drives and tests write access by creating and deleting a temporary file.
        Only drives where writing is successful are added to `self.useable_usb`.

        Args:
            poll_interval (int): Time in seconds between each polling cycle. Default is 2 seconds.

        Notes:
            - Runs an infinite loop; designed to be run in a dedicated thread or background process.
            - Silently ignores exceptions during drive checking to avoid crashes.
        """
        while True:
            try:
                self.usb_manager.update_drives(self.usb_data)
                self.useable_usb.clear()
                for drive in self.usb_data:
                    test_file = os.path.join(drive, "temp_test_file.tmp")
                    try:
                        with open(test_file, 'w') as f:
                            f.write('test')
                        os.remove(test_file)
                        self.useable_usb.add(drive)
                    except Exception:
                        pass
            except Exception:
                pass
            time.sleep(poll_interval)



    def derive_final_key(self, password, salt, user_entropy=None):
        """
        Derives a final encryption key by combining a password, salt, and optional user-specific entropy (key).

        This function generates a strong 32-byte encryption key using PBKDF2 with HMAC (SHA-512) followed by 
        HKDF (HMAC with SHA-512). If a key is provided, it is combined with the password during the derivation.

        Args:
            paswrd (str): The plaintext password used in the derivation process. This is the user’s password.
            salt (bytes): A unique salt value used to strengthen the key derivation process, ensuring uniqueness for each user.
            key (bytes, optional): Optional entropy (additional key material) to be combined with the password. 
                                If not provided, a new random key will be generated.

        Returns:
            final_key (bytes): The final derived encryption key of length SecretBox.KEY_SIZE (32 bytes).
            key (bytes): The original user-specified entropy (if provided). If a new key was generated, this is returned.
        """

        # If no user-specific entropy is provided, generate random 32-byte entropy
        generated = False
        if user_entropy is None:
            user_entropy = nacl.utils.random(SecretBox.KEY_SIZE)
            generated = True

        # Derive an intermediate key using PBKDF2-HMAC-SHA512
        intermediate_key = pbkdf2_hmac(
            hash_name="sha512",
            password=password.encode('utf-8') + user_entropy,
            salt=salt,
            iterations=500_000,
            dklen=64
        )

        # Final key derivation using HKDF to ensure uniform key size and separation
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=SecretBox.KEY_SIZE,
            salt=salt,  # Optional: use a different salt here if desired
            info=b"final-key-derivation"
        )
        final_key = hkdf.derive(intermediate_key)

        if generated:
            return final_key, user_entropy
        return final_key

    def hash_password(self, passwrd, salt=None):
        """
        Hashes a password using bcrypt and an optional salt.

        If a salt is provided, it uses that for hashing; if no salt is provided, a new random salt is generated. 
        The hashed password is returned as a base64-encoded string for storage.

        Args:
            password (str): The password to be hashed.
            salt (str, optional): The salt to use for hashing. If not provided, a new salt is generated.

        Returns:
             tuple or str: 
                - If a new salt is generated: 
                    (hashed_password: str, salt: str)
                - If a salt is provided:
                    hashed_password: str
        """

        generated = False
        if salt is None:
            salt = bcrypt.gensalt()
            generated = True

        hashed_data = bcrypt.hashpw(passwrd.encode('utf-8'), salt)
        hashed_paswrd = base64.b64encode(hashed_data).decode('utf-8')

        if generated:
            return hashed_paswrd, salt
        return hashed_paswrd
       
    def hash_username(self, username):
        """
        Hashes a username using SHA-256.

        This function returns a secure, unique hash for a given username. This hash is used to ensure that usernames 
        are stored securely, making it difficult to reverse-engineer the original value.

        Args:
            username (str): The username to hash.

        Returns:
            str: The SHA-256 hash of the username, represented as a hexadecimal string.
        """

        sha256 = hashlib.sha256(username.encode('utf-8')) 
        return sha256.hexdigest()

    def encrypt_data(self, final_key, plain_text): 
        """
        Encrypts a given plaintext using a final encryption key.

        The function uses the `SecretBox` encryption algorithm from the `nacl` library to encrypt the data. 
        The encrypted data is then base64 encoded for storage.

        Args:
            final_key (bytes): The encryption key used to encrypt the data.
            plain_text (str): The plaintext data to be encrypted.

        Returns:
            str: The base64-encoded ciphertext (encrypted data).
        """

        try:
            # Encrypt the plain_text
            box = SecretBox(final_key)
            cipher_text = box.encrypt(plain_text.encode('utf-8'))

            cipher_text_encoded = base64.b64encode(cipher_text).decode('utf-8')

            return cipher_text_encoded
        except Exception as e:
            print(f"Error during encryption: {e}")
            return None

    def decrypt_data(self, final_key, cipher_text_base64):
        """
        Decrypts a given base64-encoded ciphertext using a final encryption key.

        This function takes base64-encoded encrypted data, decrypts it using the provided key, 
        and returns the decrypted plaintext.

        Args:
            final_key (bytes): The encryption key used to decrypt the data.
            cipher_text_base64 (str): The base64-encoded encrypted data to be decrypted.

        Returns:
            str: The decrypted plaintext.
        """

        try:
            cipher_text = base64.b64decode(cipher_text_base64.encode('utf-8'))
            
            box = SecretBox(final_key)
            plain_text = box.decrypt(cipher_text).decode('utf-8')
            
            return plain_text
        except Exception as e:
            print(f"Error during decryption: {e}")
            return None

    def retrieve_data(self, hashed_username, paswrd=None):
        """
        Retrieve and decrypt user-related data for a given hashed username.

        The function first tries to retrieve the salt and key from active or default
        local data stores (`database_dec`, `auth_dec`, `key_dec`).
        If not found locally, it falls back to loading data from connected USB devices.

        Args:
            hashed_username (str): The hashed username to look up.
            paswrd (str, optional): The user's password for decrypting stored data. 
                If None, only salt and key are returned (if available).

        Returns:
            tuple:
                - decoded_key (bytes or None): The decoded encryption key if available.
                - decoded_salt (bytes): The decoded salt value.
                - decrypted_roots (dict or None): Decrypted user data dictionary if password 
                is provided and decryption succeeds, otherwise None.

        Returns (None, None, None) if user data or salt is not found.

        Notes:
            - Uses base64 decoding for salt and key.
            - If password is provided, derives the final key and attempts to decrypt user data.
            - Gracefully skips decryption failures per item with warning logs.
            - Returns partial data if only salt/key found but no password given.
        """
        # Use active decs if available, fallback to normal
        database_dec = self.active_database_dec or self.database_dec or {}
        auth_dec = self.active_auth_dec or self.auth_dec or {}
        key_dec = self.active_key_dec or self.key_dec or {}

        # Check local data first — only if decs are not empty
        if key_dec and hashed_username in key_dec:
            salt = key_dec[hashed_username].get("salt")
            key = key_dec[hashed_username].get("key")
        elif auth_dec and hashed_username in auth_dec:
            salt = auth_dec[hashed_username].get("salt")
            key = None
        else:
            # Fallback to USB data
            usb_auth_dec, usb_key_dec, usb_data_dec = self.load_usb_data()

            usb_auth_dec = usb_auth_dec or {}
            usb_key_dec = usb_key_dec or {}
            usb_data_dec = usb_data_dec or {}

            if usb_key_dec and hashed_username in usb_key_dec:
                salt = usb_key_dec[hashed_username].get("salt")
                key = usb_key_dec[hashed_username].get("key")
                auth_dec = usb_auth_dec
                key_dec = usb_key_dec
                database_dec = usb_data_dec
            elif usb_auth_dec and hashed_username in usb_auth_dec:
                salt = usb_auth_dec[hashed_username].get("salt")
                key = None
                auth_dec = usb_auth_dec
                key_dec = usb_key_dec
                database_dec = usb_data_dec
            else:
                return None, None, None  # Username not found anywhere

        if not salt:
            return None, None, None

        decoded_salt = base64.b64decode(salt.encode("utf-8"))

        # No password provided — return early with key and salt
        if not paswrd:
            if key:
                decoded_key = base64.b64decode(key.encode("utf-8"))
                return decoded_key, decoded_salt
            else:
                return None, decoded_salt

        # Password is provided — decrypt user data if it exists
        decrypted_roots = {}

        if database_dec and hashed_username in database_dec:
            if not key:
                return None, decoded_salt, None

            decoded_key = base64.b64decode(key.encode("utf-8"))
            final_key = self.derive_final_key(paswrd, decoded_salt, decoded_key)

            user_data = database_dec[hashed_username]
            if not isinstance(user_data, dict) or not user_data:
                return decoded_key, decoded_salt, {}  # No user data to decrypt

            for encrypted_root, encrypted_data in user_data.items():
                try:
                    decrypted_root_name = self.decrypt_data(final_key, encrypted_root)
                    decrypted_data = self.decrypt_data(final_key, encrypted_data)
                    decrypted_roots[decrypted_root_name] = decrypted_data
                except Exception as e:
                    print(f"Warning: failed to decrypt one item: {e}")
                    continue

            return decoded_key, decoded_salt, decrypted_roots

        return decoded_key if key else None, decoded_salt, None



    def find_secretvault(self):
        """
        Searches all connected USB drives for the "secretvault" folder.

        Returns:
            list: Paths to all "secretvault" folders found on usable USB drives.
        """
        drives = self.useable_usb
        secretvault_folders = []
        for drive in drives:
            sv_path = os.path.join(drive, "secretvault")
            if os.path.exists(sv_path) and os.path.isdir(sv_path):
                secretvault_folders.append(sv_path)
        return secretvault_folders

    def IfUserExist(self, username):
        """
        Checks if a user exists locally or on any connected USB drives (including backups).

        Args:
            username (str): The username to check.

        Returns:
            bool: True if the user exists anywhere, False otherwise.
        
        Process:
        - Hashes the username.
        - Checks local decrypted dictionaries for the hashed username.
        - If not found locally, searches all "secretvault" folders on USB drives.
        - Scans JSON files in these folders for the hashed username.
        - Handles errors silently and skips inaccessible files/folders.
        """

        hashed_username = self.hash_username(username)

        # Check locally loaded data dicts for user
        if (self.auth_dec and hashed_username in self.auth_dec) or \
        (self.database_dec and hashed_username in self.database_dec) or \
        (self.key_dec and hashed_username in self.key_dec):
            return True

        # Check USB drives for user by scanning secretvault JSON files
        secretvault_paths = self.find_secretvault()  # Returns list of secretvault paths on USBs
        for sv_path in secretvault_paths:
            try:
                for file_name in os.listdir(sv_path):
                    if not file_name.endswith('.json'):
                        continue
                    file_path = os.path.join(sv_path, file_name)
                    if not os.path.isfile(file_path):
                        continue
                    with open(file_path, 'r', encoding='utf-8') as f:
                        file_data = json.load(f)
                    if file_data and hashed_username in file_data:
                        return True
            except Exception:
                # Skip this path if any error (e.g., permission or file not found)
                continue

        # User not found anywhere
        return False

    def verify_password(self, hashed_username, passwrd, return_data=False):
        """
        Verifies if the provided password matches the stored password for the user.

        Args:
            hashed_username (str): The hashed username.
            passwrd (str): The plaintext password to verify.
            return_data (bool): Whether to return additional info (salts, keys, paths).

        Returns:
            tuple: 
                - (bool) Whether password matched.
                - (str) Location of match ("local", "usb", "both", or None).
                - Optionally: salt(s), key(s), directory path(s) used for verification.

        Process:
        - Checks connected USB drives first for user authentication data.
        - Loads salts and stored password hashes from AUTH.json or backup files.
        - Hashes the provided password with the salt and compares.
        - Then checks local storage similarly.
        - Combines local and USB verification results to determine final outcome.
        """
        found_local = found_usb = False
        match_local = match_usb = False
        salt_local = salt_usb = None
        key_local = key_usb = None
        usb_dir_found = local_dir_found = None

        # Check USBs first
        for directory in self.useable_usb:
            auth_path = os.path.join(directory, "secretvault/AUTH.json")
            auth_backup_path = os.path.join(directory, "secretvault/AUTH_BACKUP.json")
            key_path = os.path.join(directory, "secretvault/KEY.json")
            key_backup_path = os.path.join(directory, "secretvault/KEY_BACKUP.json")

            if self.path_exist(auth_path) or self.path_exist(auth_backup_path):
                auth_usb_file = auth_path if self.path_exist(auth_path) else auth_backup_path
                auth_data = self.load_data_json(auth_usb_file) or {}

                key_file = key_path if self.path_exist(key_path) else key_backup_path
                key_data = self.load_data_json(key_file) if self.path_exist(key_file) else {}

                if auth_data and hashed_username in auth_data:
                    user_auth = auth_data[hashed_username]
                    salt_usb_b64 = user_auth.get("salt", "")
                    salt_usb = base64.b64decode(salt_usb_b64.encode('utf-8')) if salt_usb_b64 else None
                    stored_password_hash = user_auth.get("password", "")

                    key_usb_b64 = key_data.get(hashed_username, {}).get("key", "")
                    key_usb = base64.b64decode(key_usb_b64) if key_usb_b64 else None

                    if salt_usb and passwrd:
                        hashed_passwrd_usb = self.hash_password(passwrd, salt_usb)
                        if hashed_passwrd_usb == stored_password_hash:
                            match_usb = True

                    found_usb = True
                    usb_dir_found = directory
                    break  # Stop after first valid USB found

        # Check local storage — only if decs are not empty
        self.auth_dec = self.auth_dec or {}
        self.key_dec = self.key_dec or {}

        if self.auth_dec or self.key_dec:
            key_local, salt_local = self.retrieve_data(hashed_username)

            if key_local and salt_local:
                found_local = True
                if passwrd:
                    hashed_passwrd_local = self.hash_password(passwrd, salt_local)
                    if hashed_username in self.auth_dec:
                        stored_local_hash = self.auth_dec[hashed_username].get("password", "")
                        if hashed_passwrd_local == stored_local_hash:
                            match_local = True

        # Combine results
        if found_local and found_usb:
            if match_local and match_usb:
                result = (True, "both")
                key_used = (key_local, key_usb)
                dir_used = (None, usb_dir_found)
            elif match_local and not match_usb:
                result = (False, "local")
                key_used = (key_local, None)
                dir_used = (None, None)
            elif not match_local and match_usb:
                result = (False, "usb")
                key_used = (None, key_usb)
                dir_used = (None, usb_dir_found)
            else:
                result = (False, "both")
                key_used = (None, None)
                dir_used = (None, usb_dir_found)
        elif found_local:
            result = (match_local, "local")
            key_used = key_local
            dir_used = None
        elif found_usb:
            result = (match_usb, "usb")
            key_used = key_usb
            dir_used = usb_dir_found
        else:
            result = (False, None)
            key_used = None
            dir_used = None

        if return_data:
            return (*result, salt_local, salt_usb, key_used, dir_used)
        else:
            return (*result, key_used, dir_used)

    def check_password_strength(self, password):
        """
        Checks password strength and returns:
        - True if the password is strong.
        - Detailed feedback and False if the password is weak.
        """

        feedback = []

        # Check all requirements
        if len(password) < 8:  # Minimum length of 8 characters
            feedback.append("• Must be at least 8 characters long.")
        if not any(c.islower() for c in password):
            feedback.append("• Must include at least one lowercase letter.")
        if not any(c.isupper() for c in password):
            feedback.append("• Must include at least one uppercase letter.")
        if not any(c.isdigit() for c in password):
            feedback.append("• Must include at least one digit.")
        if not any(c in "!@#_-+=" for c in password):
            feedback.append("• Must include at least one special character (!@#_-+=).")
        
        # If there's any feedback (password is weak)
        if feedback:
            self.clear_and_print_logo()
            full_feedback = "Your password is too weak. It must also include the following:\n" + "\n".join(feedback)
            print(full_feedback)
            return False

        # If all conditions are met, just return True
        return True

    def timespan_from_timestamp(self, past_timestamp):
        """
        Returns a human-readable string representing the time elapsed since past_timestamp.

        Args:
            past_timestamp (int): Unix timestamp in seconds.

        Returns:
            str: Human-readable elapsed time (e.g., '3 days ago', '5 hours ago').
        """
        now = int(time.time())
        diff = now - past_timestamp

        if diff < 0:
            return "in the future"

        intervals = (
            ('year', 60 * 60 * 24 * 365),
            ('month', 60 * 60 * 24 * 30),
            ('week', 60 * 60 * 24 * 7),
            ('day', 60 * 60 * 24),
            ('hour', 60 * 60),
            ('minute', 60),
            ('second', 1),
        )

        for name, seconds in intervals:
            count = diff // seconds
            if count > 0:
                return f"{count} {name}{'s' if count > 1 else ''} ago"

        return "just now"

    def input_index(self, data): 
        """Helper to get a valid entry index from user."""
        n = len(data)

        while True:
            if n == 1:
                prompt = "Enter the only option (1): "
            elif n == 2:
                prompt = "Enter the index (1 or 2): "
            else:
                prompt = f"Enter the index (1-{n}): "

            idx = input(prompt).strip()

            if not idx.isdigit():
                self.clear_and_print_logo()
                print("Invalid input. Please enter a number.")
                continue

            idx = int(idx)
            if 1 <= idx <= n:
                return idx

            print(f"Index must be between 1 and {n}.")

    def text_file_data(self, username, hashed_username, passwrd):
        """
        Generate a formatted text table displaying the user's stored data.

        Args:
            username (str): The plaintext username to display as the table title.
            hashed_username (str): The hashed username used to retrieve data.
            passwrd (str): The password for decrypting/retrieving user data.

        Returns:
            str or bool: Formatted table string if data exists, otherwise False.
        """

        _, _, user_data = self.retrieve_data(hashed_username, passwrd)

        if not user_data:
            return False

        max_root_len = max(len(str(root)) for root in user_data.keys())
        max_data_len = max(len(str(data)) for data in user_data.values())
        index_len = 6  # 'Index' length, fixed

        total_width = index_len + 3 + max_root_len + 3 + max_data_len

        # Center username as title above the table
        title = username.center(total_width)

        # Header with aligned columns
        header = f"{'Index':<6} | {'Root Name'.ljust(max_root_len)} | {'Data'.ljust(max_data_len)}"

        # Cross-shaped separator line matching header width
        separator = f"{'-' * index_len}-+-{'-' * max_root_len}-+-{'-' * max_data_len}"

        # Prepare rows with index and data
        rows = []
        for i, (root, data) in enumerate(user_data.items(), 1):
            row = f"{str(i):<6} | {str(root).ljust(max_root_len)} | {str(data).ljust(max_data_len)}"
            rows.append(row)

        # Combine everything into a full text block
        table_text = title + "\n" + header + "\n" + separator + "\n" + "\n".join(rows)

        return table_text

    def prepare_export_directory(self):
        """
        Determine and prepare the directory path for exporting data,
        depending on whether USB usage is enabled and which USB drives are available.

        Returns:
            str or None: The path to the export directory, or None if no valid directory is chosen.
        """
        export_dir = None

        if self.use_usb:
            option_dir = [d for d in self.useable_usb if d != self.usb_root] if self.useable_usb else []

            if not option_dir:
                export_dir = self.base_folder
            else:
                dir_used = self.directory_menu(option_dir, change_use_usb=False)
                export_dir = os.path.join(dir_used, self.base_folder) if dir_used else self.base_folder

        else:
            if not self.useable_usb:
                self.clear_and_print_logo()
                print("There is no USB connected to use.")
                input("Press enter to continue...")
                return None

            dir_used = self.directory_menu(self.useable_usb, include_default_dir=False, change_use_usb=False)

            if dir_used:
                export_dir = os.path.join(dir_used, self.base_folder)
            else:
                export_dir = self.base_folder

        return export_dir



    def store_password_and_salt(self, hashed_username, hashed_paswrd, salt):
        """
        Stores the bcrypt-hashed password, salt, and current timestamp for a user
        in the active authentication JSON files, including a backup.

        Args:
            hashed_username (str): The SHA-256 hashed username.
            hashed_paswrd (str): The bcrypt-hashed password.
            salt (bytes): The salt used for password hashing.

        Returns:
            None
        """
        salt_encoded = base64.b64encode(salt).decode('utf-8')

        auth_data = self.load_data_json(self.active_auth_file, self.active_auth_backup_file) or {}

        auth_data[hashed_username] = {
            "password": hashed_paswrd,
            "salt": salt_encoded,
            "timestamp": str(int(time.time()))
        }

        self.save_data_json(auth_data, self.active_auth_file)
        self.save_data_json(auth_data, self.active_auth_backup_file)

        # Update in-memory copy
        self.active_auth_dec = auth_data

    def store_encryption_key_and_salt(self, hashed_username, key, salt):
        """
        Stores the encryption key and salt for a user in the active key JSON files (with backup).
        Both key and salt are base64-encoded before storage.

        Args:
            hashed_username (str): The SHA-256 hashed username.
            key (bytes): The encryption key to store.
            salt (bytes): The salt used for key generation.

        Returns:
            None
        """
        key_encoded = base64.b64encode(key).decode('utf-8')
        salt_encoded = base64.b64encode(salt).decode('utf-8')

        existing_keys = self.load_data_json(self.active_key_file, self.active_key_backup_file) or {}

        existing_keys[hashed_username] = {
            "key": key_encoded,
            "salt": salt_encoded
        }

        self.save_data_json(existing_keys, self.active_key_file)
        self.save_data_json(existing_keys, self.active_key_backup_file)

        # Update in-memory copy
        self.active_key_dec = existing_keys

    def store_encrypted_data(self, hashed_username, encrypted_root, encrypted_data):
        """
        Stores encrypted data for a user in the active database JSON file.

        Args:
            hashed_username (str): SHA-256 hashed username.
            encrypted_root (str): Label/root name for the encrypted data.
            encrypted_data (str): Base64-encoded encrypted data.

        Returns:
            None
        """
        user_data = self.load_data_json(self.active_database_file) or {}

        if hashed_username not in user_data:
            user_data[hashed_username] = {}

        user_data[hashed_username][encrypted_root] = encrypted_data

        self.save_data_json(user_data, self.active_database_file)

        # Update in-memory copy
        self.active_database_dec = user_data



    def add_data(self, hashed_username, final_key):
        """Add new data for the user."""
        self.clear_and_print_logo()


        while True:
            data_root_input = input("Enter the root name: ").lower()
            if not data_root_input:
                self.clear_and_print_logo()
                print("Please input a root name.")
                continue
            break

        while True:
            data_of_the_root_input = input("Enter the data: ")
            if not data_of_the_root_input:
                self.clear_and_print_logo()
                print("Please input data.")
                continue
            break

        # Encrypt both root name and data
        encrypted_root = self.encrypt_data(final_key, data_root_input)
        encrypted_data = self.encrypt_data(final_key, data_of_the_root_input)

        # Store the encrypted data
        self.store_encrypted_data(hashed_username, encrypted_root, encrypted_data)

    def check_data(self, hashed_username, passwrd, roots=None, pause=False):
        """
        Check and retrieve the user's stored data. Returns True if data exists, else False.
        """

        self.clear_and_print_logo()

        # Retrieve roots if not provided
        if roots is None:
            _, _, roots_data = self.retrieve_data(hashed_username, passwrd)
        else:
            roots_data = roots


        if not roots_data:
            print("\n=============================")
            print("       No data found.")
            print("=============================\n")
            return False  # No data

        max_root_len = max(len(str(root)) for root in roots_data.keys())
        max_data_len = max(len(str(data)) for data in roots_data.values())

        header = f"{'Index':<6} | {'Root Name'.ljust(max_root_len)} | {'Data'.ljust(max_data_len)}"
        separator = "-" * (10 + max_root_len + max_data_len)
        separator2 = "=" * (10 + max_root_len + max_data_len)

        print("\n=============================")
        print("        USER DATA")
        print("=============================\n")
        print(header)
        print(separator)

        for i, (root_name, data) in enumerate(roots_data.items(), 1):
            print(f"[{i:<3}]  | {root_name.ljust(max_root_len)} | {str(data).ljust(max_data_len)}")

        print(separator2)

        if pause:
            input("Press Enter to continue...")

        return True

    def check_update_data(self, hashed_username, passwrd, final_key):
        """Check and retrieve the user's stored data with options to view, edit, delete entries."""

        # Retrieve decrypted data (roots_data) - dict {root_name: data}
        _, _, roots_data = self.retrieve_data(hashed_username, passwrd)

        if not roots_data:
            print("No data found for this user.")
            return

        while True:
            if not self.check_data(hashed_username, passwrd, roots_data):
                break

            print("\nAdditional Options:")
            print("[1] View details of a specific entry")
            print("[2] Edit existing entry")
            print("[3] Delete a specific entry")
            print("[4] Back to main menu")
            print("=============================")

            user_choice = input("Enter your choice (1-4): ").strip()
            if user_choice not in {"1", "2", "3", "4"}:
                print("Invalid choice, please enter 1-4.")
                continue

            if user_choice == "4":
                print("Returning to main menu...")
                break

            entry_index = self.input_index(roots_data)
            selected_root_name = list(roots_data.keys())[entry_index - 1]

            if user_choice == "1":  # View details
                self.clear_and_print_logo()
                print(f"Details for '{selected_root_name}': {roots_data[selected_root_name]}")
                input("Press Enter to continue...")

            elif user_choice == "2":  # Edit entry
                self.clear_and_print_logo()
                print(f"Editing entry: '{selected_root_name}'\n")

                while True:
                    update_choice = input("What would you like to update? (1: Root Name, 2: Data, 3: Both): ").strip()
                    if update_choice not in {'1', '2', '3'}:
                        print("Invalid choice, please choose 1, 2, or 3.")
                        continue
                    break

                # Update root name
                if update_choice in {'1', '3'}:
                    while True:
                        new_root_name = input(f"Enter a new root name (current: {selected_root_name}): ").strip()
                        if not new_root_name:
                            self.clear_and_print_logo()
                            print("Root name cannot be empty.")
                            continue
                        break
                    # Rename key in roots_data
                    roots_data[new_root_name] = roots_data.pop(selected_root_name)
                    selected_root_name = new_root_name

                # Update data
                if update_choice in {'2', '3'}:
                    while True:
                        new_data = input("Enter new data: ").strip()
                        if not new_data:
                            self.clear_and_print_logo()
                            print("Data cannot be empty.")
                            continue
                        break
                    roots_data[selected_root_name] = new_data

                # Re-encrypt updated data
                new_roots_data = {}
                for root_name, data in roots_data.items():
                    encrypted_root_name = self.encrypt_data(final_key, root_name)
                    encrypted_data = self.encrypt_data(final_key, data)
                    new_roots_data[encrypted_root_name] = encrypted_data

                self.active_database_dec[hashed_username] = new_roots_data
                self.save_data_json(self.active_database_dec, self.active_database_file)

            elif user_choice == "3":  # Delete entry
                self.clear_and_print_logo()
                print(f"Deleting entry: '{selected_root_name}'")

                # Find the encrypted root name that corresponds to selected_root_name
                encrypted_root_to_delete = None
                for enc_root_name in self.active_database_dec.get(hashed_username, {}):
                    decrypted_root_name = self.decrypt_data(final_key, enc_root_name)
                    if decrypted_root_name == selected_root_name:
                        encrypted_root_to_delete = enc_root_name
                        break

                if encrypted_root_to_delete:
                    del self.active_database_dec[hashed_username][encrypted_root_to_delete]
                    self.save_data_json(self.active_database_dec, self.active_database_file)
                else:
                    print("Root name not found in data. Could not delete the entry.")

            print("=============================\n")

    def change_password(self, hashed_username, salt):
        """Change the user's password."""

        self.clear_and_print_logo()

        # Show time since last password change, if available
        if "timestamp" in self.active_auth_dec.get(hashed_username, {}):
            last_change = int(self.active_auth_dec[hashed_username]["timestamp"])
            elapsed = self.timespan_from_timestamp(last_change)
            print(f"Your password was last changed: {elapsed}\n")

        while True:
            passwrd = input("Enter your password: ").strip()
            if self.verify_password(hashed_username, passwrd):
                break
            self.clear_and_print_logo()
            print("Invalid password. Please try again.")

        while True:
            passwrd_1 = input("Enter your new password: ").strip()
            passwrd_2 = input("Confirm your new password: ").strip()

            if passwrd_1 != passwrd_2:
                self.clear_and_print_logo()
                print("Error: Passwords do not match. Please try again.")
                continue

            if not self.check_password_strength(passwrd_1):
                continue

            # All checks passed — update the password and timestamp
            hashed_passwrd = self.hash_password(passwrd_1, salt)
            self.active_auth_dec[hashed_username]["password"] = hashed_passwrd
            self.active_auth_dec[hashed_username]["timestamp"] = str(int(time.time()))  # update timestamp

            # Save auth data
            self.save_data_json(self.active_auth_dec, self.active_auth_file)
            self.save_data_json(self.active_auth_dec, self.active_auth_file)
            break

    def clear_data(self, hashed_username, all_data=False):
        """Clear all encrypted root data for a user, keeping the account entry unless all_data is True."""

        user_entry = self.active_database_dec.get(hashed_username)

        # If deleting account but account doesn't exist
        if all_data and not user_entry:
            print("You don't have an account to delete.")
            return False

        # If clearing data but no data exists
        if not all_data and (not user_entry or not user_entry.items()):
            print("You don't have any data to clear.")
            return False

        # Password verification
        while True:
            password = input("Enter your password: ").strip()
            if self.verify_password(hashed_username, password):
                break
            print("Invalid password. Please try again.")

        prompt_text = "your entire account" if all_data else "all your data"

        # Final confirmation
        while True:
            choice = input(f"Last warning, are you sure you want to delete {prompt_text}? (Y/N): ").strip().lower()
            if choice not in ['y', 'n']:
                print("Invalid input. Please enter Y or N.")
                self.clear_and_print_logo()
                continue

            if choice == 'y':
                if all_data:
                    # Remove user entirely (account + data)
                    self.active_database_dec.pop(hashed_username, None)
                    self.active_auth_dec.pop(hashed_username, None)
                    self.active_key_dec.pop(hashed_username, None)

                    # Save updated data
                    self.save_data_json(self.active_database_dec, self.active_database_file)

                    print("Your entire account has been deleted. Logging out...")
                    self.start_menu()

                else:
                    # Just clear user's data but keep account entry
                    self.active_database_dec[hashed_username] = {}

                    self.save_data_json(self.active_database_dec, self.active_database_file)

                    print("All your data has been deleted.")
            else:
                self.clear_and_print_logo()
                print("Data clearance canceled.")
            break

    def export_user_data(self, username, hashed_username, passwrd):
        """
        Exports the user's data to a text file in a chosen directory (USB or local).
        It first retrieves and formats the data, asks the user to confirm exporting,
        creates necessary folders, avoids overwriting existing files by adding numbers,
        and writes the data safely while handling errors.
        """
        user_data = self.text_file_data(username, hashed_username, passwrd)

        if not user_data:
            self.clear_and_print_logo()
            print("There is no data to export")
            input("Press enter to continue...")
            return None

        export_dir = self.prepare_export_directory()

        user_path = os.path.join(export_dir, f"{username}_exported_data")

        # Confirm export action
        while True:
            self.clear_and_print_logo()
            user_input = input(f"Are you sure you want to export {username}'s data to '{user_path}'? (Y/N): ").strip().lower()
            if user_input not in ['y', 'n']:
                continue
            if user_input == 'n':
                return  # Cancel export
            break

        # Ensure export directory exists
        os.makedirs(export_dir, exist_ok=True)

        
        os.makedirs(user_path, exist_ok=True)

        # Prepare filename to avoid overwriting
        num = 0
        base_username = username
        while True:
            current_username = f"{base_username}{num}" if num > 0 else base_username
            user_file = os.path.join(user_path, f"{current_username}.txt")
            if not self.path_exist(user_file):
                break
            num += 1

        # Save to file
        try:
            with open(user_file, 'w', encoding='utf-8') as f:
                f.write(user_data)
            self.clear_and_print_logo()

        except Exception as e:
            self.clear_and_print_logo()
            print(f"Failed to export data: {e}")
            input("Press Enter to continue...")

    def transfer_user_and_wipe(self, username, hashed_username, passwrd):

        """
        Transfers the user's encrypted data files to a specified directory (such as a USB),
        then securely removes that user's data from the active program’s storage to wipe their local presence.

        Steps include:
        - Prompting for and verifying the user's password.
        - Preparing the export directory and confirming with the user.
        - Creating the export directory if it doesn't exist.
        - Defining and using a helper function (del_save) to move user data for authentication,
        encryption keys, and encrypted database files by removing the user from active memory
        and saving copies in the export directory.
        - This effectively backs up the user's data externally while erasing it locally,
        supporting secure data transfer and cleanup.
        """

        while True:
            self.clear_and_print_logo()
            passwrd = input("Enter your password: ").strip()
            if self.verify_password(hashed_username, passwrd):
                break
            print("Invalid password. Please try again.")

        export_dir = self.prepare_export_directory()

        # Confirm export action
        while True:
            self.clear_and_print_logo()
            user_input = input(f"Are you sure you want to transfer {username} data to {export_dir} and wipe? (Y/N): ").strip().lower()
            if user_input not in ['y', 'n']:
                continue
            if user_input == 'n':
                return  # Cancel export
            break

        # Ensure export directory exists
        os.makedirs(export_dir, exist_ok=True)

        def del_save(dec, hashed_username, dir_used, *, paths=None, files=None):
            paths = paths or []
            files = files or []

            data = None
            if dec and hashed_username in dec:
                data = dec[hashed_username]
                del dec[hashed_username]

            # Save updated dict (without user) to files
            for file in files:
                self.save_data_json(dec, file)

            for path in paths:
                full_path = os.path.join(dir_used, path)
                if not os.path.exists(full_path):
                    existing_data = {}
                else:
                    try:
                        with open(full_path, 'r', encoding='utf-8') as f:
                            existing_data = json.load(f)
                    except (json.JSONDecodeError, IOError):
                        existing_data = {}

                if data:
                    existing_data[hashed_username] = data
                else:
                    # If no data for user, remove if exists
                    existing_data.pop(hashed_username, None)

                self.save_data_json(existing_data, full_path)
                
        del_save(
            self.active_auth_dec,
            hashed_username,
            export_dir,
            paths=["AUTH.json", "AUTH_BACKUP.json"],
            files=[self.active_auth_file, self.active_auth_backup_file]
        )

        del_save(
            self.active_key_dec,
            hashed_username,
            export_dir,
            paths=["KEY.json", "KEY_BACKUP.json"],
            files=[self.active_key_file, self.active_key_backup_file]
        )

        del_save(
            self.active_database_dec,
            hashed_username,
            export_dir,
            paths=["DATABASE.json"],
            files=[self.active_database_file],
        )

    def show_help_faq(self):
        self.clear_and_print_logo()
        """Show help or frequently asked questions (FAQ) for the user."""

        faq_text = """
=============================
        HELP / FAQ
=============================

1. How to add important info?
- Select option [1] from the main menu and follow the prompts.

2. How to check my stored data?
- Choose option [2] to view your saved info.

3. How do I update my data?
- Use option [3] to review and update existing information.

4. How can I change my password?
- Option [4] allows you to securely change your password.

5. What happens if I clear my user data?
- Choosing option [5] will erase all your saved data from this device.

6. How do I delete my user account?
- Option [6] deletes your entire account and all associated data.

7. How can I export my data?
- Use option [7] to export your data either to a USB or locally.

8. Can I export and remove data from this device?
- Option [8] exports your data and deletes it from the current device.

9. How do I log out?
- Option [10] logs you out safely from your account.

For further assistance, contact support@example.com

=============================
Press Enter to return to the menu...
"""
        input(faq_text)

    def log_out(self):
        """Log the user out of the application after confirmation."""
        while True:
            self.clear_and_print_logo()
            user_input = input("Are you sure you want to log out? (Y/N): ").strip().lower()
            if user_input not in ['y', 'n']:
                self.clear_and_print_logo()
                print("Invalid input, please enter Y(yes) or N(no).")
                continue

            if user_input == 'y':
                # Reset all user session related attributes
                self.secretvault_dir = None
                self.active_database_file = None
                self.active_auth_file = None
                self.active_auth_backup_file = None
                self.active_key_file = None
                self.active_key_backup_file = None

                self.active_auth_dec = None
                self.active_key_dec = None
                self.active_database_dec = None

                self.use_usb = False
                self.usb_root = None

                self.user_menu()
            else:
                # User canceled logout
                return



    def directory_menu(self, directories=None, include_default_dir=True, change_use_usb=True):
        """
        Shows a menu to choose a directory.
        directories: list, str, or None - available directories or a single directory as string.
        include_default_dir: bool - whether to show 'default directory' as option 1.
        change_use_usb: bool - whether to update self.use_usb and self.usb_root when a selection is made.

        Returns the chosen directory path or None if refreshed.
        """
        while True:
            # Normalize the input
            if directories is None:
                directories = []
            elif isinstance(directories, str):
                directories = [directories]

            self.clear_and_print_logo()
            print("Choose the directory you want to use:")

            options = []
            if include_default_dir:
                print("    1.  default directory")
                options.append(None)  # None represents the default directory

            sorted_dirs = sorted(directories)
            for i, directory in enumerate(sorted_dirs, start=len(options) + 1):
                print(f"    {i}.  {directory}")
                options.append(directory)

            max_index = len(options)
            if max_index == 1:
                prompt = "Enter the only option (1) or press Enter to refresh or re-plug the USB: "
            else:
                prompt = f"Enter the index (1-{max_index}) or press Enter to refresh or re-plug the USB: "

            choice = input(prompt).strip()

            if choice == "":
                # Refresh the menu (maybe USB plugged/unplugged)
                 continue

            if not choice.isdigit():
                print("Invalid input. Please enter a number.")
                input("Press Enter to try again...")
                continue

            choice = int(choice)
            if 1 <= choice <= max_index:
                selected_dir = options[choice - 1]
                if change_use_usb:
                    self.usb_root = selected_dir
                    # If default dir chosen and included, use_usb must be False
                    if include_default_dir and choice == 1:
                        self.use_usb = False
                    else:
                        self.use_usb = (selected_dir is not None)
                return selected_dir
            else:
                print(f"Index must be between 1 and {max_index}.")
                input("Press Enter to try again...")

    def sign_in(self):
        """
        Creates a new user account and stores credentials either locally or on a USB.
        All working data is handled through 'active_' attributes only.

        Returns:
            tuple: (hashed_username, password, salt, final_key) on success
                or (None, None, None, None) on failure
        """

        while True:
            self.clear_and_print_logo()
            username = input("Enter a username: ").strip()
            if not username:
                continue
            if self.IfUserExist(username):
                print("[X] Username already exists. Try a different one.")
                continue
            break

        hashed_username = self.hash_username(username)

        while True:
            passwrd = input("Create a password: ").strip()
            confirm = input("Confirm your password: ").strip()
            if passwrd != confirm:
                self.clear_and_print_logo()
                print("[X] Passwords do not match.")
                continue
            if not self.check_password_strength(passwrd):
                continue
            break
            
        hashed_paswrd, salt = self.hash_password(passwrd)

        # Choose storage directory (local or USB)
        while True:
            self.clear_and_print_logo()
            directory = self.directory_menu(self.useable_usb)  # Should return path or None

            if self.use_usb == False:
                # Local storage paths
                self.active_auth_file = self.auth_file
                self.active_auth_backup_file = self.auth_backup_file
                self.active_key_file = self.key_file
                self.active_key_backup_file = self.key_backup_file
                self.active_database_file = self.database_file
            else:
                self.use_usb = True
                self.usb_root = directory
                if not self.usb_root:
                    print("[X] No USB detected. Sign-in failed.")
                    return None, None, None, None

                self.secretvault_dir = os.path.join(self.usb_root, self.base_folder)
                os.makedirs(self.secretvault_dir, exist_ok=True)

                self.active_auth_file = os.path.join(self.secretvault_dir, "AUTH.json")
                self.active_auth_backup_file = os.path.join(self.secretvault_dir, "AUTH_BACKUP.json")
                self.active_key_file = os.path.join(self.secretvault_dir, "KEY.json")
                self.active_key_backup_file = os.path.join(self.secretvault_dir, "KEY_BACKUP.json")
                self.active_database_file = os.path.join(self.secretvault_dir, "DATABASE.json")
            break

        # Derive encryption key using your method
        final_key, key = self.derive_final_key(passwrd, salt)

        # Store user credentials & encryption keys securely
        self.store_password_and_salt(hashed_username, hashed_paswrd, salt)
        self.store_encryption_key_and_salt(hashed_username, key, salt)

        return username, hashed_username, passwrd, salt, final_key

    def log_in(self):
        """
        Handles user login with retries.
        Prompts user repeatedly until valid username and password are entered.
        Automatically chooses the login source (USB > Local).

        Returns:
            tuple: (str hashed_username, str password, bytes salt, bytes final_key)
        """
        while True:
            self.clear_and_print_logo()
            username = input("Enter your username or press Enter to refresh or re-plug the USB: ").strip()
            if not self.IfUserExist(username):
                print("[X] Username not found. Please try again.")
                continue
            else:
                break

        hashed_username = self.hash_username(username)

        while True:
            passwrd = input("Enter your password or press Enter to refresh or re-plug the USB: ").strip()

            _, location, salt_local, salt_usb, key_used, dir_used = self.verify_password(
                hashed_username, passwrd, return_data=True
            )

            if location not in ['usb', 'local', 'both']:
                print("[X] Incorrect password. Try again.")
                continue
            else:
                break

        # Decide source automatically — USB preferred if both match

        if location == "both":
            dir_used = dir_used[1]

        if location == "usb" or self.directory_menu(dir_used):
            self.use_usb = True
            salt = salt_usb
            key = key_used[1] if isinstance(key_used, (list, tuple)) else key_used
            self.usb_root = dir_used[1] if isinstance(dir_used, (list, tuple)) else dir_used

            self.secretvault_dir = os.path.join(self.usb_root, self.base_folder)

            self.active_auth_file        = os.path.join(self.secretvault_dir, "AUTH.json")
            self.active_auth_backup_file = os.path.join(self.secretvault_dir, "AUTH_BACKUP.json")
            self.active_key_file         = os.path.join(self.secretvault_dir, "KEY.json")
            self.active_key_backup_file  = os.path.join(self.secretvault_dir, "KEY_BACKUP.json")
            self.active_database_file    = os.path.join(self.secretvault_dir, "DATABASE.json")

            self.active_auth_dec = self.load_data_json(self.active_auth_file, self.active_auth_backup_file)
            self.active_key_dec  = self.load_data_json(self.active_key_file, self.active_key_backup_file)
            self.active_database_dec = self.load_data_json(self.active_database_file)

        else:
            # local only
            self.use_usb = False
            salt = salt_local
            key = key_used

            self.active_auth_file        = self.auth_file
            self.active_auth_backup_file = self.auth_backup_file
            self.active_key_file         = self.key_file
            self.active_key_backup_file  = self.key_backup_file
            self.active_database_file    = self.database_file

            self.active_auth_dec = self.load_data_json(self.active_auth_file, self.active_auth_backup_file)
            self.active_key_dec  = self.load_data_json(self.active_key_file, self.active_key_backup_file)
            self.active_database_dec = self.load_data_json(self.active_database_file)


        key, salt = self.retrieve_data(hashed_username)
        final_key = self.derive_final_key(passwrd, salt, key)

        return username, hashed_username, passwrd, salt, final_key

    def start_menu(self):
        """
        Displays the main menu to the user and allows them to choose to log in or sign up.

        This method shows a banner with the program's name and presents two options to the user: sign-in or log-in.
        Based on the user's choice, it either calls the sign_in() method to create a new user or the log_in() method
        to authenticate an existing user.

        Args:
            None

        Returns:
            tuple:
                - str: The chosen username.
                - str: The entered password.
        """

        menu_text = """
Please choose an option:
--------------------------
    [1] Sign in
    [2] Log in
    [3] Exit program
--------------------------
"""
        while True:
            self.clear_and_print_logo()
            print(menu_text)
            
            choice = input("Enter your choice (1-3): ").strip()
            
            if choice not in ['1', '2', '3']:
                print("Invalid input. Please try again.")
                continue

            if choice == '1':
                username, hashed_username, passwrd, salt, final_key = self.sign_in()
            elif choice == '2':
                username, hashed_username, passwrd, salt, final_key = self.log_in()
            elif choice == '3':
                print("Exiting...")
                exit()
            else:
                print("Invalid input. Please try again.")

            return username, hashed_username, passwrd, salt, final_key

    def user_menu(self):
        # Get hashed username and password from start_menu
        username, hashed_username, passwrd, salt, final_key = self.start_menu()

        text = """
=============================
    USER MENU
=============================
    Please choose an option:
                        
[1] Add important info      
[2] Check user data
[3] Check and update user data
[4] Change password        
[5] Clear user data        
[6] Delete user account    
[7] Export user data (to USB or local)
[8] Export user data and delete from current device
[9] Help/FAQ
[10] Log out
=============================
Enter your choice (1-10): """


        while True:
            self.clear_and_print_logo()

            choice = input(text).strip()
            if choice not in [str(i) for i in range(1, 11)]:
                print("Invalid input. Please choose a number between 1 and 10.")
                continue

            if choice == '1':
                self.add_data(hashed_username, final_key)
            elif choice == '2':
                self.check_data(hashed_username, passwrd, pause=True) # usb?
            elif choice == '3':
                self.check_update_data(hashed_username, passwrd, final_key)
            elif choice == '4':
                self.change_password(hashed_username, salt)
            elif choice == '5':
                self.clear_data(hashed_username, salt)
            elif choice == '6':
                self.clear_data(hashed_username, salt, all_data=True)
            elif choice == '7':
                self.export_user_data(username, hashed_username, passwrd)
            elif choice == '8':
                self.transfer_user_and_wipe(username, hashed_username, passwrd)
            elif choice == '9':
                self.show_help_faq()
            elif choice == '10':
                self.log_out()

