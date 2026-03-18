import base64
import os
import pickle
import secrets
import hashlib
from io import BytesIO
from types import SimpleNamespace

from electrum.gui.qt.wizard.virtual_token_utils.db_manager import SQLiteDBManager
from electrum.gui.qt.wizard.virtual_token_utils.google_drive_utils import authenticate_with_google, upload_google_drive, get_or_create_app_folder

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from bitarray import bitarray

from electrum.gui.qt.wizard.virtual_token_utils.protocol_config import g

class enrollmentUtils:
    def break_runs(self, bit_array, n):
        result = bitarray()
        run_length = 0
        for bit in bit_array:
            if bit == 0:
                run_length += 1
                if run_length > n:
                    # insert a 1 to break the run
                    result.append(1)
                    run_length = 0
                else:
                    result.append(0)
            else:
                run_length = 0
                result.append(1)
        return result

    def generate_ephemeral_key(self, size):
        # Generate a random bitarray of length 'size', ensuring no long runs of zeros.
        num_bytes = (size + 7) // 8
        random_bytes = secrets.token_bytes(num_bytes)
        key = bitarray()
        key.frombytes(random_bytes)
        final_key = self.break_runs(key[:size], g)
        return final_key

    def generate_Kc(self, size):
        # Generate two random bitarrays (omega and s) of length 'size'.
        num_bytes = (size + 7) // 8
        omega_bytes = secrets.token_bytes(num_bytes)
        s_bytes = secrets.token_bytes(num_bytes)
        omega = bitarray(); omega.frombytes(omega_bytes)
        s = bitarray(); s.frombytes(s_bytes)
        return self.break_runs(omega[:size], g), self.break_runs(s[:size], g)

    def encrypt_file(self, filename, key, user_id, external_pw, kc):
        # Encrypt the file content with AES-256-CBC using the given key (bitarray or bytes).
        # Convert key to bytes if needed
        if isinstance(key, bitarray):
            key = key.tobytes()
        if len(key) < 32:
            raise ValueError("Key must be at least 32 bytes long for AES-256.")
        key = key[:32]

        # Encrypt the file
        cipher = AES.new(key, AES.MODE_CBC)
        with open(filename, "rb") as file:
            plaintext = file.read()
        padded_plaintext = pad(plaintext, AES.block_size, style="pkcs7")
        ciphertext = cipher.encrypt(padded_plaintext)
        encrypted_file = cipher.iv + ciphertext

        print(f"[DEBUG encrypt_file] Plaintext length: {len(plaintext)}")
        print(f"[DEBUG encrypt_file] Padded plaintext length: {len(padded_plaintext)}")
        print(f"[DEBUG encrypt_file] Encrypted file length: {len(encrypted_file)}")
        print(f"[DEBUG encrypt_file] IV (hex): {cipher.iv.hex()}")
        print(f"[DEBUG encrypt_file] First 32 bytes of encrypted_file (hex): {encrypted_file[:32].hex()}")
        print(f"[DEBUG encrypt_file] Last 32 bytes of encrypted_file (hex): {encrypted_file[-32:].hex()}")

        # Enroll in the database
        db = SQLiteDBManager()
        uid = db.enroll_new_user(user_id, external_pw, kc, encrypted_file)
        print(f"Enrolled with UID: {uid}")

        # Return the encrypted bytes
        return encrypted_file

    def encrypt_description(self, description, key):
        # Encrypt the text description using AES-256-CBC and return base64 string.
        if isinstance(key, bitarray):
            key = key.tobytes()
        if isinstance(key, str):
            key = key.encode("utf-8")
        if len(key) < 32:
            raise ValueError("Key must be at least 32 bytes long for AES-256.")
        key = key[:32]
        cipher = AES.new(key, AES.MODE_CBC)
        plaintext_bytes = description.encode("utf-8")
        padded_plaintext = pad(plaintext_bytes, AES.block_size, style="pkcs7")
        ciphertext = cipher.encrypt(padded_plaintext)
        encrypted_description = cipher.iv + ciphertext
        return base64.b64encode(encrypted_description).decode("utf-8")

    def encrypt_file_content(self, content, key):
        if isinstance(key, bitarray):
            key = key.tobytes()
        if len(key) < 32:
            raise ValueError("Key must be at least 32 bytes long for AES-256.")
        key = key[:32]
        cipher = AES.new(key, AES.MODE_CBC)
        padded_content = pad(content, AES.block_size, style="pkcs7")
        encrypted_content = cipher.iv + cipher.encrypt(padded_content)
        return encrypted_content

    def linear_congruent_rng(self, alpha, beta, xi, P, d):
        positions = []
        xi_previous = xi
        for _ in range(P):
            xi_next = ((alpha * xi_previous) + beta) % d
            positions.append(xi_next)
            xi_previous = xi_next
        return positions

    def subset_of_responses(self, key, responses):
        if len(key) != len(responses):
            raise ValueError("Key and responses must have the same length.")
        subset_responses = []
        for i, bit in enumerate(key):
            if bit == 1:
                subset_responses.append(responses[i])
        return subset_responses

    def serialize_and_encode_keys(self, kc, kr, hkey):
        kc_encoded = base64.b64encode(pickle.dumps(kc)).decode("utf-8")
        kr_encoded = base64.b64encode(pickle.dumps(kr)).decode("utf-8")
        hkey_encoded = base64.b64encode(pickle.dumps(hkey)).decode("utf-8")
        return kc_encoded, kr_encoded, hkey_encoded

    def get_file_size(self, file_path):
        return os.path.getsize(file_path)

    def store_file(self, filename, file_path, file_description, file_extension, file_size) -> SimpleNamespace:
        # Build and return a record object with attribute access (simulate DB record)
        record = SimpleNamespace(
            filename=filename,
            file_path=file_path,
            file_description=file_description,
            file_extension=file_extension,
            size=file_size
        )
        return record

    def save_keys_to_usb(self, kc_enc, kr_enc, hkey_enc, target_path, password, keys_filename):
        """
        Save the encoded keys and hash to an external file (USB) in a binary serialized format.
        The data is encrypted with AES-256 using the provided password.
        Uses the provided keys_filename (hash-based) to ensure deterministic naming.
        
        Args:
            keys_filename: Hash-based filename (e.g., <hash>_keys.bin)
        """
        # Normalize path
        path = target_path
        if len(path) == 2 and path[1] == ':' and not path.endswith(os.sep):
            # Normalize Windows drive letter path (e.g., "E:" -> "E:\\")
            path = path + os.sep
        
        # Construct full path with hash-based filename
        if os.path.isdir(path):
            key_file_path = os.path.join(path, keys_filename)
        else:
            # Use the provided path if it's not a directory
            key_file_path = path
            dir_name = os.path.dirname(key_file_path) or '.'
            if not os.path.isdir(dir_name):
                raise FileNotFoundError(f"Directory '{dir_name}' does not exist")

        # Prepare data dictionary and serialize to bytes
        data = {'kc': kc_enc, 'kr': kr_enc, 'hkey': hkey_enc}
        serialized_bytes = pickle.dumps(data)

        # Derive 32-byte key from password using SHA-256
        aes_key = hashlib.sha256(password.encode('utf-8')).digest()
        # Encrypt the serialized data with AES-256-CBC
        cipher = AES.new(aes_key, AES.MODE_CBC)
        padded_data = pad(serialized_bytes, AES.block_size, style='pkcs7')
        ciphertext = cipher.encrypt(padded_data)
        # Write IV + ciphertext to the key file
        with open(key_file_path, "wb") as key_file:
            key_file.write(cipher.iv)
            key_file.write(ciphertext)
        print(f"[DEBUG] Keys saved to: {key_file_path}")
        # Successfully written keys to external file
        return key_file_path

    def save_keys_to_google_drive(self, kc_enc, kr_enc, hkey_enc, password, filename="keys.bin"):
        """
        Save the encoded keys and hash to Google Drive in an encrypted binary format.
        The data is encrypted with AES-256 using the provided password.
        Returns the Google Drive file ID.
        """
        # Prepare data dictionary and serialize to bytes
        data = {'kc': kc_enc, 'kr': kr_enc, 'hkey': hkey_enc}
        serialized_bytes = pickle.dumps(data)

        # Derive 32-byte key from password using SHA-256
        aes_key = hashlib.sha256(password.encode('utf-8')).digest()
        # Encrypt the serialized data with AES-256-CBC
        cipher = AES.new(aes_key, AES.MODE_CBC)
        padded_data = pad(serialized_bytes, AES.block_size, style='pkcs7')
        ciphertext = cipher.encrypt(padded_data)
        
        # Create BytesIO object with IV + ciphertext
        encrypted_bytes = BytesIO(cipher.iv + ciphertext)
        
        # Authenticate with Google Drive
        creds = authenticate_with_google()
        
        # Get or create VirtualTokenApp folder
        folder_id = get_or_create_app_folder(creds)
        
        # Upload to Google Drive in VirtualTokenApp folder
        file_id = upload_google_drive(encrypted_bytes, creds, filename, folder_id=folder_id)
        print(f"[DEBUG] Keys uploaded to Google Drive with file ID: {file_id}")
        return file_id

    def save_keys_to_database(self, kc_enc, kr_enc, hkey_enc, user_id, external_pw, kc):
        """
        Save the encoded keys to the Oracle database in the ENCRYPTED_KEYS column.
        Keys are encrypted the same way as USB storage (with password-derived AES key).
        """
        # Prepare data dictionary and serialize to bytes
        data = {'kc': kc_enc, 'kr': kr_enc, 'hkey': hkey_enc}
        serialized_bytes = pickle.dumps(data)

        # Derive 32-byte key from password using SHA-256
        aes_key = hashlib.sha256(external_pw.encode('utf-8')).digest()
        # Encrypt the serialized data with AES-256-CBC
        cipher = AES.new(aes_key, AES.MODE_CBC)
        padded_data = pad(serialized_bytes, AES.block_size, style='pkcs7')
        ciphertext = cipher.encrypt(padded_data)
        
        # Create encrypted blob (IV + ciphertext)
        encrypted_keys_blob = cipher.iv + ciphertext
        
        # Store in database
        db = SQLiteDBManager()
        uid = db.store_encrypted_keys(user_id, external_pw, kc, encrypted_keys_blob)
        
        print(f"[DEBUG] Keys stored in database for user: {user_id}, UID: {uid}")
        return uid

    def save_encrypted_file_to_usb(self, encrypted_file_bytes, target_path, filename):
        """
        Save the encrypted file bytes to USB storage.
        Uses the provided filename (hash-based) to ensure deterministic naming.
        
        Args:
            filename: Hash-based filename (e.g., <hash>_file.hypn)
        """
        path = target_path
        if len(path) == 2 and path[1] == ':' and not path.endswith(os.sep):
            path = path + os.sep
        
        # Construct full path with hash-based filename
        if os.path.isdir(path):
            file_path = os.path.join(path, filename)
        else:
            file_path = path
            dir_name = os.path.dirname(file_path) or '.'
            if not os.path.isdir(dir_name):
                raise FileNotFoundError(f"Directory '{dir_name}' does not exist")
        
        with open(file_path, "wb") as f:
            f.write(encrypted_file_bytes)
        
        print(f"[DEBUG] Encrypted file saved to USB: {file_path}")
        return file_path

    def save_encrypted_file_to_google_drive(self, encrypted_file_bytes, filename):
        """
        Save the encrypted file bytes to Google Drive.
        Returns the Google Drive file ID.
        """
        # Create BytesIO object from encrypted bytes
        encrypted_bytesio = BytesIO(encrypted_file_bytes)
        
        # Authenticate with Google Drive
        creds = authenticate_with_google()
        
        # Get or create VirtualTokenApp folder
        folder_id = get_or_create_app_folder(creds)
        
        # Upload to Google Drive in VirtualTokenApp folder
        file_id = upload_google_drive(encrypted_bytesio, creds, filename, folder_id=folder_id)
        print(f"[DEBUG] Encrypted file uploaded to Google Drive with file ID: {file_id}")
        return file_id
