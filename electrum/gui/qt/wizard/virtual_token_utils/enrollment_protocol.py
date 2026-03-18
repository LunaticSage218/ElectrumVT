import os
import time
import json
import base64

from electrum.gui.qt.wizard.virtual_token_utils.protocol_config import size, d, alpha, beta, P, D
from electrum.gui.qt.wizard.virtual_token_utils.enrollment_utils import enrollmentUtils
from electrum.gui.qt.wizard.virtual_token_utils.protocol_utils import protocolUtils
from electrum.gui.qt.wizard.virtual_token_utils.hash_utils import get_file_info_name, get_keys_filename, get_encrypted_filename

def enrollment_protocol(file_path, filename, description, file_extension, user_id, 
                        external_path=None, external_pw=None, 
                        keys_storage="usb", file_storage="database"):
    try:
        print(f"[DEBUG] Starting enrollment for file: {file_path} by user: {user_id}")
        print(f"[DEBUG] Keys storage: {keys_storage}, File storage: {file_storage}")
        start_enrollment = time.time()

        pUtils = protocolUtils()
        eUtils = enrollmentUtils()
        print("[DEBUG] Initialized protocol and enrollment utilities")

        # Generate ephemeral key and hash
        l = eUtils.generate_ephemeral_key(size)
        hkey = pUtils.hash_key(l)

        w, s = eUtils.generate_Kc(size)

        # Encrypt the file, returning bytes instead of writing to disk
        # Only enroll in database if file_storage is 'database'
        if file_storage == "database":
            encrypted_bytes = eUtils.encrypt_file(file_path, l, user_id, external_pw, [w, s])
        else:
            # Encrypt without database enrollment
            key = l.tobytes() if hasattr(l, 'tobytes') else l
            if len(key) < 32:
                raise ValueError("Key must be at least 32 bytes long for AES-256.")
            key = key[:32]
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            cipher = AES.new(key, AES.MODE_CBC)
            with open(file_path, "rb") as file:
                plaintext = file.read()
            padded_plaintext = pad(plaintext, AES.block_size, style="pkcs7")
            ciphertext = cipher.encrypt(padded_plaintext)
            encrypted_bytes = cipher.iv + ciphertext
            
        print(f"[DEBUG] Encrypted file length: {len(encrypted_bytes)} bytes")

        # f_double_circle using bytes
        f_double_circle = pUtils.generate_f_double_circle(encrypted_bytes, [w, s], d)

        challenges = pUtils.generate_challenges(s, D)
        responses = pUtils.generate_responses(f_double_circle, challenges, alpha, beta, P, d)

        k0 = responses[0]
        encrypted_description = eUtils.encrypt_description(description, k0)

        subset_of_res = eUtils.subset_of_responses(l, responses[1:])

        kc_encoded, kr_encoded, hkey_encoded = eUtils.serialize_and_encode_keys([w, s], subset_of_res, hkey)

        # Generate hash-based filenames
        keys_filename = get_keys_filename(filename, user_id, external_pw)
        encrypted_filename = get_encrypted_filename(filename, user_id, external_pw)
        print(f"[DEBUG] Generated keys filename: {keys_filename}")
        print(f"[DEBUG] Generated encrypted filename: {encrypted_filename}")

        # Route keys storage based on keys_storage parameter
        keys_file_id = None
        keys_uid = None
        if keys_storage == "usb" and external_path and external_pw:
            eUtils.save_keys_to_usb(kc_encoded, kr_encoded, hkey_encoded, external_path, external_pw, keys_filename)
            print("[DEBUG] Keys saved to USB")
        elif keys_storage == "google_drive" and external_pw:
            keys_file_id = eUtils.save_keys_to_google_drive(kc_encoded, kr_encoded, hkey_encoded, external_pw, keys_filename)
            print(f"[DEBUG] Keys saved to Google Drive, file_id: {keys_file_id}")
        elif keys_storage == "database" and external_pw:
            keys_uid = eUtils.save_keys_to_database(kc_encoded, kr_encoded, hkey_encoded, user_id, external_pw, [w, s])
            print(f"[DEBUG] Keys saved to Oracle database with UID: {keys_uid}")

        # Route encrypted file storage based on file_storage parameter
        encrypted_file_id = None
        encrypted_file_path = None
        if file_storage == "usb" and external_path:
            encrypted_file_path = eUtils.save_encrypted_file_to_usb(encrypted_bytes, external_path, encrypted_filename)
            print(f"[DEBUG] Encrypted file saved to USB: {encrypted_file_path}")
        elif file_storage == "google_drive":
            encrypted_file_id = eUtils.save_encrypted_file_to_google_drive(encrypted_bytes, encrypted_filename)
            print(f"[DEBUG] Encrypted file saved to Google Drive, file_id: {encrypted_file_id}")
        elif file_storage == "database":
            # File was already enrolled in database via encrypt_file() call above
            print("[DEBUG] Encrypted file stored in database")

        file_size = eUtils.get_file_size(file_path)

        # Store info in SimpleNamespace
        file_info = eUtils.store_file(
            filename, encrypted_bytes, encrypted_description,
            file_extension, file_size
        )

        # Encode any bytes fields as Base64 for JSON
        serializable_info = vars(file_info).copy()
        
        # Remove file_path since it contains encrypted bytes (or is in storage)
        if 'file_path' in serializable_info:
            del serializable_info['file_path']
        
        # Add storage metadata (only essential info)
        serializable_info['user_id'] = user_id
        serializable_info['keys_storage'] = keys_storage
        serializable_info['file_storage'] = file_storage
        
        # Store Google Drive file IDs if applicable (needed for retrieval)
        if keys_file_id:
            serializable_info['keys_file_id'] = keys_file_id
        if encrypted_file_id:
            serializable_info['encrypted_file_id'] = encrypted_file_id
        
        for key, value in serializable_info.items():
            if isinstance(value, bytes):
                serializable_info[key] = base64.b64encode(value).decode('utf-8')

        # Generate hash-based file_info.json name: hash(user_id|password)_file_info.json
        json_filename = get_file_info_name(user_id, external_pw)
        print(f"[DEBUG] Generated file_info filename: {json_filename}")
        
        # Always save to USB (external_path is required)
        if not external_path:
            raise ValueError("external_path (USB path) is required for file_info.json storage")
        
        json_filepath = os.path.join(external_path, json_filename)
        with open(json_filepath, "w", encoding="utf-8") as json_file:
            json.dump(serializable_info, json_file, indent=4)
        print(f"[DEBUG] Saved file_info to USB: {json_filepath}")

        pUtils.log_timing(start_enrollment, "Enrollment process")
        print("[DEBUG] Enrollment process completed successfully")

        return True, serializable_info, "File enrolled successfully."

    except Exception as e:
        print(f"[ERROR] Enrollment failed: {e}")
        return False, None, f"Error enrolling file: {e}"
