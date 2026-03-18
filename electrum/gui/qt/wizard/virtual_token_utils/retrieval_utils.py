"""
Retrieval / verification utilities for the Virtual Token system.
Ported from VirtualTokenDB/DataEncap/verification/verificationUtils.py,
adapted to use Electrum's local modules.
"""

import base64
import hashlib
import os
import pickle
from io import BytesIO
from itertools import product
from typing import List, Optional, Tuple, Union

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from bitarray import bitarray

from electrum.gui.qt.wizard.virtual_token_utils.protocol_config import g
from electrum.gui.qt.wizard.virtual_token_utils.protocol_utils import protocolUtils
from electrum.gui.qt.wizard.virtual_token_utils.db_manager import SQLiteDBManager


class retrievalUtils:
    """Utilities for key recovery and file decryption during VT verification."""

    # ── match / error-detection ──────────────────────────────────────

    def find_match(self, b1, b2, tolerance):
        if len(b1) != len(b2):
            raise ValueError("Bitarrays must be of the same length.")
        hamming_distance = (b1 ^ b2).count()
        return hamming_distance <= tolerance

    def check_match(self, gamma, i, responses, subres, BER):
        tolerance_bits = int(len(subres) * BER)
        match_idx = []
        no_matches_found = True
        nomatch = []
        for k in range(gamma):
            response_idx = i + k
            if response_idx >= len(responses):
                break
            match = self.find_match(responses[response_idx], subres, tolerance_bits)
            if match:
                match_idx.append(response_idx)
                no_matches_found = False
        if no_matches_found:
            nomatch = [i + _g for _g in range(gamma) if (i + _g) < len(responses)]
        return len(match_idx), match_idx, nomatch

    def error_detection(self, responses, subres, gamma0, BER, num_responses):
        match_idx = []
        collision_idx = []
        ftd_idx = []
        i, j = 0, 0
        gamma = gamma0
        while j < len(subres):
            gamma = min(gamma, num_responses - i)
            match_count, match_pos, nomatch_pos = self.check_match(
                gamma, i, responses, subres[j], BER
            )
            if match_count == 0:
                ftd_idx.append(nomatch_pos)
                gamma = 2 * g
            elif match_count == 1:
                match_idx.append(match_pos[0])
                gamma = gamma0
                i = match_pos[0] + 1
            else:
                collision_idx.append(match_pos)
                gamma = gamma0 + (match_pos[-1] - match_pos[0])
                i = match_pos[0] + 1
            j += 1
        return match_idx, collision_idx, ftd_idx

    def merge_matches_with(self, a, b):
        for num in a[:]:
            for sublist in b[:]:
                if num in sublist:
                    index = sublist.index(num)
                    sublist[:] = sublist[:index]
                    if len(sublist) == 1:
                        a.append(sublist[0])
                        b.remove(sublist)
        return a, b

    # ── key recovery ─────────────────────────────────────────────────

    def get_num_possible_keys(self, collision_idx, ftd_idx, max_keys=1e7):
        combined_list = collision_idx + ftd_idx
        num_possible_keys = 1
        for sublist in combined_list:
            num_possible_keys *= len(sublist)
            if num_possible_keys >= max_keys:
                return int(max_keys)
        return int(num_possible_keys)

    def generate_bitarray(self, indexes, length):
        bit_array = bitarray(length)
        bit_array.setall(0)
        for index in indexes:
            if 0 <= index < length:
                bit_array[index] = 1
        return bit_array

    def generate_possible_keys(self, match_idx, collision_idx, ftd_idx, n, hk):
        pUtils = protocolUtils()
        raw_key = bitarray(self.generate_bitarray(match_idx, n))
        combined_list = collision_idx + ftd_idx
        num_possible_keys = self.get_num_possible_keys(collision_idx, ftd_idx)
        print(f"Number of possible keys: {num_possible_keys}")
        if num_possible_keys > 1e6:
            print(f"Number of possible keys exceeds limit: {num_possible_keys}")
            return raw_key
        for indices_to_flip in product(*combined_list):
            modified_key = raw_key.copy()
            for index in indices_to_flip:
                modified_key[index] = not modified_key[index]
            if pUtils.hash_key(modified_key) == hk:
                print("Key successfully recovered!")
                return modified_key
            else:
                print(f"Hash mismatch: {pUtils.hash_key(modified_key)} != {hk}")
        return raw_key

    # ── key de-serialisation ─────────────────────────────────────────

    def retrieve_encryption_keys(self, kc_enc, kr_enc, hkey_enc):
        try:
            kc = pickle.loads(base64.b64decode(kc_enc))
            kr = pickle.loads(base64.b64decode(kr_enc))
            hkey = pickle.loads(base64.b64decode(hkey_enc))
        except (ValueError, pickle.UnpicklingError) as e:
            raise ValueError(f"Error decoding encryption keys: {e}")
        return kc, kr, hkey

    # ── load keys from various storage backends ──────────────────────

    def load_keys_from_usb(self, source_path: str, password: str, keys_filename: str):
        path = source_path
        if len(path) == 2 and path[1] == ':' and not path.endswith(os.sep):
            path = path + os.sep

        if os.path.isdir(path):
            key_file_path = os.path.join(path, keys_filename)
        else:
            key_file_path = path

        with open(key_file_path, "rb") as key_file:
            data = key_file.read()
        iv = data[:16]
        ciphertext = data[16:]
        aes_key = hashlib.sha256(password.encode('utf-8')).digest()
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        decrypted_bytes = cipher.decrypt(ciphertext)
        try:
            serialized = unpad(decrypted_bytes, AES.block_size, style='pkcs7')
        except ValueError:
            raise ValueError("Failed to decrypt keys file: incorrect password or file integrity issue")
        data_dict = pickle.loads(serialized)
        kc_enc = data_dict.get('kc')
        kr_enc = data_dict.get('kr')
        hkey_enc = data_dict.get('hkey')
        if not (kc_enc and kr_enc and hkey_enc):
            raise ValueError("Key file is missing expected data")
        return kc_enc, kr_enc, hkey_enc

    def load_keys_from_database(self, file_info: dict, external_pw: str):
        uid = file_info.get('keys_uid')
        if not uid:
            raise ValueError("keys_uid not found in file_info for database key storage")
        db = SQLiteDBManager()
        encrypted_keys_blob = db.fetch_encrypted_keys(uid)
        if not encrypted_keys_blob:
            raise ValueError(f"No encrypted keys found in database for UID: {uid}")
        iv = encrypted_keys_blob[:16]
        ciphertext = encrypted_keys_blob[16:]
        aes_key = hashlib.sha256(external_pw.encode('utf-8')).digest()
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        decrypted_bytes = cipher.decrypt(ciphertext)
        try:
            serialized = unpad(decrypted_bytes, AES.block_size, style='pkcs7')
        except ValueError:
            raise ValueError("Failed to decrypt keys from database: incorrect password or data integrity issue")
        data_dict = pickle.loads(serialized)
        kc_enc = data_dict.get('kc')
        kr_enc = data_dict.get('kr')
        hkey_enc = data_dict.get('hkey')
        if not (kc_enc and kr_enc and hkey_enc):
            raise ValueError("Key data from database is missing expected fields")
        return kc_enc, kr_enc, hkey_enc

    def load_keys_from_google_drive(self, file_id: str, password: str):
        from electrum.gui.qt.wizard.virtual_token_utils.google_drive_utils import authenticate_with_google, _bypass_electrum_dns
        from googleapiclient.discovery import build
        from googleapiclient.http import MediaIoBaseDownload

        creds = authenticate_with_google()
        service = build("drive", "v3", credentials=creds)
        request = service.files().get_media(fileId=file_id)
        downloaded_bytes = BytesIO()
        downloader = MediaIoBaseDownload(downloaded_bytes, request)
        done = False
        with _bypass_electrum_dns():
            while not done:
                _, done = downloader.next_chunk()
        downloaded_bytes.seek(0)
        data = downloaded_bytes.read()

        iv = data[:16]
        ciphertext = data[16:]
        aes_key = hashlib.sha256(password.encode('utf-8')).digest()
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        decrypted_bytes = cipher.decrypt(ciphertext)
        try:
            serialized = unpad(decrypted_bytes, AES.block_size, style='pkcs7')
        except ValueError:
            raise ValueError("Failed to decrypt keys from Google Drive: incorrect password or file integrity issue")
        data_dict = pickle.loads(serialized)
        kc_enc = data_dict.get('kc')
        kr_enc = data_dict.get('kr')
        hkey_enc = data_dict.get('hkey')
        if not (kc_enc and kr_enc and hkey_enc):
            raise ValueError("Key file from Google Drive is missing expected data")
        return kc_enc, kr_enc, hkey_enc

    # ── load encrypted VT file from various backends ─────────────────

    def load_encrypted_file_from_usb(self, usb_path: str, filename: str) -> bytes:
        path = usb_path
        if len(path) == 2 and path[1] == ':' and not path.endswith(os.sep):
            path = path + os.sep
        if os.path.isdir(path):
            file_path = os.path.join(path, filename)
        else:
            file_path = path
        with open(file_path, "rb") as f:
            return f.read()

    def load_encrypted_file_from_google_drive(self, file_id: str) -> bytes:
        from electrum.gui.qt.wizard.virtual_token_utils.google_drive_utils import authenticate_with_google, _bypass_electrum_dns
        from googleapiclient.discovery import build
        from googleapiclient.http import MediaIoBaseDownload

        creds = authenticate_with_google()
        service = build("drive", "v3", credentials=creds)
        request = service.files().get_media(fileId=file_id)
        downloaded_bytes = BytesIO()
        downloader = MediaIoBaseDownload(downloaded_bytes, request)
        done = False
        with _bypass_electrum_dns():
            while not done:
                _, done = downloader.next_chunk()
        downloaded_bytes.seek(0)
        return downloaded_bytes.read()

    # ── decryption helpers ───────────────────────────────────────────

    def decrypt_file_from_bytes(self, encrypted_data: bytes, key, user_id, external_pw, kc) -> bytes:
        if isinstance(key, bitarray):
            key = key.tobytes()
        if isinstance(key, str):
            key = key.encode("utf-8")
        if len(key) < 32:
            key = key.ljust(32, b'\0')
        key = key[:32]

        if len(encrypted_data) < 16:
            raise ValueError(f"Encrypted data too short: {len(encrypted_data)} bytes")
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_content = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted_content, AES.block_size, style="pkcs7")
        return plaintext

    def decrypt_description(self, encrypted_description, key) -> str:
        if isinstance(key, bitarray):
            key = key.tobytes()
        if isinstance(key, str):
            key = key.encode("utf-8")
        if len(key) < 32:
            raise ValueError("Key must be at least 32 bytes for AES-256")
        key = key[:32]

        if isinstance(encrypted_description, str):
            encrypted_data = base64.b64decode(encrypted_description)
        elif isinstance(encrypted_description, bytes):
            encrypted_data = encrypted_description
        else:
            raise TypeError(f"encrypted_description must be str or bytes, got {type(encrypted_description)}")

        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_content = cipher.decrypt(ciphertext)
        plaintext_bytes = unpad(decrypted_content, AES.block_size, style="pkcs7")
        return plaintext_bytes.decode("utf-8")
