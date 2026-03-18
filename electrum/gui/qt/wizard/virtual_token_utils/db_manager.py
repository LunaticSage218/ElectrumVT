import hashlib
import sqlite3
from typing import List, Union
from bitarray import bitarray
import os

# --- CONFIGURATION ---
db_dir = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(db_dir, "enrollments.db")


class SQLiteDBManager:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ENROLLMENTS (
                    UNIQUE_ID   TEXT PRIMARY KEY,
                    ENCRYPTED_FILE BLOB,
                    ENCRYPTED_KEYS BLOB
                )
            """)
            conn.commit()
        print(f"[INFO] SQLite database initialized at {self.db_path}")

    def _get_connection(self):
        try:
            conn = sqlite3.connect(self.db_path)
            print("[INFO] Successfully connected to SQLite DB")
            return conn
        except Exception as e:
            raise RuntimeError(f"[ERROR] Failed to connect to SQLite DB: {e}")

    def compute_unique_id(self, user_id: str, external_pw: str, kc: List[bitarray]) -> str:
        if not isinstance(kc, (list, tuple)) or len(kc) != 2:
            raise ValueError("kc must be a list/tuple with two bitarrays [w, s].")
        w, s = kc
        if not isinstance(w, bitarray) or not isinstance(s, bitarray):
            raise TypeError("Both w and s must be bitarrays.")
        kc_bytes = w.tobytes() + s.tobytes()
        data = user_id.encode() + external_pw.encode() + kc_bytes
        return hashlib.sha256(data).hexdigest()

    def enroll_new_user(self, user_id: str, external_pw: str, kc: List[bitarray], encrypted_file: bytes) -> str:
        unique_id = self.compute_unique_id(user_id, external_pw, kc)
        print(f"[DB ENROLLMENT] Storing encrypted file, UID: {unique_id}, length: {len(encrypted_file)} bytes")
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO ENROLLMENTS (UNIQUE_ID, ENCRYPTED_FILE)
                VALUES (?, ?)
                ON CONFLICT(UNIQUE_ID) DO UPDATE SET ENCRYPTED_FILE = excluded.ENCRYPTED_FILE
            """, (unique_id, encrypted_file))
            conn.commit()
        return unique_id

    def fetch_encrypted_file(self, unique_id: str) -> Union[bytes, None]:
        print(f"[DB RETRIEVAL] Fetching encrypted file, UID: {unique_id}")
        with self._get_connection() as conn:
            cur = conn.execute("""
                SELECT ENCRYPTED_FILE FROM ENROLLMENTS
                WHERE UNIQUE_ID = ?
            """, (unique_id,))
            row = cur.fetchone()
            if row and row[0]:
                data = row[0]
                print(f"Retrieved encrypted file, length: {len(data)} bytes")
                return data
            return None

    def store_encrypted_keys(self, user_id: str, external_pw: str, kc: List[bitarray], encrypted_keys_blob: bytes) -> str:
        unique_id = self.compute_unique_id(user_id, external_pw, kc)
        print(f"[DB ENROLLMENT] Storing encrypted keys, UID: {unique_id}, length: {len(encrypted_keys_blob)} bytes")
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO ENROLLMENTS (UNIQUE_ID, ENCRYPTED_KEYS)
                VALUES (?, ?)
                ON CONFLICT(UNIQUE_ID) DO UPDATE SET ENCRYPTED_KEYS = excluded.ENCRYPTED_KEYS
            """, (unique_id, encrypted_keys_blob))
            conn.commit()
        return unique_id

    def fetch_encrypted_keys(self, unique_id: str) -> Union[bytes, None]:
        print(f"[DB RETRIEVAL] Fetching encrypted keys, UID: {unique_id}")
        with self._get_connection() as conn:
            cur = conn.execute("""
                SELECT ENCRYPTED_KEYS FROM ENROLLMENTS
                WHERE UNIQUE_ID = ?
            """, (unique_id,))
            row = cur.fetchone()
            if row and row[0]:
                data = row[0]
                print(f"Retrieved encrypted keys, length: {len(data)} bytes")
                return data
            return None


# Backward-compatible alias
OracleDBManager = SQLiteDBManager
