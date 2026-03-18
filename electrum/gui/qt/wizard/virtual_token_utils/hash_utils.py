"""
Hash utilities for deterministic filename generation.
Uses SHA3-256 for all hashing operations.
"""
import hashlib
import os


def compute_user_hash(user_id: str, password: str) -> str:
    """
    Compute hash for file_info.json naming.
    Format: hash(user_id|password)
    
    Args:
        user_id: User identifier
        password: User password
        
    Returns:
        64-character hex string (SHA3-256)
    """
    data = f"{user_id}|{password}"
    return hashlib.sha3_256(data.encode('utf-8')).hexdigest()


def compute_file_hash(filename: str, user_id: str, password: str) -> str:
    """
    Compute hash for keys/encrypted file naming.
    Format: hash(filename_without_extension|user_id|password)
    
    Args:
        filename: Original filename (with or without extension)
        user_id: User identifier
        password: User password
        
    Returns:
        64-character hex string (SHA3-256)
    """
    # Remove extension from filename
    base_filename = os.path.splitext(filename)[0]
    data = f"{base_filename}|{user_id}|{password}"
    return hashlib.sha3_256(data.encode('utf-8')).hexdigest()


def get_file_info_name(user_id: str, password: str) -> str:
    """
    Generate file_info.json filename.
    Format: <hash>_file_info.json
    """
    user_hash = compute_user_hash(user_id, password)
    return f"{user_hash}_file_info.json"


def get_keys_filename(original_filename: str, user_id: str, password: str) -> str:
    """
    Generate keys filename.
    Format: <hash>_keys.bin
    """
    file_hash = compute_file_hash(original_filename, user_id, password)
    return f"{file_hash}_keys.bin"


def get_encrypted_filename(original_filename: str, user_id: str, password: str) -> str:
    """
    Generate encrypted file filename.
    Format: <hash>_file.hypn
    """
    file_hash = compute_file_hash(original_filename, user_id, password)
    return f"{file_hash}_file.hypn"


def get_seed_filename(user_id: str, password: str) -> str:
    """
    Generate encrypted seed filename.
    Format: <hash>_seed.enc
    """
    user_hash = compute_user_hash(user_id, password)
    return f"{user_hash}_seed.enc"
