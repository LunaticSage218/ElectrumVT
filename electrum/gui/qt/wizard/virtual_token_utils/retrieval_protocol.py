"""
Retrieval protocol for the Virtual Token system.
Ported from VirtualTokenDB/DataEncap/verification/verification.py.

Reconstructs the ephemeral key (l) from enrolled VT data so it can be
used as an encryption key for the seed phrase.
"""

import time
from typing import Optional

from bitarray import bitarray

from electrum.gui.qt.wizard.virtual_token_utils.protocol_config import (
    d, D, alpha, beta, P, gamma0, BER, size,
)
from electrum.gui.qt.wizard.virtual_token_utils.protocol_utils import protocolUtils
from electrum.gui.qt.wizard.virtual_token_utils.retrieval_utils import retrievalUtils
from electrum.gui.qt.wizard.virtual_token_utils.db_manager import SQLiteDBManager
from electrum.gui.qt.wizard.virtual_token_utils.hash_utils import (
    get_keys_filename, get_encrypted_filename,
)


def retrieval_protocol(
    file_info: dict,
    user_id: str,
    external_pw: str,
    keys_storage: str = "usb",
    file_storage: str = "database",
    usb_path: Optional[str] = None,
) -> Optional[bitarray]:
    """Run the verification protocol and return the recovered ephemeral key *l*.

    This is the "crypto table" that can then be used to encrypt / decrypt the
    seed phrase with AES-256-CBC.

    Returns:
        The recovered ephemeral key as a *bitarray*, or ``None`` on failure.
    """
    try:
        start_time = time.time()
        pUtils = protocolUtils()
        vUtils = retrievalUtils()

        original_filename = file_info.get("filename")
        if not original_filename:
            raise ValueError("filename not found in file_info")

        keys_filename = get_keys_filename(original_filename, user_id, external_pw)
        encrypted_filename = get_encrypted_filename(original_filename, user_id, external_pw)
        print(f"[RETRIEVAL] keys file: {keys_filename}, encrypted file: {encrypted_filename}")

        # ── Step 1: load keys ────────────────────────────────────────
        if keys_storage == "usb":
            if not usb_path:
                raise ValueError("USB path is required for USB keys storage")
            kc_enc, kr_enc, hkey_enc = vUtils.load_keys_from_usb(
                usb_path, external_pw, keys_filename
            )
        elif keys_storage == "google_drive":
            keys_file_id = file_info.get("keys_file_id")
            if not keys_file_id:
                raise ValueError("keys_file_id not found in file_info")
            kc_enc, kr_enc, hkey_enc = vUtils.load_keys_from_google_drive(
                keys_file_id, external_pw
            )
        elif keys_storage == "database":
            kc_enc, kr_enc, hkey_enc = vUtils.load_keys_from_database(
                file_info, external_pw
            )
        else:
            raise ValueError(f"Unknown keys_storage: {keys_storage}")

        # ── Step 2: decode keys ──────────────────────────────────────
        kc, kr, hkey = vUtils.retrieve_encryption_keys(kc_enc, kr_enc, hkey_enc)
        if not kc or not kr or not hkey:
            raise ValueError("One or more decoded keys (kc, kr, hkey) are None")

        # ── Step 3: load encrypted VT file ───────────────────────────
        if file_storage == "database":
            db = SQLiteDBManager()
            uid = db.compute_unique_id(user_id, external_pw, kc)
            encrypted_file_bytes = db.fetch_encrypted_file(uid)
        elif file_storage == "usb":
            if not usb_path:
                raise ValueError("USB path is required for USB file storage")
            encrypted_file_bytes = vUtils.load_encrypted_file_from_usb(
                usb_path, encrypted_filename
            )
        elif file_storage == "google_drive":
            encrypted_file_id = file_info.get("encrypted_file_id")
            if not encrypted_file_id:
                raise ValueError("encrypted_file_id not found in file_info")
            encrypted_file_bytes = vUtils.load_encrypted_file_from_google_drive(
                encrypted_file_id
            )
        else:
            raise ValueError(f"Unknown file_storage: {file_storage}")

        if encrypted_file_bytes is None:
            raise FileNotFoundError("No encrypted VT data found")

        # ── Step 4: regenerate CRP data ──────────────────────────────
        f_double_circle = pUtils.generate_f_double_circle(
            encrypted_file_bytes, [kc[0], kc[1]], d
        )
        challenges = pUtils.generate_challenges(kc[1], D)
        responses = pUtils.generate_responses(
            f_double_circle, challenges, alpha, beta, P, d
        )

        if not responses:
            raise ValueError("Responses list is empty")

        # ── Step 5: error detection & key recovery ───────────────────
        response = responses[1:] if len(responses) > 1 else []
        match_index, collision_index, ftd_index = vUtils.error_detection(
            response, kr, gamma0, BER, size
        )
        updated_matches_index, updated_collision_index = vUtils.merge_matches_with(
            match_index, collision_index
        )
        updated_matches_index, updated_ftd_index = vUtils.merge_matches_with(
            updated_matches_index, ftd_index
        )
        l = vUtils.generate_possible_keys(
            updated_matches_index, updated_collision_index, updated_ftd_index, size, hkey
        )

        elapsed = time.time() - start_time
        print(f"[RETRIEVAL] Ephemeral key recovered in {elapsed:.2f}s")

        if l is None:
            raise ValueError("Recovered key (l) is None")
        return l

    except Exception as e:
        print(f"[RETRIEVAL ERROR] {e}")
        return None
