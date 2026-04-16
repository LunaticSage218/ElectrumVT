"""
Derives an ephemeral key from a digital file using the challenge-response
approach from the Gen-2 project:
  1. SHAKE-256 hash the file → large binary string
  2. RN1 + password → challenge addresses into the binary string → crypto table
  3. RN2 + password → extraction positions into the crypto table → 256-bit ephemeral_key

The same key can be regenerated deterministically given the same file,
password, RN1, and RN2.
"""

import hashlib
import random
import secrets
import struct
from typing import Tuple

import numpy as np
from bitarray import bitarray

# ---------------------------------------------------------------------------
# Constants (matching Gen-2 conventions)
# ---------------------------------------------------------------------------
FRAME_SIZE = 256
CRYPTO_TABLE_SIZE = FRAME_SIZE * FRAME_SIZE          # 65536
CT_ADDRESSES = 256 * 8                                # 2048 extraction positions
BINARY_STRING_BITS = CRYPTO_TABLE_SIZE * 16           # ~1 048 576 bits from file hash


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _hash_file_to_binary(file_bytes: bytes) -> str:
    """SHAKE-256 hash the file content into a long binary string."""
    shake = hashlib.shake_256()
    shake.update(file_bytes)
    num_bytes = BINARY_STRING_BITS // 8 + (1 if BINARY_STRING_BITS % 8 else 0)
    hash_output = shake.digest(num_bytes)
    return ''.join(format(byte, '08b') for byte in hash_output)


def _generate_rn(bits: int = 512) -> bitarray:
    """Generate a cryptographically random bitarray of *bits* length."""
    ba = bitarray([secrets.randbelow(2) for _ in range(bits)])
    return ba


def _hashed_password(password: str) -> bitarray:
    """SHA3-512 hash of the password, returned as a bitarray."""
    pwd = bitarray()
    pwd.frombytes(hashlib.sha3_512(password.encode()).digest())
    return pwd


def _derive_challenges(rn: bitarray, password: str, num_challenges: int,
                       mod_value: int) -> np.ndarray:
    """
    Derive *num_challenges* integer challenge addresses from *rn* and *password*.

    Mirrors Gen-2's challenge derivation:
      concatenate = rn || SHA3-512(password)
      digest = SHAKE-256(concatenate, num_challenges * 4 bytes)
      unpack as big-endian uint32 → mod by *mod_value*
    """
    pwd = _hashed_password(password)
    concatenated = rn + pwd
    digest = hashlib.shake_256(concatenated.tobytes()).digest(num_challenges * 4)
    struct_fmt = struct.Struct(">" + "I" * num_challenges)
    uints = struct_fmt.unpack(digest)
    return np.array([u % mod_value for u in uints])


def _build_crypto_table(binary_string: str, challenges: np.ndarray) -> list:
    """Index into the binary string at each challenge position → '0'/'1' list."""
    return [binary_string[int(c)] for c in challenges]


def _extract_ephemeral_key(crypto_table: list, extraction_positions: np.ndarray,
                           password: str) -> str:
    """
    Read crypto table at extraction positions, then deterministically select
    256 bits to form the ephemeral key.

    Mirrors Gen-2 Protocol.create_seed:
      raw_key = [crypto_table[pos] for pos in extraction_positions]
      (no X filtering needed — single deterministic factor)
      password-seeded random.sample picks 256 indices
    """
    raw_key = [crypto_table[int(pos)] for pos in extraction_positions]

    # With a single deterministic factor there are no 'X' cells, but keep the
    # same selection logic as Gen-2 for consistency / future-proofing.
    filtered_indices = list(range(len(raw_key)))

    if len(filtered_indices) < 256:
        raise ValueError(
            f"Not enough positions for a 256-bit key "
            f"(got {len(filtered_indices)}, need 256)."
        )

    hashed_pw = hashlib.sha256(password.encode()).digest()
    random.seed(hashed_pw)
    key_indices = random.sample(filtered_indices, 256)

    ephemeral_key = ''.join(raw_key[idx] for idx in key_indices)
    return ephemeral_key


def _ephemeral_key_to_bytes(ephemeral_key: str) -> bytes:
    """Convert a 256-char binary string ('0'/'1') into 32 bytes."""
    return int(ephemeral_key, 2).to_bytes(32, byteorder='big')


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_seed_key(file_bytes: bytes, password: str
                      ) -> Tuple[bytes, bitarray, bitarray]:
    """Derive a 256-bit ephemeral key from *file_bytes* and *password*.

    This is used at **enrollment time** — fresh RN1 and RN2 are generated and
    must be stored alongside the encrypted seed.

    Returns:
        (ephemeral_key, rn1, rn2)
        where *ephemeral_key* is 32 bytes suitable for AES-256.
    """
    binary_string = _hash_file_to_binary(file_bytes)

    # --- Stage 1: VT table via RN1 challenges ---
    rn1 = _generate_rn(512)
    t_challenges = _derive_challenges(rn1, password, CRYPTO_TABLE_SIZE,
                                      BINARY_STRING_BITS)
    crypto_table = _build_crypto_table(binary_string, t_challenges)

    # --- Stage 2: ephemeral key extraction via RN2 ---
    rn2 = _generate_rn(512)
    extraction_positions = _derive_challenges(rn2, password, CT_ADDRESSES,
                                              CRYPTO_TABLE_SIZE)
    ephemeral_key = _extract_ephemeral_key(crypto_table, extraction_positions, password)

    return _ephemeral_key_to_bytes(ephemeral_key), rn1, rn2


def recover_seed_key(file_bytes: bytes, password: str,
                     rn1: bitarray, rn2: bitarray) -> bytes:
    """Re-derive the same ephemeral key using previously stored RN1 and RN2.

    This is used at **retrieval time**.

    Returns:
        32-byte ephemeral key (identical to the one from ``generate_seed_key``).
    """
    binary_string = _hash_file_to_binary(file_bytes)

    t_challenges = _derive_challenges(rn1, password, CRYPTO_TABLE_SIZE,
                                      BINARY_STRING_BITS)
    crypto_table = _build_crypto_table(binary_string, t_challenges)

    extraction_positions = _derive_challenges(rn2, password, CT_ADDRESSES,
                                              CRYPTO_TABLE_SIZE)
    ephemeral_key = _extract_ephemeral_key(crypto_table, extraction_positions, password)

    return _ephemeral_key_to_bytes(ephemeral_key)
