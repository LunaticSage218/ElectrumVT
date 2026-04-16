# Virtual Token Protocol Flowchart

```
                        ╔═══════════════════════╗
                        ║     ENROLLMENT        ║
                        ╚═══════════╤═══════════╝
                                    │
                    ┌───────────────▼───────────────┐
                    │  Generate ephemeral key (l)   │
                    │  256-bit random bitarray      │
                    │  (no zero-runs > 5)           │
                    └───────────────┬───────────────┘
                                    │
                 ┌──────────────────┼──────────────────┐
                 │                  │                  │
    ┌────────────▼──────────┐  ┌───▼────────────┐  ┌───▼──────────────┐
    │ hkey = SHA3-256(l)    │  │ Generate kc =  │  │ Encrypt file     │
    │ (verification hash)   │  │ [omega, s]     │  │ with l (AES-256) │
    │                       │  │ (random pair)  │  │ → encrypted_bytes│
    └────────────┬──────────┘  └──┬──────────┬──┘  └───┬──────────────┘
                 │                │          │         │
                 │                │          │         │
                 │    ┌───────────▼──────────▼─────────▼──┐
                 │    │ f⊚ = SHAKE-256(                  │
                 │    │         SHA-256(encrypted_bytes)  │
                 │    │         ‖ omega                   │
                 │    │       )                           │
                 │    └──────────────────┬────────────────┘
                 │                       │
                 │    ┌──────────────────▼────────────────┐
                 │    │ challenges = SHAKE-256(s)         │
                 │    │ → 257 chunks of D=16 bits each    │
                 │    └──────────────────┬────────────────┘
                 │                       │
                 │    ┌──────────────────▼────────────────┐
                 │    │ responses = for each challenge:   │
                 │    │   LCG(alpha, beta, challenge, d)  │
                 │    │   → positions into f⊚            │
                 │    │   → collect bits at positions     │
                 │    │                                   │
                 │    │ responses[0]  → k0 (256-bit)      │
                 │    │ responses[1:] → 256 responses     │
                 │    │                  (P=8 bits each)  │
                 │    └────────┬─────────────────────┬────┘
                 │             │                     │
                 │    ┌────────▼──────────┐  ┌───────▼────────────────┐
                 │    │ Encrypt file      │  │ kr = subset(l,         │
                 │    │ description       │  │         responses[1:]) │
                 │    │ with k0           │  │                        │
                 │    └────────┬──────────┘  │ For each bit in l:     │
                 │             │             │  1 → keep response     │
                 │             │             │  0 → skip response     │
                 │             │             └───────┬────────────────┘
                 │             │                     │
                 └─────────────┼─────────────────────┘
                               │
                  ┌────────────▼────────────┐
                  │  STORE: kc, kr, hkey    │
                  │  (+ encrypted file)     │
                  └─────────────────────────┘


                        ╔═══════════════════════╗
                        ║     RETRIEVAL         ║
                        ╚═══════════╤═══════════╝
                                    │
                    ┌───────────────▼───────────────┐
                    │ RETRIEVE: kc, kr, hkey        │
                    │ (+ encrypted file)            │
                    └───────────────┬───────────────┘
                                    │
                 ┌──────────────────▼──────────────────┐
                 │ Regenerate CRP data identically:    │
                 │                                     │
                 │ f⊚ = SHAKE-256(SHA-256(enc_file)   │
                 │                ‖ omega)             │
                 │ challenges = SHAKE-256(s)           │
                 │ responses = LCG over f⊚            │
                 │ → full set of 256 responses         │
                 └──────────────────┬──────────────────┘
                                    │
                 ┌──────────────────▼──────────────────┐
                 │ ERROR DETECTION                     │
                 │                                     │
                 │ For each sub-response in kr,        │
                 │ search a sliding window (γ₀=6)      │
                 │ in the full response list:          │
                 │                                     │
                 │ Hamming distance ≤ tolerance?       │
                 └───┬──────────────┬──────────────┬───┘
                     │              │              │
            ┌────────▼────┐  ┌─────▼──────┐  ┌───▼───────────┐
            │ 1 match     │  │ >1 match   │  │ 0 matches     │
            │→ match_idx  │  │→ collision │  │→ ftd_idx      │
            │ (confirmed  │  │   _idx     │  │ (failure to   │
            │  l[i] = 1)  │  │ (ambiguous)│  │  detect)      │
            └────────┬────┘  └─────┬──────┘  └───┬───────────┘
                     │             │              │
                     └─────────────┼──────────────┘
                                   │
                 ┌─────────────────▼───────────────────┐
                 │ MERGE: resolve overlaps between     │
                 │ match_idx and collision/ftd lists   │
                 └─────────────────┬───────────────────┘
                                   │
                 ┌─────────────────▼───────────────────┐
                 │ KEY RECOVERY                        │
                 │                                     │
                 │ 1. Base candidate: 256-bit array    │
                 │    set 1 at each match_idx          │
                 │                                     │
                 │ 2. For ambiguous positions          │
                 │    (collision + ftd):               │
                 │    brute-force flip combinations    │
                 │                                     │
                 │ 3. Check: SHA3-256(candidate)       │
                 │           == hkey?                  │
                 │    YES → recovered l                │
                 └─────────────────┬───────────────────┘
                                   │
                        ┌──────────▼──────────┐
                        │  Return l           │
                        │  (256-bit key for   │
                        │   AES-256 decrypt)  │
                        └──────────┬──────────┘
                                   │
                                   │
      ╔════════════════════════════╧════════════════════════════╗
      ║      FILE RECONSTRUCTION                                ║
      ╚════════════════════════════╤════════════════════════════╝
                                   │
                 ┌─────────────────▼───────────────────┐
                 │ Decrypt enrolled VT file using l:   │
                 │                                     │
                 │ l_bytes = l[:32]                    │
                 │ iv  = encrypted_file[:16]           │
                 │ ct  = encrypted_file[16:]           │
                 │ decrypted_file = AES-256-CBC        │
                 │   decrypt(l_bytes, iv, ct)          │
                 └─────────────────┬───────────────────┘
                                   │
                                   │
      ╔════════════════════════════╧════════════════════════════╗
      ║  SEED KEY DERIVATION  (Gen-2 VT protocol)               ║
      ╚════════════════════════════╤════════════════════════════╝
                                   │
            ┌──────────────────────┴──────────────────────┐
            │                                             │
   (after enrollment)                            (after retrieval)
   generates fresh RN1, RN2                      loads stored RN1, RN2
            │                                             │
            └──────────────────────┬──────────────────────┘
                                   │
                 ┌─────────────────▼───────────────────┐
                 │ STEP 1: Hash file → binary string   │
                 │                                     │
                 │ binary_str = SHAKE-256(             │
                 │   decrypted_file                    │
                 │ )                                   │
                 │ → 1,048,576 bits                    │
                 │   (CRYPTO_TABLE_SIZE × 16)          │
                 └─────────────────┬───────────────────┘
                                   │
                 ┌─────────────────▼───────────────────┐
                 │ STEP 2: RN1 challenges → VT table   │
                 │                                     │
                 │ concat = RN1 ‖ SHA3-512(password)   │
                 │ digest = SHAKE-256(concat,          │
                 │           65536 × 4 bytes)          │
                 │ t_challenges = unpack as uint32     │
                 │                mod 1,048,576        │
                 │                                     │
                 │ crypto_table[i] =                   │
                 │   binary_str[t_challenges[i]]       │
                 │ → 65536-entry table of '0'/'1'      │
                 └─────────────────┬───────────────────┘
                                   │
                 ┌─────────────────▼───────────────────┐
                 │ STEP 3: RN2 extraction → raw key    │
                 │                                     │
                 │ concat = RN2 ‖ SHA3-512(password)   │
                 │ digest = SHAKE-256(concat,          │
                 │           2048 × 4 bytes)           │
                 │ positions = unpack as uint32        │
                 │             mod 65536               │
                 │                                     │
                 │ raw_key[i] =                        │
                 │   crypto_table[positions[i]]        │
                 │ → 2048-entry list of '0'/'1'        │
                 └─────────────────┬───────────────────┘
                                   │
                 ┌─────────────────▼───────────────────┐
                 │ STEP 4: Select 256 bits             │
                 │                                     │
                 │ seed = SHA-256(password)            │
                 │ random.seed(seed)                   │
                 │ key_indices = random.sample(        │
                 │   range(2048), 256)                 │
                 │                                     │
                 │ ephemeral_key =                     │
                 │   ''.join(raw_key[i]                │
                 │           for i in key_indices)     │
                 │ → 256-bit binary string             │
                 │ → convert to 32 bytes               │
                 └─────────────────┬───────────────────┘
                                   │
                                   │
      ╔════════════════════════════╧════════════════════════════╗
      ║          SEED PHRASE ENCRYPT / DECRYPT                  ║
      ╚════════════════════════════╤════════════════════════════╝
                                   │
            ┌──────────────────────┴──────────────────────┐
            │                                             │
   (after enrollment)                            (after retrieval)
            │                                             │
  ┌─────────▼──────────────┐                 ┌────────────▼─────────────┐
  │ ENCRYPT:               │                 │ DECRYPT:                 │
  │                        │                 │                          │
  │ plaintext =            │                 │ Load RN1, RN2 from       │
  │   seed.encode('utf-8') │                 │   seed_nonces.bin        │
  │                        │                 │   (AES-decrypt with      │
  │ cipher = AES-256-CBC   │                 │    SHA-256(password))    │
  │   (random IV)          │                 │                          │
  │   key = ephemeral_key  │                 │ Read encrypted_seed      │
  │                        │                 │   from disk              │
  │ ct = cipher.encrypt(   │                 │                          │
  │   PKCS7_pad(plaintext))│                 │ iv = encrypted_seed[:16] │
  │                        │                 │ ct = encrypted_seed[16:] │
  │ encrypted_seed =       │                 │                          │
  │   IV ‖ ct              │                 │ cipher = AES-256-CBC     │
  └─────────┬──────────────┘                 │   key = ephemeral_key    │
            │                                │                          │
  ┌─────────▼──────────────┐                 │ plaintext =              │
  │ STORE to USB:          │                 │   PKCS7_unpad(           │
  │  • encrypted_seed      │                 │     cipher.decrypt(ct))  │
  │  • seed_nonces.bin     │                 │                          │
  │    (RN1 + RN2,         │                 │ seed_phrase =            │
  │     AES-encrypted      │                 │   plaintext.decode()     │
  │     with password)     │                 └────────────┬─────────────┘
  │  • update file_info    │                              │
  │    .json with nonces   │                 ┌────────────▼─────────────┐
  │    filename            │                 │ Return seed_phrase       │
  └────────────────────────┘                 └──────────────────────────┘
```

## Some Things to Note

`l` is never stored directly. During enrollment it's used as a **bit mask** to select
a subset of deterministic responses (`kr`). During retrieval, the same responses are
regenerated, and by matching `kr` back to the full list, the protocol infers which
positions were selected — recovering the bit pattern of `l`. The hash `hkey` confirms
correctness.

However, `l` is **not** the key that encrypts the seed phrase. Instead, `l` is used to
**decrypt the enrolled VT file**, recovering the original digital file bytes. Those bytes
are then run through the **Gen-2 VT protocol** — a separate challenge-response
derivation using two random nonces (RN1 and RN2):

1. **SHAKE-256** hashes the file into a 1M-bit binary string
2. **RN1** + password derive challenge addresses → index the binary string → crypto table
3. **RN2** + password derive extraction positions → index the crypto table → raw key
4. A password-seeded selection picks **256 bits** from the raw key → `ephemeral_key`

The seed phrase is encrypted/decrypted with **AES-256-CBC** using `ephemeral_key`.
RN1 and RN2 are stored (AES-encrypted with the password) alongside the encrypted seed
so the same `ephemeral_key` can be re-derived at retrieval time.

### Stored Artifacts

| Storage    | Contents                                         |
|------------|--------------------------------------------------|
| USB        | `file_info.json`, keys file, seed nonces, encrypted seed |
| Database   | Encrypted VT file (or keys, depending on config) |
| Google Drive | Keys or encrypted VT file (depending on config) |
