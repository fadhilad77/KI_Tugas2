SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
INV_SBOX = [0]*256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

NB = 4   
NK = 4   
NR = 10  



def xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def gmul(a, b):
    """Perkalian di GF(2^8) (untuk MixColumns)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF


def key_expansion(key_bytes):
    """key_bytes: 16 byte -> menghasilkan 11 round key (masing-masing 16 byte)."""
    assert len(key_bytes) == 16
    w = [list(key_bytes[4*i:4*i+4]) for i in range(NK)]

    for i in range(NK, NB * (NR + 1)):
        temp = list(w[i - 1])
        if i % NK == 0:
            temp = temp[1:] + temp[:1]                 # RotWord
            temp = [SBOX[b] for b in temp]              # SubWord
            temp[0] ^= RCON[i // NK - 1]                # Rcon
        w.append([w[i - NK][j] ^ temp[j] for j in range(4)])

    round_keys = []
    for r in range(NR + 1):
        rk = []
        for c in range(4):
            rk += w[r * 4 + c]
        round_keys.append(rk)
    return round_keys


def bytes_to_state(block):
    """16 byte -> matrix 4x4 (column-major, sesuai spesifikasi AES)."""
    return [[block[r + 4*c] for c in range(4)] for r in range(4)]


def state_to_bytes(state):
    out = [0]*16
    for r in range(4):
        for c in range(4):
            out[r + 4*c] = state[r][c]
    return bytes(out)


def add_round_key(state, round_key):
    rk = bytes_to_state(round_key)
    for r in range(4):
        for c in range(4):
            state[r][c] ^= rk[r][c]


def sub_bytes(state, box):
    for r in range(4):
        for c in range(4):
            state[r][c] = box[state[r][c]]


def shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]


def inv_shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]


def mix_columns(state):
    for c in range(4):
        a0, a1, a2, a3 = (state[0][c], state[1][c], state[2][c], state[3][c])
        state[0][c] = gmul(a0,2) ^ gmul(a1,3) ^ a2 ^ a3
        state[1][c] = a0 ^ gmul(a1,2) ^ gmul(a2,3) ^ a3
        state[2][c] = a0 ^ a1 ^ gmul(a2,2) ^ gmul(a3,3)
        state[3][c] = gmul(a0,3) ^ a1 ^ a2 ^ gmul(a3,2)


def inv_mix_columns(state):
    for c in range(4):
        a0, a1, a2, a3 = (state[0][c], state[1][c], state[2][c], state[3][c])
        state[0][c] = gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9)
        state[1][c] = gmul(a0,9)  ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13)
        state[2][c] = gmul(a0,13) ^ gmul(a1,9)  ^ gmul(a2,14) ^ gmul(a3,11)
        state[3][c] = gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9)  ^ gmul(a3,14)


def encrypt_block(block, round_keys):
    state = bytes_to_state(block)
    add_round_key(state, round_keys[0])
    for rnd in range(1, NR):
        sub_bytes(state, SBOX)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[rnd])
    sub_bytes(state, SBOX)
    shift_rows(state)
    add_round_key(state, round_keys[NR])
    return state_to_bytes(state)


def decrypt_block(block, round_keys):
    state = bytes_to_state(block)
    add_round_key(state, round_keys[NR])
    for rnd in range(NR - 1, 0, -1):
        inv_shift_rows(state)
        sub_bytes(state, INV_SBOX)
        add_round_key(state, round_keys[rnd])
        inv_mix_columns(state)
    inv_shift_rows(state)
    sub_bytes(state, INV_SBOX)
    add_round_key(state, round_keys[0])
    return state_to_bytes(state)


def pkcs7_pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Padding tidak valid")
    return data[:-pad_len]



def normalize_key(ascii_key: str) -> bytes:
    """Key ASCII bebas panjang -> tepat 16 byte (pad dengan 0x00 / potong)."""
    kb = ascii_key.encode("ascii", errors="ignore")
    if len(kb) < 16:
        kb = kb + b"\x00" * (16 - len(kb))
    else:
        kb = kb[:16]
    return kb



def aes_encrypt_hex(plaintext: str, ascii_key: str) -> str:
    key_bytes = normalize_key(ascii_key)
    round_keys = key_expansion(key_bytes)
    data = pkcs7_pad(plaintext.encode("utf-8"))
    out = b""
    for i in range(0, len(data), 16):
        out += encrypt_block(data[i:i+16], round_keys)
    return out.hex()


def aes_decrypt_hex(ciphertext_hex: str, ascii_key: str) -> str:
    key_bytes = normalize_key(ascii_key)
    round_keys = key_expansion(key_bytes)
    data = bytes.fromhex(ciphertext_hex)
    out = b""
    for i in range(0, len(data), 16):
        out += decrypt_block(data[i:i+16], round_keys)
    out = pkcs7_unpad(out)
    return out.decode("utf-8", errors="replace")



if __name__ == "__main__":
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt  = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ct = "69c4e0d86a7b0430d8cdb78070b4c55a"
    rk = key_expansion(key)
    ct = encrypt_block(pt, rk)
    print("Test vector FIPS-197:")
    print("  ciphertext dihasilkan :", ct.hex())
    print("  ciphertext seharusnya :", expected_ct)
    assert ct.hex() == expected_ct, "AES block cipher SALAH!"
    back = decrypt_block(ct, rk)
    assert back == pt, "AES decrypt SALAH!"
    print("  OK - block cipher benar\n")

    print("Test high-level API (ASCII key & plaintext, hex ciphertext):")
    c = aes_encrypt_hex("Hello, Bob! Ini pesan rahasia dari Alice.", "RahasiaKunci123")
    print("  ciphertext hex:", c)
    p = aes_decrypt_hex(c, "RahasiaKunci123")
    print("  plaintext     :", p)
    assert p == "Hello, Bob! Ini pesan rahasia dari Alice."
    print("  OK - encrypt/decrypt roundtrip benar")
