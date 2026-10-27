import socket
import threading
import json
import os
import secrets
import string

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEYS_FILE = "kdc_keys.json"
LOCK = threading.Lock()


def load_keys():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE) as f:
            return json.load(f)
    return {}


def save_keys(keys):
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=2)


def normalize_key(ascii_key: str) -> bytes:
    kb = ascii_key.encode("ascii", errors="ignore")
    if len(kb) < 16:
        kb = kb + b"\x00" * (16 - len(kb))
    return kb[:16]


def lib_aes_encrypt(plaintext_bytes: bytes, ascii_key: str):
    """AES-CBC (pakai pycryptodome) -> (iv_hex, ct_hex). Hanya dipakai KDC."""
    key = normalize_key(ascii_key)
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext_bytes, 16))
    return iv.hex(), ct.hex()


def random_session_key(length=16) -> str:
    """Bangkitkan Ks ASCII acak (dipakai sebagai key AES manual Alice<->Bob)."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def send_json(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())


def recv_json_line(conn, buf: bytes):
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return None, buf
        buf += chunk
    line, _, rest = buf.partition(b"\n")
    return json.loads(line.decode()), rest


    print(f"[KDC] Koneksi masuk dari {addr}")
    buf = b""
    try:
        msg, buf = recv_json_line(conn, buf)
        if msg is None or msg.get("step") != 1:
            print("[KDC] Pesan step-1 tidak valid, menutup koneksi.")
            return

        ida, idb, n1 = msg["IDA"], msg["IDB"], msg["N1"]
        print(f"[KDC] Step 1 diterima: IDA={ida} IDB={idb} N1={n1}")

        with LOCK:
            keys = load_keys()
        if ida not in keys or idb not in keys:
            print(f"[KDC] ID tidak dikenal (IDA/IDB belum terdaftar di {KEYS_FILE})")
            send_json(conn, {"step": 2, "error": "ID tidak terdaftar di KDC"})
            return

        ka, kb = keys[ida], keys[idb]
        ks = random_session_key(16)
        print(f"[KDC] Session key Ks dibangkitkan untuk {ida}<->{idb}: {ks}")

        part1_plain = json.dumps({"Ks": ks, "IDA": ida, "IDB": idb, "N1": n1}).encode()
        part2_plain = json.dumps({"Ks": ks, "IDA": ida}).encode()

        iv1, ct1 = lib_aes_encrypt(part1_plain, ka)   # E(Ka, [Ks||IDA||IDB||N1])
        iv2, ct2 = lib_aes_encrypt(part2_plain, kb)   # E(Kb, [Ks||IDA])  <- tiket utk B

        send_json(conn, {
            "step": 2,
            "part1_iv": iv1, "part1_ct": ct1,
            "part2_iv": iv2, "part2_ct": ct2,
        })
        print(f"[KDC] Step 2 dikirim ke {ida} (ticket utk {idb} disertakan).")
    except Exception as e:
        print(f"[KDC] Error menangani {addr}: {e}")
    finally:
        conn.close()


def admin_console(host, port):
    """Console interaktif KDC: tambah/ubah/lihat key kapan saja tanpa restart server."""
    print("\n=== KDC Admin Console ===")
    print(f"KDC mendengarkan di {host}:{port}")
    print("Perintah: list | setkey <ID> <key-ascii> | help | quit\n")
    while True:
        try:
            cmd = input("kdc> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd:
            continue
        parts = cmd.split(maxsplit=2)
        op = parts[0].lower()

        if op == "help":
            print("  list                      - tampilkan semua ID & key terdaftar")
            print("  setkey <ID> <key-ascii>   - set/ubah long-term key untuk suatu ID")
            print("  quit                      - keluar (server tetap jalan di background)")
        elif op == "list":
            with LOCK:
                keys = load_keys()
            if not keys:
                print("  (belum ada key terdaftar)")
            for k, v in keys.items():
                print(f"  {k:10s} : {v}")
        elif op == "setkey" and len(parts) == 3:
            _, kid, kval = parts
            with LOCK:
                keys = load_keys()
                keys[kid.upper()] = kval
                save_keys(keys)
            print(f"  OK -> key untuk {kid.upper()} di-set.")
        elif op == "quit":
            print("  (console ditutup, server KDC tetap berjalan)")
            break
        else:
            print("  perintah tidak dikenal, ketik 'help'")


def main():
    print("=== Key Distribution Center (KDC) ===")
    host = input("Bind IP KDC ini [default 0.0.0.0]: ").strip() or "0.0.0.0"
    port_s = input("Port KDC [default 9000]: ").strip() or "9000"
    port = int(port_s)

    if not os.path.exists(KEYS_FILE):
        print(f"\n({KEYS_FILE} belum ada, mari daftarkan key awal)")
        keys = {}
        while True:
            kid = input("  Masukkan ID (misal ALICE), kosongkan utk selesai: ").strip().upper()
            if not kid:
                break
            kkey = input(f"  Masukkan long-term key ASCII untuk {kid}: ").strip()
            keys[kid] = kkey
        save_keys(keys)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)

    def accept_loop():
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    admin_console(host, port)


if __name__ == "__main__":
    main()
