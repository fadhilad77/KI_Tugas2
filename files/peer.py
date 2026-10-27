import socket
import threading
import json
import secrets

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

import aes_manual as amanual


def normalize_key(ascii_key: str) -> bytes:
    kb = ascii_key.encode("ascii", errors="ignore")
    if len(kb) < 16:
        kb = kb + b"\x00" * (16 - len(kb))
    return kb[:16]


def lib_aes_decrypt(iv_hex, ct_hex, ascii_key):
    key = normalize_key(ascii_key)
    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), 16)
    return json.loads(pt.decode())


def send_json(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())


class LineReader:
    """Pembaca stream TCP per-baris (biar bisa dipakai di loop recv thread)."""
    def __init__(self, conn):
        self.conn = conn
        self.buf = b""

    def read_json(self):
        while b"\n" not in self.buf:
            chunk = self.conn.recv(4096)
            if not chunk:
                return None
            self.buf += chunk
        line, _, self.buf = self.buf.partition(b"\n")
        if not line:
            return self.read_json()
        return json.loads(line.decode())


def chat_loop(conn, reader: LineReader, my_id, peer_id, ks_holder):
    """ks_holder = dict {'ks': <str>} supaya Ks bisa diganti interaktif
    (misal mau test apa yang terjadi kalau key beda / salah) tanpa restart."""

    stop_flag = {"stop": False}

    def recv_worker():
        while not stop_flag["stop"]:
            try:
                msg = reader.read_json()
            except Exception:
                break
            if msg is None:
                print(f"\n[{my_id}] Koneksi dengan {peer_id} terputus.")
                stop_flag["stop"] = True
                break
            if msg.get("type") == "msg":
                try:
                    pt = amanual.aes_decrypt_hex(msg["ct"], ks_holder["ks"])
                except Exception as e:
                    pt = f"(gagal decrypt dgn Ks saat ini: {e})"
                print(f"\n[{peer_id} -> {my_id}] ciphertext(hex)={msg['ct']}")
                print(f"[{peer_id} -> {my_id}] plaintext       ={pt}\n{my_id}> ", end="", flush=True)

    threading.Thread(target=recv_worker, daemon=True).start()

    print(f"\n=== Chat aktif antara {my_id} <-> {peer_id} (Ks = {ks_holder['ks']}) ===")
    print("Perintah: ketik pesan lalu Enter utk kirim | ':setkey <baru>' ganti Ks lokal")
    print("          ':showkey' lihat Ks saat ini | ':quit' keluar\n")

    while not stop_flag["stop"]:
        try:
            line = input(f"{my_id}> ")
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        if line.startswith(":setkey "):
            ks_holder["ks"] = line.split(" ", 1)[1].strip()
            print(f"  (Ks lokal sekarang: {ks_holder['ks']})")
            continue
        if line.strip() == ":showkey":
            print(f"  (Ks lokal sekarang: {ks_holder['ks']})")
            continue
        if line.strip() == ":quit":
            break

        ct_hex = amanual.aes_encrypt_hex(line, ks_holder["ks"])
        try:
            send_json(conn, {"type": "msg", "ct": ct_hex})
        except Exception as e:
            print(f"  gagal kirim: {e}")
            break
        print(f"  (terkirim, ciphertext hex = {ct_hex})")

    stop_flag["stop"] = True
    conn.close()
    print(f"[{my_id}] Chat selesai.")


def run_initiator():
    print("=== Mode: INITIATOR (contoh: Alice) ===")
    my_id = input("ID saya (misal ALICE): ").strip().upper()
    my_key = input(f"Long-term key (Ka) saya dgn KDC utk {my_id}: ").strip()
    kdc_host = input("IP KDC: ").strip()
    kdc_port = int(input("Port KDC [9000]: ").strip() or "9000")
    peer_id = input("ID peer (misal BOB): ").strip().upper()
    peer_host = input("IP peer (tempat peer listen): ").strip()
    peer_port = int(input("Port peer [9100]: ").strip() or "9100")

    # --- Step 1: kirim IDA||IDB||N1 ke KDC ---
    n1 = secrets.randbelow(10**6)
    print(f"\n[{my_id}] Step 1 -> KDC: IDA={my_id} IDB={peer_id} N1={n1}")
    kdc_sock = socket.create_connection((kdc_host, kdc_port))
    send_json(kdc_sock, {"step": 1, "IDA": my_id, "IDB": peer_id, "N1": n1})

    kdc_reader = LineReader(kdc_sock)
    resp = kdc_reader.read_json()
    kdc_sock.close()
    if resp is None or "error" in resp:
        print(f"[{my_id}] Gagal dari KDC: {resp}")
        return

    # --- Step 2: buka E(Ka, [Ks||IDA||IDB||N1]) ---
    part1 = lib_aes_decrypt(resp["part1_iv"], resp["part1_ct"], my_key)
    print(f"[{my_id}] Step 2 diterima & didekripsi pakai Ka: {part1}")
    if part1["N1"] != n1 or part1["IDA"] != my_id or part1["IDB"] != peer_id:
        print(f"[{my_id}] PERINGATAN: N1/ID tidak cocok, kemungkinan replay/serangan!")
        return
    ks = part1["Ks"]
    print(f"[{my_id}] Session key Ks diperoleh: {ks}")

    ticket_iv, ticket_ct = resp["part2_iv"], resp["part2_ct"]  # E(Kb,[Ks||IDA]) -- tidak bisa dibuka Alice

    # --- Step 3: teruskan tiket ke peer (Bob) ---
    print(f"[{my_id}] Step 3 -> {peer_id} ({peer_host}:{peer_port}): meneruskan tiket E(Kb,[Ks||IDA])")
    conn = socket.create_connection((peer_host, peer_port))
    reader = LineReader(conn)
    send_json(conn, {"step": 3, "ticket_iv": ticket_iv, "ticket_ct": ticket_ct})

    # --- Step 4: terima E(Ks, N2) dari Bob (AES MANUAL) ---
    msg4 = reader.read_json()
    if msg4 is None or msg4.get("step") != 4:
        print(f"[{my_id}] Tidak menerima step 4 yang valid, batal.")
        conn.close()
        return
    n2_payload = json.loads(amanual.aes_decrypt_hex(msg4["ct"], ks))
    n2 = n2_payload["N2"]
    print(f"[{my_id}] Step 4 diterima, N2={n2} (didekripsi pakai Ks, AES manual)")

    # --- Step 5: kirim E(Ks, f(N2)) ---
    fn2 = n2 - 1   # fungsi f sederhana yang disepakati (N2 - 1)
    ct5 = amanual.aes_encrypt_hex(json.dumps({"fN2": fn2}), ks)
    send_json(conn, {"step": 5, "ct": ct5})
    print(f"[{my_id}] Step 5 -> {peer_id}: kirim E(Ks, f(N2)={fn2}) (AES manual)")
    print(f"[{my_id}] Handshake KDC selesai. Autentikasi & distribusi key berhasil!\n")

    ks_holder = {"ks": ks}
    chat_loop(conn, reader, my_id, peer_id, ks_holder)



def run_responder():
    print("=== Mode: RESPONDER (contoh: Bob) ===")
    my_id = input("ID saya (misal BOB): ").strip().upper()
    my_key = input(f"Long-term key (Kb) saya dgn KDC utk {my_id}: ").strip()
    bind_host = input("IP bind saya [0.0.0.0]: ").strip() or "0.0.0.0"
    bind_port = int(input("Port listen saya [9100]: ").strip() or "9100")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_host, bind_port))
    srv.listen(1)
    print(f"[{my_id}] Menunggu koneksi dari initiator di {bind_host}:{bind_port} ...")
    conn, addr = srv.accept()
    print(f"[{my_id}] Koneksi masuk dari {addr}")
    reader = LineReader(conn)

    # --- Step 3: terima tiket E(Kb, [Ks||IDA]) ---
    msg3 = reader.read_json()
    if msg3 is None or msg3.get("step") != 3:
        print(f"[{my_id}] Step 3 tidak valid, menutup koneksi.")
        conn.close()
        return
    ticket = lib_aes_decrypt(msg3["ticket_iv"], msg3["ticket_ct"], my_key)
    ks, peer_id = ticket["Ks"], ticket["IDA"]
    print(f"[{my_id}] Step 3 diterima & didekripsi pakai Kb: Ks={ks} dari IDA={peer_id}")

    # --- Step 4: kirim E(Ks, N2) (AES MANUAL) ---
    n2 = secrets.randbelow(10**6)
    ct4 = amanual.aes_encrypt_hex(json.dumps({"N2": n2}), ks)
    send_json(conn, {"step": 4, "ct": ct4})
    print(f"[{my_id}] Step 4 -> {peer_id}: kirim E(Ks, N2={n2}) (AES manual)")

    # --- Step 5: terima & verifikasi E(Ks, f(N2)) ---
    msg5 = reader.read_json()
    if msg5 is None or msg5.get("step") != 5:
        print(f"[{my_id}] Step 5 tidak diterima, batal.")
        conn.close()
        return
    fn2_payload = json.loads(amanual.aes_decrypt_hex(msg5["ct"], ks))
    fn2_received = fn2_payload["fN2"]
    expected = n2 - 1
    if fn2_received == expected:
        print(f"[{my_id}] Step 5 terverifikasi: f(N2) cocok ({fn2_received}). Autentikasi SUKSES!\n")
    else:
        print(f"[{my_id}] PERINGATAN: f(N2) TIDAK cocok (dapat={fn2_received}, harus={expected}). "
              f"Autentikasi GAGAL, tapi chat tetap dibuka utk keperluan testing.\n")

    ks_holder = {"ks": ks}
    chat_loop(conn, reader, my_id, peer_id, ks_holder)


def main():
    print("=== Peer Program (dipakai utk Alice maupun Bob) ===")
    print("  1) INITIATOR  (mulai ke KDC lebih dulu, lalu hubungi peer)  -> role 'Alice'")
    print("  2) RESPONDER  (menunggu koneksi dari initiator)             -> role 'Bob'")
    role = input("Pilih role [1/2]: ").strip()
    if role == "1":
        run_initiator()
    elif role == "2":
        run_responder()
    else:
        print("Pilihan tidak valid.")


if __name__ == "__main__":
    main()
