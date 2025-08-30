#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json, base64, time, secrets, argparse, sys, os, threading
from typing import Any, Dict, Tuple

try:
    import oqs
except Exception:
    print("[ERROR] Can't import oqs (PyOQS).")
    sys.exit(1)

SIGNED_FIELDS = ["topic", "seq", "ts", "payload", "nonce", "pubkey_id"]

# size/security limits (defense-in-depth)
MAX_JSON_BYTES = 64 * 1024          # max input JSON file size
MAX_CANON_BYTES = 64 * 1024         # max canonical bytes for signed part
MAX_SIG_BYTES = 8 * 1024            # generous cap for Dilithium signatures
MAX_B64_SIG_LEN = 12 * 1024         # base64 text length cap before decode
MAX_NONCE_LEN = 256                 # cap to avoid pathological inputs
MAX_TOPIC_LEN = 128

def canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def now_ms() -> int: return int(time.time() * 1000)
def new_nonce(nbytes: int = 12) -> str:
    # URL-safe base64, strip '=' padding
    return base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).decode().rstrip("=")

def load_pub(pub_path: str) -> dict:
    with open(pub_path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_sec(sec_path: str) -> dict:
    # 確認檔案權限（僅限擁有者可讀寫）
    try:
        st = os.stat(sec_path)
        if (st.st_mode & 0o077) != 0:
            raise SystemExit(f"[ERROR] Secret key file permissions too open: {oct(st.st_mode & 0o777)}; expected 0600")
    except FileNotFoundError:
        raise
    with open(sec_path, "r", encoding="utf-8") as f:
        return json.load(f)

class Signer:
    def __init__(self, secdoc: dict):
        self.alg = secdoc["alg"]
        self.pubkey_id = secdoc["pubkey_id"]
        self.secret = base64.b64decode(secdoc["secret_b64"])
        # The secret key is passed to the constructor to create a stateful signer object
        self._signer = oqs.Signature(self.alg, self.secret)

    def make_cmd(self, linear_x: float, angular_z: float, pubkey_id: str | None = None) -> dict:
        return {
            "topic": "/cmd_vel",
            "seq": now_ms() % 1_000_000,
            "ts": now_ms(),
            "payload": {
                "linear": {"x": float(linear_x), "y": 0.0, "z": 0.0},
                "angular": {"x": 0.0, "y": 0.0, "z": float(angular_z)},
            },
            "nonce": new_nonce(),
            "pubkey_id": pubkey_id or self.pubkey_id,
        }

    def sign_message(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        part = {k: msg[k] for k in SIGNED_FIELDS}
        payload = canon(part)
        # The stateful _signer object already holds the secret key
        sig = self._signer.sign(payload)
        out = dict(msg)
        out["signature"] = base64.b64encode(sig).decode()
        return out

class Verifier:
    def __init__(self, pubdocs: dict[str, dict], window_ms: int = 2000):
        # pubdocs: pubkey_id -> pubdoc
        self.window_ms = window_ms
        self.keyring: dict[str, Tuple[str, bytes]] = {}
        for pid, d in pubdocs.items():
            self.keyring[pid] = (d["alg"], base64.b64decode(d["pubkey_b64"]))
        # (pubkey_id, nonce) -> timestamp
        self.seen: dict[Tuple[str, str], int] = {}
        self._lock = threading.Lock()

    def verify(self, signed: Dict[str, Any]) -> Tuple[bool, str]:
        pid = signed.get("pubkey_id")
        if pid not in self.keyring:
            return False, "ERR_NO_SUCH_PUBKEY_ID"
        # type/shape checks (cheap checks first)
        if not isinstance(signed.get("topic"), str) or not signed["topic"] or len(signed["topic"]) > MAX_TOPIC_LEN:
            return False, "ERR_BAD_TOPIC"
        try:
            ts = int(signed.get("ts", 0))
        except (TypeError, ValueError):
            return False, "ERR_BAD_TS"
        if abs(now_ms() - ts) > self.window_ms:
            return False, "ERR_TS_WINDOW"
        nonce = str(signed.get("nonce", ""))
        if not nonce or len(nonce) > MAX_NONCE_LEN:
            return False, "ERR_BAD_NONCE"
        if not isinstance(signed.get("seq"), (int,)):
            return False, "ERR_BAD_SEQ"
        if not isinstance(signed.get("payload"), dict):
            return False, "ERR_BAD_PAYLOAD"
        key = (pid, nonce)
        now = now_ms()
        # 清理過期的 nonce，避免記憶體洩漏（加鎖以確保執行緒安全）
        with self._lock:
            expiry = now - self.window_ms
            self.seen = {k: t for k, t in self.seen.items() if t >= expiry}
            if key in self.seen:
                return False, "ERR_REPLAY"
        try:
            sig_b64 = signed.get("signature", "")
            if not isinstance(sig_b64, str) or len(sig_b64) > MAX_B64_SIG_LEN:
                return False, "ERR_BAD_BASE64"
            sig = base64.b64decode(sig_b64, validate=True)
        except Exception:
            return False, "ERR_BAD_BASE64"
        if len(sig) > MAX_SIG_BYTES:
            return False, "ERR_SIG_TOO_LARGE"
        missing = [k for k in SIGNED_FIELDS if k not in signed]
        if missing:
            return False, "ERR_MISSING_FIELDS"
        part = {k: signed[k] for k in SIGNED_FIELDS}
        # 限制 canonical bytes 大小，避免超大 payload 造成 DoS
        part_bytes = canon(part)
        if len(part_bytes) > MAX_CANON_BYTES:
            return False, "ERR_MSG_TOO_LARGE"
        alg, pk = self.keyring[pid]
        try:
            with oqs.Signature(alg) as v:
                ok = v.verify(part_bytes, sig, pk)
        except Exception:
            return False, "ERR_VERIFY_EXCEPTION"
        if not ok:
            return False, "ERR_BAD_SIGNATURE"
        with self._lock:
            self.seen[key] = now
        return True, "OK"

def cli():
    ap = argparse.ArgumentParser(description="Sign/Verify demo using ML‑DSA JSON keys")
    ap.add_argument("--pub", help="ml_dsa_pub.json", required=True)
    ap.add_argument("--sec", help="ml_dsa_sec.json (for signing)")
    ap.add_argument("--mode", choices=["sign","verify"], required=True)
    ap.add_argument("--in", dest="infile", help="input JSON (when mode=verify)")
    ap.add_argument("--out", dest="outfile", help="output JSON (when mode=sign)")
    args = ap.parse_args()

    if args.mode == "sign":
        if not args.sec:
            raise SystemExit("--sec is required for sign mode")
        secdoc = load_sec(args.sec)
        signer = Signer(secdoc)
        msg = signer.make_cmd(0.1, 0.2)
        signed = signer.sign_message(msg)
        data = json.dumps(signed, ensure_ascii=False, indent=2)
        if args.outfile:
            with open(args.outfile, "w", encoding="utf-8") as f: f.write(data)
            print(f"[OK] wrote {args.outfile}")
        else:
            print(data)
    else:
        pubdoc = load_pub(args.pub)
        if args.infile:
            try:
                sz = os.path.getsize(args.infile)
                if sz > MAX_JSON_BYTES:
                    raise SystemExit(f"[ERROR] input JSON too large ({sz} bytes) > {MAX_JSON_BYTES}")
            except FileNotFoundError:
                raise
        with open(args.infile, "r", encoding="utf-8") as f:
            signed = json.load(f)
        v = Verifier({pubdoc["pubkey_id"]: pubdoc}, window_ms=2000)
        ok, code = v.verify(signed)
        print({"ok": ok, "code": code})

if __name__ == "__main__":
    cli()

# 先產生金鑰
#python keygen.py --pubkey-id controller-01

# 簽一筆 /cmd_vel 指令（存檔）
#python sign_verify.py --mode sign --sec ml_dsa_sec.json --pub ml_dsa_pub.json --out signed_cmd.json

# 驗證那筆指令
#python sign_verify.py --mode verify --pub ml_dsa_pub.json --in signed_cmd.json
