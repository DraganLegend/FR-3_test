#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json, base64, os, sys, argparse, tempfile

try:
    import oqs
except Exception as e:
    print("[ERROR] Can't import oqs (PyOQS). Make sure liboqs/pyoqs is installed.")
    sys.exit(1)

def get_enabled_schemes():
    # 新 API
    if hasattr(oqs, "get_enabled_sig_mechanisms"):
        try:
            return set(oqs.get_enabled_sig_mechanisms())
        except Exception:
            pass
    # 舊 API1
    if hasattr(oqs, "Signature") and hasattr(oqs.Signature, "algorithms"):
        try:
            return set(oqs.Signature.algorithms)
        except Exception:
            pass
    # 舊 API2
    if hasattr(oqs, "get_enabled_sigs"):
        try:
            return set(oqs.get_enabled_sigs())
        except Exception:
            pass
    return set()

PREF = ["ML-DSA-44", "Dilithium2", "ML-DSA-65", "Dilithium3", "ML-DSA-87", "Dilithium5"]

def choose_scheme(requested: str | None, available: set[str]) -> str:
    if requested:
        if requested in available:
            return requested
        # 常見別名
        alias = {
            "dilithium2": "Dilithium2",
            "dilithium3": "Dilithium3",
            "dilithium5": "Dilithium5",
            "ml-dsa-44": "ML-DSA-44",
            "ml-dsa-65": "ML-DSA-65",
            "ml-dsa-87": "ML-DSA-87",
        }
        key = requested.strip()
        key = alias.get(key.lower(), key)
        if key in available:
            return key
        print(f"[WARN] Requested alg '{requested}' not available. Available: {sorted(available)}")
    for a in PREF:
        if a in available:
            return a
    raise SystemExit("[ERROR] No ML‑DSA/Dilithium scheme available in your oqs build.")

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")

def write_json(path: str, obj: dict, secret: bool = False):
    data = json.dumps(obj, ensure_ascii=False, indent=2)
    if secret:
        # 以原子方式寫入秘密檔：先寫入臨時檔（0600、O_EXCL）再 os.replace 取代
        dir_name = os.path.dirname(path) or "."
        base_name = os.path.basename(path)
        tmp_name = None
        try:
            # 建立唯一臨時檔（0600）避免競態與短暫權限暴露
            fd, tmp_name = tempfile.mkstemp(prefix=f".{base_name}.", dir=dir_name, text=True)
            try:
                os.fchmod(fd, 0o600)
            except Exception:
                pass
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, path)
        finally:
            # 若替換失敗，清理臨時檔
            if tmp_name and os.path.exists(tmp_name):
                try:
                    os.remove(tmp_name)
                except Exception:
                    pass
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
    print(f"[OK] wrote {path}")

def main():
    ap = argparse.ArgumentParser(description="Generate ML‑DSA (Dilithium) keypair")
    ap.add_argument("--pubkey-id", default="controller-01", help="pubkey identity string")
    ap.add_argument("--alg", default=None, help="algorithm name (e.g., ML-DSA-44, Dilithium3)")
    ap.add_argument("--out-pub", default="ml_dsa_pub.json")
    ap.add_argument("--out-sec", default="ml_dsa_sec.json")
    args = ap.parse_args()

    avail = get_enabled_schemes()
    if not avail:
        raise SystemExit("[ERROR] No oqs signature mechanisms detected. Check your installation.")

    scheme = choose_scheme(args.alg, avail)
    print(f"[INFO] Using scheme: {scheme}")

    with oqs.Signature(scheme) as signer:
        pub = signer.generate_keypair()
        sec = signer.export_secret_key()

    pubdoc = {
        "type": "ml-dsa-public",
        "alg": scheme,
        "pubkey_id": args.pubkey_id,
        "pubkey_b64": b64(pub),
    }
    secdoc = {
        "type": "ml-dsa-secret",
        "alg": scheme,
        "pubkey_id": args.pubkey_id,
        "secret_b64": b64(sec),
    }

    write_json(args.out_pub, pubdoc, secret=False)
    write_json(args.out_sec, secdoc, secret=True)
    print("[DONE] Keep your secret file safe (0600). Distribute only the public JSON.")

if __name__ == "__main__":
    main()

#
# 產生一組 Dilithium2 / ML‑DSA‑44 金鑰
#python keygen.py --pubkey-id controller-01

# 指定 ML‑DSA‑65（等效 Dilithium3）
#python keygen.py --pubkey-id controller-02 --alg ML-DSA-65
