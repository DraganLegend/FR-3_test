# FR-3 PQC PoC

## 1) 安裝
- macOS (Apple Silicon)
  - `brew install liboqs pkg-config cmake ninja`
  - `uv pip install --no-binary=:all: pyoqs`

## 2) 產生金鑰
```bash
python keygen.py --pubkey-id controller-01
```
## 3) 簽章 / 驗證（單筆）
```bash
python sign_verify.py --mode sign --sec ml_dsa_sec.json --pub ml_dsa_pub.json --out signed_cmd.json && python sign_verify.py --mode verify --pub ml_dsa_pub.json --in signed_cmd.json
```
## 4) 自動化測試（四情境 ×10）
```bash
python test_poc.py
```
