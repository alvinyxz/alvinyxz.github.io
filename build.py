#!/usr/bin/env python3
"""
build.py — round-trip editor for the password-protected churning.html page.

churning.html is a StatiCrypt page: the card data lives inside it as one
AES-CBC-encrypted blob. This script lets you edit that data in place without
ever putting plaintext into the repo.

    python3 build.py decrypt     # churning.html  ->  cards.html   (plaintext, gitignored)
    python3 build.py encrypt     # cards.html     ->  churning.html (re-encrypts the blob)

Typical edit session (works anywhere, incl. Claude Code on mobile):
    export CHURNING_PASSWORD='...'      # or you'll be prompted
    python3 build.py decrypt            # get the editable HTML
    #   ...edit cards.html (the ROWS array)...
    python3 build.py encrypt            # fold changes back into churning.html
    git commit -am 'update cards' && git push

The public repo only ever contains ciphertext: cards.html is gitignored and
churning.html holds only the encrypted blob. The password is never stored —
it comes from the CHURNING_PASSWORD env var, --password, or an interactive
prompt.

Crypto matches StatiCrypt exactly:
  key   = PBKDF2(SHA1,1000) -> PBKDF2(SHA256,14000) -> PBKDF2(SHA256,585000)
  blob  = HMAC_SHA256(key, iv||ct)  ||  iv  ||  ciphertext        (all hex)
  cipher = AES-256-CBC, PKCS7 padding
No external Python packages required — uses stdlib + the `openssl` CLI.
"""
import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.abspath(__file__))
CHURNING = os.path.join(REPO, "churning.html")
CARDS = os.path.join(REPO, "cards.html")

CONFIG_RE = re.compile(r"staticryptConfig = (\{.*?\});", re.S)
BLOB_RE = re.compile(r'("staticryptEncryptedMsgUniqueVariableName":")[0-9a-f]+(")')


def read_config():
    """Return (full_html, config_dict) parsed from churning.html."""
    html = open(CHURNING, encoding="utf-8").read()
    m = CONFIG_RE.search(html)
    if not m:
        sys.exit("error: could not find staticryptConfig in churning.html")
    return html, json.loads(m.group(1))


def get_password():
    pw = os.environ.get("CHURNING_PASSWORD")
    for i, arg in enumerate(sys.argv):
        if arg == "--password" and i + 1 < len(sys.argv):
            pw = sys.argv[i + 1]
    if not pw:
        pw = getpass.getpass("Password: ")
    if not pw:
        sys.exit("error: no password provided")
    return pw


def derive_key(password, salt):
    """StatiCrypt's 3-round PBKDF2 chain -> 32 raw key bytes."""
    s = salt.encode()
    h1 = hashlib.pbkdf2_hmac("sha1", password.encode(), s, 1000, 32).hex()
    h2 = hashlib.pbkdf2_hmac("sha256", h1.encode(), s, 14000, 32).hex()
    h3 = hashlib.pbkdf2_hmac("sha256", h2.encode(), s, 585000, 32).hex()
    return bytes.fromhex(h3)


def _openssl(args, data):
    p = subprocess.run(
        ["openssl", "enc", *args, "-nosalt"],
        input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if p.returncode != 0:
        sys.exit("openssl error: " + p.stderr.decode(errors="replace"))
    return p.stdout


def aes_encrypt(key, iv, plaintext):
    return _openssl(["-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex()], plaintext)


def aes_decrypt(key, iv, ciphertext):
    return _openssl(["-d", "-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex()], ciphertext)


def decrypt():
    html, cfg = read_config()
    key = derive_key(get_password(), cfg["staticryptSaltUniqueVariableName"])
    blob = cfg["staticryptEncryptedMsgUniqueVariableName"]
    mac, enc = blob[:64], blob[64:]
    if not hmac.compare_digest(hmac.new(key, enc.encode(), hashlib.sha256).hexdigest(), mac):
        sys.exit("error: wrong password (HMAC mismatch)")
    iv, ct = bytes.fromhex(enc[:32]), bytes.fromhex(enc[32:])
    plaintext = aes_decrypt(key, iv, ct).decode("utf-8")
    open(CARDS, "w", encoding="utf-8").write(plaintext)
    print(f"decrypted -> {CARDS}  ({len(plaintext)} chars)")


def encrypt():
    if not os.path.exists(CARDS):
        sys.exit(f"error: {CARDS} not found — run 'decrypt' first, then edit it")
    html, cfg = read_config()
    key = derive_key(get_password(), cfg["staticryptSaltUniqueVariableName"])
    plaintext = open(CARDS, encoding="utf-8").read().encode("utf-8")
    iv = os.urandom(16)
    ct = aes_encrypt(key, iv, plaintext)
    enc = iv.hex() + ct.hex()
    mac = hmac.new(key, enc.encode(), hashlib.sha256).hexdigest()
    new_blob = mac + enc
    new_html, n = BLOB_RE.subn(lambda m: m.group(1) + new_blob + m.group(2), html)
    if n != 1:
        sys.exit(f"error: expected to replace exactly 1 blob, replaced {n}")
    # sanity: decrypt what we just wrote before touching churning.html
    check_mac, check_enc = new_blob[:64], new_blob[64:]
    rt = aes_decrypt(key, bytes.fromhex(check_enc[:32]), bytes.fromhex(check_enc[32:]))
    if rt != plaintext:
        sys.exit("error: round-trip verification failed — churning.html left unchanged")
    open(CHURNING, "w", encoding="utf-8").write(new_html)
    print(f"encrypted -> {CHURNING}  (blob {len(new_blob)} hex chars)")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "decrypt":
        decrypt()
    elif cmd == "encrypt":
        encrypt()
    else:
        sys.exit("usage: python3 build.py {decrypt|encrypt} [--password PW]")


if __name__ == "__main__":
    main()
