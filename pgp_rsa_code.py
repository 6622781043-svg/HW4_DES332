import myRSA
import hashlib
import json
import os

# =========================================
# SECTION 1: PATH SETUP (FIX COLAB)
# =========================================
print("\n[SETUP] Initializing environment...")

BASE_DIR = os.getcwd()
print(f"[SETUP] Working directory: {BASE_DIR}")

def build_path(filename):
    path = os.path.join(BASE_DIR, filename)
    print(f"[SETUP] Building path for {filename}: {path}")
    return path


# =========================================
# SECTION 2: LOAD KEYS
# =========================================
print("\n[KEY LOADING] Loading RSA keys from files...")

def load_key(file_name):
    path = build_path(file_name)
    with open(path, "r") as f:
        lines = f.read().strip().splitlines()
    key = (int(lines[0]), int(lines[1]))
    print(f"[KEY LOADING] Loaded {file_name}: {key}")
    return key


# =========================================
# SECTION 3: HASH FUNCTION
# =========================================
print("\n[HASH] Preparing SHA-256 hashing function...")

def compute_hash(message):
    print(f"[HASH] Computing hash for message: {message}")
    digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
    print(f"[HASH] SHA-256 (hex): {digest}")
    value = int(digest, 16)
    print(f"[HASH] Converted to integer: {value}")
    return value


# =========================================
# SECTION 4: SIGNATURE GENERATION
# =========================================
print("\n[SIGNATURE] Preparing signing function...")

def create_signature(message, private_key):
    print("\n[SIGNATURE] Creating digital signature...")
    d, n = private_key
    h = compute_hash(message)
    signature = myRSA.moduloExp(h % n, d, n)
    print(f"[SIGNATURE] Signature = (hash^d mod n): {signature}")
    return signature


# =========================================
# SECTION 5: SIGNATURE VERIFICATION
# =========================================
print("\n[VERIFY] Preparing verification function...")

def verify_signature(message, signature, public_key):
    print("\n[VERIFY] Verifying signature...")
    e, n = public_key
    h = compute_hash(message)
    check = myRSA.moduloExp(signature, e, n)
    print(f"[VERIFY] Decrypted signature: {check}")
    print(f"[VERIFY] Original hash mod n: {h % n}")
    return check == (h % n)


# =========================================
# SECTION 6: PGP ENCRYPT (SEND)
# =========================================
print("\n[PGP SEND] Preparing encryption process...")

def pgp_send(message, sender_private, receiver_public):
    print("\n================ PGP SEND ================")
    print(f"[SEND] Original Message: {message}")

    signature = create_signature(message, sender_private)

    print("\n[SEND] Encrypting message using receiver's public key...")
    ciphertext = myRSA.encryptText(message, receiver_public)
    print(f"[SEND] Ciphertext: {ciphertext[:80]}...")

    envelope = {
        "ciphertext": ciphertext,
        "signature": signature
    }

    print("[SEND] Envelope created successfully.")
    return envelope


# =========================================
# SECTION 7: PGP DECRYPT (RECEIVE)
# =========================================
print("\n[PGP RECEIVE] Preparing decryption process...")

def pgp_receive(envelope, receiver_private, sender_public):
    print("\n================ PGP RECEIVE ================")

    ciphertext = envelope["ciphertext"]
    signature = envelope["signature"]

    print("[RECEIVE] Decrypting message...")
    plaintext = myRSA.descryptText(ciphertext, receiver_private)
    print(f"[RECEIVE] Decrypted Message: {plaintext}")

    valid = verify_signature(plaintext, signature, sender_public)

    if valid:
        print("[RECEIVE] Signature VALID ✓")
    else:
        print("[RECEIVE] Signature INVALID ✗")
        raise ValueError("Message integrity compromised!")

    return plaintext


# =========================================
# SECTION 8: SAVE / LOAD MESSAGE
# =========================================
print("\n[FILE] Preparing file operations...")

def save_message(envelope, filename):
    path = build_path(filename)
    with open(path, "w") as f:
        json.dump({
            "ciphertext": envelope["ciphertext"],
            "signature": str(envelope["signature"])
        }, f, indent=4)
    print(f"[FILE] Message saved to {path}")

def load_message(filename):
    path = build_path(filename)
    with open(path, "r") as f:
        data = json.load(f)
    print(f"[FILE] Message loaded from {path}")
    return {
        "ciphertext": data["ciphertext"],
        "signature": int(data["signature"])
    }


# =========================================
# SECTION 9: MAIN DEMO
# =========================================
print("\n[DEMO] Starting PGP Simulation...\n")

def main():
    PU_A = load_key("PU_A.txt")
    PR_A = load_key("PR_A.txt")
    PU_B = load_key("PU_B.txt")
    PR_B = load_key("PR_B.txt")

    print("\n========== ALICE → BOB ==========")
    message = "Hello Bob! This is Alice. Meet me at the library at 5pm."

    env1 = pgp_send(message, PR_A, PU_B)
    save_message(env1, "alice_to_bob.json")

    received1 = load_message("alice_to_bob.json")
    result1 = pgp_receive(received1, PR_B, PU_A)

    print(f"\n[RESULT] Bob reads: {result1}")

    print("\n========== BOB → ALICE ==========")
    reply = "Hi Alice! Confirmed. See you at 5pm."

    env2 = pgp_send(reply, PR_B, PU_A)
    save_message(env2, "bob_to_alice.json")

    received2 = load_message("bob_to_alice.json")
    result2 = pgp_receive(received2, PR_A, PU_B)

    print(f"\n[RESULT] Alice reads: {result2}")

    print("\n========== ATTACK TEST ==========")
    tampered = dict(received1)
    tampered["signature"] = 99999999

    print("[ATTACK] Signature has been modified!")

    try:
        pgp_receive(tampered, PR_B, PU_A)
    except Exception as e:
        print(f"[ATTACK RESULT] {e}")

    print("\n========== DEMO COMPLETE ==========")


# =========================================
# RUN PROGRAM
# =========================================
main()
