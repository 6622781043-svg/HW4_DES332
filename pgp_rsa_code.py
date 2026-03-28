import math
import random
import hashlib

# =========================================
# BASIC MATH
# =========================================

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def modexp(a, e, n):
    result = 1
    a %= n
    while e > 0:
        if e % 2:
            result = (result * a) % n
        a = (a * a) % n
        e //= 2
    return result


# =========================================
# PRIME GENERATION
# =========================================

def isPrime(n, k=5):
    if n < 2:
        return False
    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True


def genPrime(bits):
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1
        if isPrime(p):
            return p


# =========================================
# MOD INVERSE
# =========================================

def modInverse(e, phi):
    m0, x0, x1 = phi, 0, 1
    while e > 1:
        q = e // phi
        e, phi = phi, e % phi
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


# =========================================
# KEY GENERATION
# =========================================

def keyGen(bits=128):
    p = genPrime(bits // 2)
    q = genPrime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        return keyGen(bits)

    d = modInverse(e, phi)

    return (d, n), (e, n)


# =========================================
# TEXT ENCODING
# =========================================

def textToIntBlocks(text):
    return [ord(c) for c in text]


def intBlocksToText(blocks):
    return "".join(chr(b) for b in blocks)


# =========================================
# ENCRYPT / DECRYPT
# =========================================

def encrypt(PU, text):
    e, n = PU
    blocks = textToIntBlocks(text)
    return [modexp(b, e, n) for b in blocks]


def decrypt(PR, cipher):
    d, n = PR
    return intBlocksToText([modexp(c, d, n) for c in cipher])


# =========================================
# SHA-256 SIGNATURE
# =========================================

def sha256Hash(msg):
    return int(hashlib.sha256(msg.encode()).hexdigest(), 16)


def sign(msg, PR):
    d, n = PR
    return modexp(sha256Hash(msg), d, n)


def verify(msg, sig, PU):
    e, n = PU
    return modexp(sig, e, n) == sha256Hash(msg)


# =========================================
# FILE ENCRYPTION
# =========================================

def encryptFile(inputFile, outputFile, PU):
    with open(inputFile, "r", encoding="utf-8") as f:
        data = f.read()

    cipher = encrypt(PU, data)

    with open(outputFile, "w") as f:
        f.write(" ".join(map(str, cipher)))


def decryptFile(inputFile, outputFile, PR):
    with open(inputFile, "r") as f:
        data = list(map(int, f.read().split()))

    text = decrypt(PR, data)

    with open(outputFile, "w", encoding="utf-8") as f:
        f.write(text)


# =========================================
# DEMO
# =========================================

if __name__ == "__main__":
    print("=== RSA ADVANCED SYSTEM ===")

    PR, PU = keyGen(128)

    print("Public Key :", PU)
    print("Private Key:", PR)

    message = "Hello Advanced RSA"
    print("\nOriginal:", message)

    # Encrypt / Decrypt
    cipher = encrypt(PU, message)
    plain = decrypt(PR, cipher)

    print("Encrypted:", cipher[:5], "...")
    print("Decrypted:", plain)

    # Signature
    sig = sign(message, PR)
    print("\nSignature:", sig)

    print("Verify:", "VALID" if verify(message, sig, PU) else "INVALID")

    # Tamper Test
    fake = "Hello Hacker"
    print("Tampered:", "VALID" if verify(fake, sig, PU) else "INVALID")

    # File Test
    print("\n[File Test]")
    with open("test.txt", "w", encoding="utf-8") as f:
        f.write(message)

    encryptFile("test.txt", "enc.txt", PU)
    decryptFile("enc.txt", "dec.txt", PR)

    print("File encryption complete")

print("\n=== END ===")
