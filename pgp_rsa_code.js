import math
import random

# =========================================
# SECTION 1: BASIC MATHEMATICS
# =========================================

def EuclidGCD(a, b):
    """
    Compute GCD using Euclidean Algorithm
    """
    while b != 0:
        temp = b
        b = a % b
        a = temp
    return a


def moduloExp(a, m, n):
    """
    Compute a^m mod n using fast exponentiation
    """
    result = 1
    base = a % n
    exponent = m

    while exponent > 0:
        # if exponent is odd
        if exponent % 2 == 1:
            result = (result * base) % n

        # square the base
        base = (base * base) % n

        # divide exponent by 2
        exponent = exponent // 2

    return result


# =========================================
# SECTION 2: PRIME GENERATION
# =========================================

def isPrime(n, k=5):
    """
    Probabilistic primality test (Fermat Test)
    """
    if n < 2:
        return False

    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False

    return True


def generatePrime(bits):
    """
    Generate a random prime number of given bit size
    """
    while True:
        p = random.getrandbits(bits)

        # ensure highest bit = 1 and odd number
        p |= (1 << bits - 1) | 1

        if isPrime(p):
            return p


# =========================================
# SECTION 3: MODULAR INVERSE
# =========================================

def mulInverse(a, m):
    """
    Extended Euclidean Algorithm for modular inverse
    """
    m0 = m
    x0 = 0
    x1 = 1

    if m == 1:
        return 0

    while a > 1:
        q = a // m

        temp = m
        m = a % m
        a = temp

        temp = x0
        x0 = x1 - q * x0
        x1 = temp

    if x1 < 0:
        x1 += m0

    return x1


# =========================================
# SECTION 4: RSA KEY GENERATION
# =========================================

def rsaKeyGen(nOfBits=128):
    """
    Generate RSA public and private keys
    """

    # Step 1: generate primes
    p = generatePrime(nOfBits // 2)
    q = generatePrime(nOfBits // 2)

    # Step 2: compute modulus
    n = p * q

    # Step 3: compute phi(n)
    phi_n = (p - 1) * (q - 1)

    # Step 4: choose e
    while True:
        e = random.randrange(2, phi_n)
        if EuclidGCD(e, phi_n) == 1:
            break

    # Step 5: compute d
    d = mulInverse(e, phi_n)

    # return keys
    PR = (d, n)
    PU = (e, n)

    return (PR, PU)


# =========================================
# SECTION 5: BLOCK ENCRYPTION / DECRYPTION
# =========================================

def encryptBlock(M, K):
    e, n = K
    C = moduloExp(M, e, n)
    return C


def decryptBlock(C, K):
    d, n = K
    M = moduloExp(C, d, n)
    return M


def encryptBlocks(Ms, K):
    result = []
    for m in Ms:
        result.append(encryptBlock(m, K))
    return result


def decryptBlocks(Cs, K):
    result = []
    for c in Cs:
        result.append(decryptBlock(c, K))
    return result


# =========================================
# SECTION 6: BIT STRING ENCRYPTION
# =========================================

def encryptBitString(plainBitSeq, K):
    e, n = K

    blockSize = math.floor(math.log2(n))

    # Step 1: split into blocks
    Ms = []
    i = 0
    while i < len(plainBitSeq):
        Ms.append(plainBitSeq[i:i + blockSize])
        i += blockSize

    # Step 2: padding last block
    lastBlock = Ms[-1]
    lastBlock = lastBlock + "1" + "0" * (blockSize - len(lastBlock) - 1)
    Ms[-1] = lastBlock

    # Step 3: convert to integers
    Ms_int = []
    for m in Ms:
        Ms_int.append(int(m, 2))

    # Step 4: encrypt
    Cs = encryptBlocks(Ms_int, K)

    # Step 5: convert back to binary
    Cs_bin = []
    for c in Cs:
        binary = bin(c)[2:]
        padded = "0" * (blockSize + 1 - len(binary)) + binary
        Cs_bin.append(padded)

    # Step 6: combine
    cipherText = ""
    for b in Cs_bin:
        cipherText += b

    return cipherText


# =========================================
# SECTION 7: BIT STRING DECRYPTION
# =========================================

def descryptBitString(cipheredBitSeq, K):
    d, n = K

    blockSize = math.floor(math.log2(n)) + 1

    # Step 1: split blocks
    Cs = []
    i = 0
    while i < len(cipheredBitSeq):
        Cs.append(cipheredBitSeq[i:i + blockSize])
        i += blockSize

    # Step 2: convert to integers
    Cs_int = []
    for c in Cs:
        Cs_int.append(int(c, 2))

    # Step 3: decrypt
    Ms = decryptBlocks(Cs_int, K)

    # Step 4: convert back to binary
    Ms_bin = []
    for m in Ms:
        binary = bin(m)[2:]
        padded = "0" * (blockSize - 1 - len(binary)) + binary
        Ms_bin.append(padded)

    plainBitSeq = "".join(Ms_bin)

    # Step 5: remove padding
    p = len(plainBitSeq) - 1
    while plainBitSeq[p] == "0":
        p -= 1

    return plainBitSeq[:p]


# =========================================
# SECTION 8: TEXT ENCRYPTION
# =========================================

def encryptText(text, K):
    # convert text to binary
    bitString = ""
    for b in text.encode("utf-8"):
        bitString += "0" * (8 - len(bin(b)[2:])) + bin(b)[2:]

    return encryptBitString(bitString, K)


def descryptText(ciphertext, K):
    plainBits = descryptBitString(ciphertext, K)

    plaintext = ""
    i = 0
    while i < len(plainBits):
        chunk = plainBits[i:i + 8]
        plaintext += chr(int(chunk, 2))
        i += 8

    return plaintext


# =========================================
# SECTION 9: TEST PROGRAM
# =========================================

if __name__ == "__main__":

    print("=== RSA TEST PROGRAM ===")

    # generate keys
    PR, PU = rsaKeyGen(128)

    print("Public Key :", PU)
    print("Private Key:", PR)

    # message
    message = "Hello RSA Encryption"

    print("\nOriginal Message:", message)

    # encrypt
    cipher = encryptText(message, PU)
    print("\nEncrypted (first 100 bits):")
    print(cipher[:100] + "...")

    # decrypt
    decrypted = descryptText(cipher, PR)
    print("\nDecrypted Message:", decrypted)

if decrypted == message:
    print("Decryption Successful")
else:
    print("Error in Decryption")
    
print("\n=== END TEST ===")
