

# ----------------------------
# Task 1: Manual RSA helpers
# ----------------------------

def gcd(a, b):
    
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """Extended Euclidean algorithm.
    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b).
    """
    if b == 0:
        return (a, 1, 0)
    else:
        g, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return (g, x, y)

def modinv(a, m):
    """Return modular inverse of a modulo m (a^-1 mod m)."""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"modular inverse does not exist for a={a}, m={m} (gcd={g})")
    return x % m

def msg_to_int(msg: str) -> int:
    """Convert short string message to integer (big-endian)."""
    if msg == "":
        return 0
    return int.from_bytes(msg.encode('utf-8'), 'big')

def int_to_msg(i: int) -> str:
    """Convert integer back to utf-8 message."""
    if i == 0:
        return ""
    length = (i.bit_length() + 7) // 8
    try:
        return i.to_bytes(length, 'big').decode('utf-8')
    except Exception:
        # Fallback: decode with ignore to avoid errors for malformed bytes
        return i.to_bytes(length, 'big').decode('utf-8', errors='ignore')

# ----------------------------
# Task 1: Simple RSA (manual)
# ----------------------------

def generate_small_rsa_keys(p=61, q=53, e=17):
    """Generate small RSA keys (educational only).
       Returns (n, e, d)
    """
    if p == q:
        raise ValueError("p and q should be distinct primes for RSA.")
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        # find a small odd e that is coprime with phi
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    d = modinv(e, phi)
    return n, e, d

def rsa_encrypt_integer(m_int: int, e: int, n: int) -> int:
    """Encrypt integer under RSA (c = m^e mod n)."""
    return pow(m_int, e, n)

def rsa_decrypt_integer(c_int: int, d: int, n: int) -> int:
    """Decrypt integer under RSA (m = c^d mod n)."""
    return pow(c_int, d, n)

def task1_demo():
    print("\n===== TASK 1: Manual RSA (Educational) =====")
    p = 61
    q = 53
    n, e, d = generate_small_rsa_keys(p, q, e=17)
    print(f"Chosen primes: p={p}, q={q}")
    print(f"Public key (n, e): ({n}, {e})")
    print(f"Private exponent d: {d}")

    name = "Tayyaba"
    print("Original message:", name)
    m_int = msg_to_int(name)
    if m_int >= n:
        print("Warning: message integer is >= n. Choose larger primes or shorter message.")
    c_int = rsa_encrypt_integer(m_int, e, n)
    print("Ciphertext (integer):", c_int)
    m2_int = rsa_decrypt_integer(c_int, d, n)
    recovered = int_to_msg(m2_int)
    print("Decrypted message:", recovered)
    print("Note: This simple RSA uses NO padding and is NOT secure for real use.\n")

# ----------------------------
# Tasks 2 & 3: library usage
# ----------------------------

# We'll attempt to import PyCryptodome modules. If they fail, we set a flag.
_HAS_CRYPTO = False
try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.Signature import pkcs1_15
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False

def task2_demo():
    """RSA encryption/decryption using PyCryptodome with OAEP."""
    print("\n===== TASK 2: RSA with PyCryptodome (2048-bit) =====")
    if not _HAS_CRYPTO:
        print("PyCryptodome not available. Install it with: pip install pycryptodome")
        return

    # Generate 2048-bit RSA key pair
    key = RSA.generate(2048)
    pub_key = key.publickey()

    message = "Hello RSA Secure World!"
    print("Original message:", message)

    # Encrypt with OAEP using the public key
    cipher = PKCS1_OAEP.new(pub_key)
    ciphertext = cipher.encrypt(message.encode('utf-8'))
    print("Ciphertext (hex):", ciphertext.hex())

    # Decrypt with private key
    decipher = PKCS1_OAEP.new(key)
    plaintext = decipher.decrypt(ciphertext)
    print("Decrypted message:", plaintext.decode('utf-8'))

def task3_demo():
    """Digital signature demonstration (SHA-256 + RSA) using PyCryptodome."""
    print("\n===== TASK 3: Digital Signature (SHA-256 + RSA) =====")
    if not _HAS_CRYPTO:
        print("PyCryptodome not available. Install it with: pip install pycryptodome")
        return

    # Generate key pair
    key = RSA.generate(2048)
    pub_key = key.publickey()

    message = "Security is important"
    print("Message to sign:", message)

    # Hash the message
    h = SHA256.new(message.encode('utf-8'))

    # Sign the hash using PKCS#1 v1.5 (ok for learning; PSS preferred in production)
    signature = pkcs1_15.new(key).sign(h)
    print("Signature (hex):", signature.hex())

    # Verify (should succeed)
    try:
        pkcs1_15.new(pub_key).verify(h, signature)
        print("Verification (original message): SUCCESS")
    except (ValueError, TypeError):
        print("Verification (original message): FAILED")

    # Tamper message and verify (should fail)
    tampered = message + "!"
    h2 = SHA256.new(tampered.encode('utf-8'))
    try:
        pkcs1_15.new(pub_key).verify(h2, signature)
        print("Verification (tampered message): UNEXPECTEDLY SUCCEEDED")
    except (ValueError, TypeError):
        print("Verification (tampered message): FAILED (as expected)")

# ----------------------------
# Entry point

def main():
    task1_demo()
    task2_demo()
    task3_demo()

if __name__ == "__main__":
    main()
