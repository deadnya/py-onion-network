import secrets
import hashlib
import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Elliptic Curve Parameters (secp256r1)
P = 2**256 - 2**224 + 2**192 + 2**96 - 1
A = -3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63b3f7ef3fe2c6082
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __eq__(self, other):
        if other is None:
            return False
        return self.x == other.x and self.y == other.y

    def __ne__(self, other):
        return not self.__eq__(other)


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    d, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return d, x, y

def modular_inverse(a, p):
    g, x, y = extended_gcd(a, p)
    if g != 1:
        return None
    else:
        return x % p

def point_add(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1

    if P1.__eq__(P2) and P1.y == (P - P2.y) % P:
        return None

    if P1.__eq__(P2):
        return point_double(P1)

    inv = modular_inverse((P2.x - P1.x) % P, P)
    if inv is None:
        return None

    s = ((P2.y - P1.y) * inv) % P
    x = (s**2 - P1.x - P2.x) % P
    y = (s * (P1.x - x) - P1.y) % P
    return Point(x, y)

def point_double(P1):
    if P1 is None:
        return None

    if P1.y == 0:
      return None


    inv = modular_inverse((2 * P1.y) % P, P)
    if inv is None:
        return None

    s = (3 * P1.x**2 + A) * inv % P
    x = (s**2 - 2 * P1.x) % P
    y = (s * (P1.x - x) - P1.y) % P
    return Point(x, y)

def scalar_multiply(P, n):
    result = None
    while n > 0:
        if n % 2 == 1:
            result = point_add(result, P)
        P = point_double(P)
        n //= 2
    return result

def generate_key_pair():
    private_key = secrets.randbelow(P)
    public_key = scalar_multiply(Point(Gx, Gy), private_key)
    if public_key is None:
        return None, None
    return private_key, public_key

def derive_session_key(private_key, public_key):
    shared_point = scalar_multiply(public_key, private_key)
    if shared_point is None:
        return None
    x_bytes = shared_point.x.to_bytes(32, 'big')
    session_key = hashlib.sha256(x_bytes).digest()
    return session_key

def encrypt(message, key):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = pad(message, AES.block_size)
    ciphertext = cipher.encrypt(message)
    return base64.b64encode(iv + ciphertext)

def decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:AES.block_size]
    ciphertext_bytes = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = cipher.decrypt(ciphertext_bytes)
    message = unpad(message, AES.block_size)
    return message.decode('utf-8')

def sign(message, private_key):
    z = int(hashlib.sha256(message.encode('utf-8')).hexdigest(), 16)
    r = 0
    s = 0
    while r == 0 or s == 0:
        k = secrets.randbelow(P)
        kG = scalar_multiply(Point(Gx, Gy), k)
        if kG is None:
            continue

        r = kG.x % P
        s = (modular_inverse(k, P) * (z + private_key * r)) % P
        if modular_inverse(k, P) is None:
            continue

    return r, s

def verify(message, signature, public_key):
    r, s = signature
    if not (1 <= r < P and 1 <= s < P):
        return False
    z = int(hashlib.sha256(message.encode('utf-8')).hexdigest(), 16)
    w = modular_inverse(s, P)
    if w is None:
        return False

    u1 = (z * w) % P
    u2 = (r * w) % P
    point1 = scalar_multiply(Point(Gx, Gy), u1)
    point2 = scalar_multiply(public_key, u2)
    x = point_add(point1, point2)
    if x is None or x.x is None or x.y is None:
        return False
    return x.x == r
