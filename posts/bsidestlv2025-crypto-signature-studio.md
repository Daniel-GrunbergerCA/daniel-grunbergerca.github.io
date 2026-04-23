# BSidesTLV 2025 — Signature Studio: ECDSA Signature Malleability

The challenge presents a signing oracle over a socket. We can sign any message and then verify a message+signature pair. The catch: the server rejects any signature it has seen before - we must present a *different* valid signature for the same message to get the flag.

```
# Signature Studio
# Welcome to the Signature Studio, where no signature appears twice

from Crypto.Util.number import bytes_to_long
from collections import namedtuple
from hashlib import sha256
import binascii
import random
from secret import FLAG


# Standard elliptic curve operations
Point = namedtuple("Point", "x y")
O = 'Infinity'

def check_point(P):
    if P == O:
        return True
    else:
        return (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0 and 0 <= P.x < p and 0 <= P.y < p


def point_inverse(P):
    if P == O:
        return P
    return Point(P.x, -P.y % p)


def point_addition(P, Q):
    if P == O:
        return Q
    elif Q == O:
        return P
    elif Q == point_inverse(P):
        return O
    else:
        if P == Q:
            lam = (3*P.x**2 + a)*pow(2*P.y, -1, p)
            lam %= p
        else:
            lam = (Q.y - P.y) * pow((Q.x - P.x), -1, p)
            lam %= p
    Rx = (lam**2 - P.x - Q.x) % p
    Ry = (lam*(P.x - Rx) - P.y) % p
    R = Point(Rx, Ry)
    assert check_point(R)
    return R


def point_multiplication(P, n):
    Q = P
    R = O
    while n > 0:
        if n % 2 == 1:
            R = point_addition(R, Q)
        Q = point_addition(Q, Q)
        n = n // 2
    assert check_point(R)
    return R


# Standard ECDSA operations
def number_to_string(num):
    l = p.bit_length() // 8
    fmt_str = "%0" + str(2 * l) + "x"
    string = binascii.unhexlify((fmt_str % num).encode())
    assert len(string) == l, (len(string), l)
    return string.hex()


def string_to_number(string):
    return int(binascii.hexlify(string), 16)


def hash_message(message):
    return bytes_to_long(sha256(message.encode()).digest())


def sign(private_key, G, message, k=None):
    if k is None:
        k = random.randrange(n)
    hash = hash_message(message)
    r = point_multiplication(G, k).x % n
    s = pow(k, -1, n) * (hash + r * private_key) % n
    return number_to_string(r) + number_to_string(s)


def verify(public_key, G, message, signature):
    signature = bytes.fromhex(signature)
    l = p.bit_length() // 8
    if len(signature) != 2*l:
        return False
    r = string_to_number(signature[:l])
    s = string_to_number(signature[l:])
    if r < 1 or r > n - 1 or s < 1 or s > n-1:
        return False
    hash = hash_message(message)
    u1 = (hash * pow(s, -1, n)) % n
    u2 = (r * pow(s, -1, n)) % n
    P = point_addition(
        point_multiplication(G, u1), 
        point_multiplication(public_key, u2)
        )
    return P.x % n == r



# Communication with client
def send(message):
    print(message)

def recv(message=''):
    return input(message + "\n").strip()


# Challenge
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
G = Point(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

private_key = random.randrange(n)
public_key = point_multiplication(G, private_key)

SIGNATURES_CACHE = set()
FLAG_MESSAGE = "can i haz flag?"

def main():
    while True:
        choice = recv(
"""1 - Sign a message
2 - Verify a message
3 - Exit""")
        if choice == "1":
            message = recv("Enter a message to sign:")
            signature = sign(private_key, G, message)
            send("Signature: " + signature)
            SIGNATURES_CACHE.add(signature)
        elif choice == "2":
            message = recv("What is your message?")
            signature = recv("What is your signature?")
            try:
                if not verify(public_key, G, message, signature):
                    send("Signature is invalid!")
                    continue
            except:
                send("I could not verify that...")
                continue
            if signature in SIGNATURES_CACHE:
                send("I already knew that...")
                continue
            if message == FLAG_MESSAGE:
                send("Cool, here's the flag: " + FLAG)
            else:
                send("OK, noted")
        elif choice == "3":
            break
        else:
            send("Huh?")

main()
```

## ECDSA Signature Malleability

An ECDSA signature is a pair $(r, s)$. For any valid signature, the negated form $(r, n - s \mod n)$ is equally valid, because ECDSA verification only checks:

$$r \equiv (k^{-1} \cdot (H(m) + r \cdot d)) \cdot G \pmod{n}$$

Negating $s$ is equivalent to negating the nonce $k$, but since $k$ is chosen uniformly from $[1, n-1]$, $-k \mod n$ is just another element of that range and the verification equation still holds.

## Exploit

1. Sign `"can i haz flag?"` to obtain $(r, s)$.
2. Compute the malleable counterpart: $s' = (n - s) \mod n$.
3. Submit $(r, s')$ as the "different" signature for the same message.

```python
from pwn import *
import binascii

n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

def number_to_string(num):
    l = p.bit_length() // 8
    fmt_str = "%0" + str(2 * l) + "x"
    return binascii.unhexlify((fmt_str % num).encode()).hex()

conn = remote("0.cloud.chals.io", 27412)

# Sign the message
conn.recvuntil(b"3 - Exit\n")
conn.sendline(b"1")
conn.recvuntil(b"Enter a message to sign:\n")
conn.sendline(b"can i haz flag?")
resp = conn.recvline().decode().strip()
sig_hex = resp.split("Signature: ")[1]

# Forge the malleable signature
l = p.bit_length() // 8
r = int(sig_hex[:2*l], 16)
s = int(sig_hex[2*l:], 16)
s_new = (n - s) % n
sig_forged = number_to_string(r) + number_to_string(s_new)

# Verify with the forged signature
conn.recvuntil(b"3 - Exit\n")
conn.sendline(b"2")
conn.recvuntil(b"What is your message?\n")
conn.sendline(b"can i haz flag?")
conn.recvuntil(b"What is your signature?\n")
conn.sendline(sig_forged.encode())

print(conn.recvline().decode().strip())
conn.close()
```

The server accepts the forged signature because it is cryptographically valid, but it hasn't seen this specific $(r, s')$ pair before.
