# Reference to https://github.com/AntonKueltz/fastecdsa

from binascii import hexlify
from os import urandom
from typing import Callable, Tuple
import random
from os import urandom
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


def modsqrt(a, p):
    """ Find a quadratic residue (mod p) of 'a'. p
    must be an odd prime.
    Solve the congruence of the form:
    x^2 = a (mod p)
    And returns x. Note that p - x is also a root.
    0 is returned is no square root exists for
    these a and p.
    The Tonelli-Shanks algorithm is used (except
    for some simple cases in which the solution
    is known from an identity). This algorithm
    runs in polynomial time (unless the
    generalized Riemann hypothesis is false).
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        # Interesting bug. s /= 2 and s = int(s) not equals to s //= 2
        # s /= 2
        # s = int(s)
        s //= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m

def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
    Euler's criterion. p is a prime, a is
    relatively prime to p (if p divides
    a, then a|p = 0)
    Returns 1 if a has a square root modulo
    p, -1 otherwise.
    """
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

def modinv(a, m):
    a = a % m
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("modular inverse does not exist")
    else:
        return x % m

def int_length_in_byte(n: int):
    assert n >= 0
    length = 0
    while n:
        n >>= 8
        length += 1
    return length

@dataclass
class Point:
    x: Optional[int]
    y: Optional[int]
    curve: "Curve"

    def is_at_infinity(self) -> bool:
        return self.x is None and self.y is None

    def __post_init__(self):
        if not self.is_at_infinity() and not self.curve.is_on_curve(self):
            raise ValueError("The point is not on the curve.")

    def __str__(self):
        if self.is_at_infinity():
            return f"Point(At infinity, Curve={str(self.curve)})"
        else:
            return f"Point(X={self.x}, Y={self.y}, Curve={str(self.curve)})"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.curve == other.curve and self.x == other.x and self.y == other.y

    def __neg__(self):
        return self.curve.neg_point(self)

    def __add__(self, other):
        return self.curve.add_point(self, other)

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        negative = - other
        return self.__add__(negative)

    def __mul__(self, scalar: int):
        return self.curve.mul_point(scalar, self)

    def __rmul__(self, scalar: int):
        return self.__mul__(scalar)
    
    def to_byte(self):
        if self.y % 2 == 0:
            # If y-coordinate is even, set the sign bit to 0
            public_key_bytes = self.x.to_bytes(32, 'big')
        else:
            # If y-coordinate is odd, set the sign bit to 1
            public_key_bytes = self.x.to_bytes(32, 'big')
        return public_key_bytes
    
    def byte_to_hex(byte_str):
        return "".join(format(x, "02x") for x in byte_str)

@dataclass
class Curve(ABC):
    name: str
    a: int
    b: int
    p: int
    n: int
    G_x: int
    G_y: int

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return (
            self.a == other.a and self.b == other.b and self.p == other.p and
            self.n == other.n and self.G_x == other.G_x and self.G_y == other.G_y
        )

    @property
    def G(self) -> Point:
        return Point(self.G_x, self.G_y, self)

    @property
    def INF(self) -> Point:
        return Point(None, None, self)

    def is_on_curve(self, P: Point) -> bool:
        if P.curve != self:
            return False
        return P.is_at_infinity() or self._is_on_curve(P)

    @abstractmethod
    def _is_on_curve(self, P: Point) -> bool:
        pass

    def add_point(self, P: Point, Q: Point) -> Point:
        if (not self.is_on_curve(P)) or (not self.is_on_curve(Q)):
            raise ValueError("The points are not on the curve.")
        if P.is_at_infinity():
            return Q
        elif Q.is_at_infinity():
            return P

        if P == -Q:
            return self.INF
        if P == Q:
            return self._double_point(P)

        return self._add_point(P, Q)

    @abstractmethod
    def _add_point(self, P: Point, Q: Point) -> Point:
        pass

    @abstractmethod
    def _double_point(self, P: Point) -> Point:
        pass

    def mul_point(self, d: int, P: Point) -> Point:
        """
        https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
        """
        if not self.is_on_curve(P):
            raise ValueError("The point is not on the curve.")
        if P.is_at_infinity():
            return self.INF
        if d == 0:
            return self.INF

        res = self.INF
        is_negative_scalar = d < 0
        d = -d if is_negative_scalar else d
        tmp = P
        while d:
            if d & 0x1 == 1:
                res = self.add_point(res, tmp)
            tmp = self.add_point(tmp, tmp)
            d >>= 1
        if is_negative_scalar:
            return -res
        else:
            return res

    def neg_point(self, P: Point) -> Point:
        if not self.is_on_curve(P):
            raise ValueError("The point is not on the curve.")
        if P.is_at_infinity():
            return self.INF

        return self._neg_point(P)

    @abstractmethod
    def _neg_point(self, P: Point) -> Point:
        pass

    @abstractmethod
    def compute_y(self, x: int) -> int:
        pass

    def encode_point(self, plaintext: bytes) -> Point:
        plaintext = len(plaintext).to_bytes(1, byteorder="big") + plaintext
        while True:
            x = int.from_bytes(plaintext, "big")
            y = self.compute_y(x)
            if y:
                return Point(x, y, self)
            plaintext += urandom(1)

    def decode_point(self, M: Point) -> bytes:
        byte_len = int_length_in_byte(M.x)
        plaintext_len = (M.x >> ((byte_len - 1) * 8)) & 0xff
        plaintext = ((M.x >> ((byte_len - plaintext_len - 1) * 8))
                     & (int.from_bytes(b"\xff" * plaintext_len, "big")))
        return plaintext.to_bytes(plaintext_len, byteorder="big")

class MontgomeryCurve(Curve):
    """
    by^2 = x^3 + ax^2 + x
    https://en.wikipedia.org/wiki/Montgomery_curve
    """

    def _is_on_curve(self, P: Point) -> bool:
        left = self.b * P.y * P.y
        right = (P.x * P.x * P.x) + (self.a * P.x * P.x) + P.x
        return (left - right) % self.p == 0

    def _add_point(self, P: Point, Q: Point) -> Point:
        # s = (yP - yQ) / (xP - xQ)
        # xR = b * s^2 - a - xP - xQ
        # yR = yP + s * (xR - xP)
        delta_x = P.x - Q.x
        delta_y = P.y - Q.y
        s = delta_y * modinv(delta_x, self.p)
        res_x = (self.b * s * s - self.a - P.x - Q.x) % self.p
        res_y = (P.y + s * (res_x - P.x)) % self.p
        return - Point(res_x, res_y, self)

    def _double_point(self, P: Point) -> Point:
        # s = (3 * xP^2 + 2 * a * xP + 1) / (2 * b * yP)
        # xR = b * s^2 - a - 2 * xP
        # yR = yP + s * (xR - xP)
        up = 3 * P.x * P.x + 2 * self.a * P.x + 1
        down = 2 * self.b * P.y
        s = up * modinv(down, self.p)
        res_x = (self.b * s * s - self.a - 2 * P.x) % self.p
        res_y = (P.y + s * (res_x - P.x)) % self.p
        return - Point(res_x, res_y, self)

    def _neg_point(self, P: Point) -> Point:
        return Point(P.x, -P.y % self.p, self)

    def compute_y(self, x: int) -> int:
        right = (x * x * x + self.a * x * x + x) % self.p
        inv_b = modinv(self.b, self.p)
        right = (right * inv_b) % self.p
        y = modsqrt(right, self.p)
        return y

Curve25519 = MontgomeryCurve(
    name="Curve25519",
    a=486662,
    b=1,
    #p=0x7fffffffffffffffffffffffffffffff,
    p=0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed,
    n=0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed,
    G_x=0x9,
    G_y=0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9
)

def gen_keypair(curve: Curve,
                randfunc: Callable = None) -> Tuple[int, Point]:
    randfunc = randfunc or urandom
    private_key = gen_private_key(curve, randfunc)
    public_key = get_public_key(private_key, curve.G, curve)
    return private_key, public_key


def gen_private_key(curve: Curve,
                    randfunc: Callable = None) -> int:
    order_bits = 0
    order = curve.n

    while order > 0:
        order >>= 1
        order_bits += 1

    order_bytes = (order_bits + 7) // 8
    #order_bytes = (order_bits + 7) // 16

    rand = int(hexlify(randfunc(6)), 16)
    #rand = int(hexlify(randfunc(16)), 16)

    while rand >= curve.n:
        rand = int(hexlify(randfunc(order_bytes)), 16)


    return rand

def ec_elgamal_encrypt(public_key: Point, message: bytes, curve: Curve25519) -> (Point, Point):
    k = random.randint(1, curve.n - 1)
    c1 = k * curve.G
    c2 = message * curve.G + k * public_key
    return c1, c2

def ec_elgamal_decrypt(private_key: int, ciphertext: (Point, Point), curve: Curve25519) -> Point:
    c1, c2 = ciphertext
    return c2 - private_key * c1

def get_public_key(private_key: int, point_on_curve: Point, curve: Curve) -> Point:
    return private_key*curve.G


def get_common_key(my_private_key: int, other_public_key: Point):
    return my_private_key * other_public_key