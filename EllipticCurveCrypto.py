# Course: Theory of Cryptography - ET3310
# Lecturers: Do Trong Tuan, Ma Viet Duc
# School: Hanoi University of Science and Technology - HUST
# Group: 4
# Students: Nguyen Ho Trieu Duong - C41 , Nguyen Tien Dat - C42, Vu Tien Dat - C43
# Created: Tue 16 Dec 2025 08:25:39 Hanoi, Vietnam

def modinv(a, p):
    """
    Tính nghịch đảo modulo: a^-1 mod p
    """
    if a == 0:
        raise ZeroDivisionError("Không có nghịch đảo modulo")

    lm, hm = 1, 0
    low, high = a % p, p

    while low > 1:
        r = high // low
        nm = hm - lm * r
        new = high - low * r
        hm, lm = lm, nm
        high, low = low, new

    return lm % p
class EllipticCurve:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

        # Kiểm tra đường cong không suy biến
        if (4 * a**3 + 27 * b**2) % p == 0:
            raise ValueError("Đường cong suy biến")

class Point:
    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y

    def is_infinity(self):
        return self.x is None and self.y is None

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y
    def __str__(self):
        if self.is_infinity():
            return "O (Point at Infinity)"
        return f"({self.x}, {self.y})" 
    

def point_add(P, Q):
    curve = P.curve

    # Trường hợp O
    if P.is_infinity():
        return Q
    if Q.is_infinity():
        return P

    # P + (-P) = O
    if P.x == Q.x and (P.y + Q.y) % curve.p == 0:
        return Point(curve, None, None)

    if P != Q:
        # lambda = (y2 - y1)/(x2 - x1)
        l = ((Q.y - P.y) * modinv(Q.x - P.x, curve.p)) % curve.p
    else:
        # Nhân đôi
        l = ((3 * P.x**2 + curve.a) * modinv(2 * P.y, curve.p)) % curve.p

    x3 = (l**2 - P.x - Q.x) % curve.p
    y3 = (l * (P.x - x3) - P.y) % curve.p

    return Point(curve, x3, y3)


def scalar_mult(k, P):
    result = Point(P.curve, None, None)  # O
    addend = P

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result



import random

def generate_keypair(curve, G, n):
    private_key = random.randint(1, n - 1)
    public_key = scalar_mult(private_key, G)
    return private_key, public_key

def encrypt(curve, G, public_key, message_point, n):
    k = random.randint(1, n - 1)
    C1 = scalar_mult(k, G)
    C2 = point_add(message_point, scalar_mult(k, public_key))
    return C1, C2




def encrypt(curve, G, public_key, message_point, k):
    
    C1 = scalar_mult(k, G)
    C2 = point_add(message_point, scalar_mult(k, public_key))
    return C1, C2


def decrypt(private_key, C1, C2):
    return point_add(C2, scalar_mult(private_key, Point(C1.curve, C1.x, -C1.y)))


curve = EllipticCurve(-1,188,751)

G = Point(curve,0,376)

Message = Point(curve,562, 201)

PB = Point(curve, 201, 5)

k = 386 

C1, C2 = encrypt(curve,G, PB,Message, k)
print("Message: ",Message)
print("Ciphertext =",C1, C2 )


private = 58 # (private* G = PB)

plain= decrypt(private, C1, C2)

print("After decrypt: ", plain)




