# Course: Theory of Cryptography - ET3310
# Lecturers: Do Trong Tuan, Ma Viet Duc
# School: Hanoi University of Science and Technology - HUST
# Group: 4
# Students: Nguyen Ho Trieu Duong - C41 , Nguyen Tien Dat - C42, Vu Tien Dat - C43
# Created: Tue 16 Dec 2025 08:25:39 Hanoi, Vietnam


from tinyec import registry
import secrets

def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

curve = registry.get_curve('brainpoolP256r1')

alicePrivKey = secrets.randbelow(curve.field.n)
alicePubKey = alicePrivKey * curve.g
print("Alice public key:", compress(alicePubKey))

bobPrivKey = secrets.randbelow(curve.field.n)
bobPubKey = bobPrivKey * curve.g
print("Bob public key:", compress(bobPubKey))

print("Now exchange the public keys (e.g. through Internet)")

aliceSharedKey = alicePrivKey * bobPubKey
print("Alice shared key:", compress(aliceSharedKey))

bobSharedKey = bobPrivKey * alicePubKey
print("Bob shared key:", compress(bobSharedKey))

print("Equal shared keys:", aliceSharedKey == bobSharedKey)