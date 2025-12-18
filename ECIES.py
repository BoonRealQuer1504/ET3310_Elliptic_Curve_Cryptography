# Course: Theory of Cryptography - ET3310 
# Lecturers: Do Trong Tuan, Ma Viet Duc 
# School: Hanoi University of Science and Technology - HUST 
# Group: 4 
# Students: Nguyen Ho Trieu Duong - C41 , Nguyen Tien Dat - C42, Vu Tien Dat - C43 
# Created: Tue 16 Dec 2025 08:25:39 Hanoi, Vietnam 
## ECIES implementation following the SECG-SEC-1 standard 
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import sys 
CURVE = ec.SECP256K1()

def encrypt_ecies(public_key_hex: str, plaintext: str) -> str:
    # Load public key của người nhận
    pub_bytes = bytes.fromhex('04'+public_key_hex)
    recipient_pub = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, pub_bytes)

    # Tạo ephemeral key pair
    ephemeral_priv = ec.generate_private_key(CURVE)
    ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )  # 65 bytes, bắt đầu bằng 0x04
    
    # ECDH để lấy shared secret Z
    shared = ephemeral_priv.exchange(ec.ECDH(), recipient_pub)

    # KDF đơn giản: SHA-256(shared) → 32-byte key cho AES-256-GCM
    derived_key = hashlib.sha256(shared).digest()

    # Nonce ngẫu nhiên 12 byte (khuyến nghị cho GCM)
    nonce = os.urandom(12)

    # Mã hóa AES-256-GCM
    aesgcm = AESGCM(derived_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

    # Ghép: ephemeral_pub (65) + nonce (12) + ciphertext+tag
    encrypted = ephemeral_pub_bytes + nonce + ciphertext_with_tag

    return encrypted.hex()
def decrypt_ecies(private_key_hex: str, encrypted_hex: str) -> str:
    try:
        encrypted = bytes.fromhex(encrypted_hex)

        
        ephemeral_pub_bytes = encrypted[:65] #ephemeral_pub_bytes
        nonce = encrypted[65:77]          # 12 bytes
        ciphertext = encrypted[77:]       # ciphertext + 16-byte GCM tag

        # Private key của người nhận
        private_value = int(private_key_hex, 16)
        recipient_priv = ec.derive_private_key(private_value, CURVE)

        # Load ephemeral public key
        ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            CURVE, ephemeral_pub_bytes
        )

        # ECDH để lấy shared secret key bằng public key tạm thời * private key của người nhận
        shared = recipient_priv.exchange(ec.ECDH(), ephemeral_pub)

        
        derived_key = hashlib.sha256(shared).digest()

        # AES-256
        aesgcm = AESGCM(derived_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext.decode("utf-8")

    except Exception:
        return "Error: cannot decrypt the message"



def main():
    print("Receiver's public key:")
    public_key_hex = sys.stdin.readline().strip()
    print("PLaintext:") 
    plaintext = sys.stdin.readline().strip() 
    encrypted_hex = encrypt_ecies(public_key_hex, plaintext) 
    print("Encrypted Message:")
    print(encrypted_hex)
    print("Receiver's private key:")
    private_key_hex=sys.stdin.readline().strip() #only người nhận biết 
    result = decrypt_ecies(private_key_hex, encrypted_hex)
    print("Plaintext after decrypt:")
    print(result)

if __name__ == "__main__":
    main()
