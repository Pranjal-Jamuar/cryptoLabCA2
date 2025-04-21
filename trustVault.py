# ------------------------- COMMON IMPORTS AND SETUP -------------------------
import os
import secrets
import hashlib
import base64
from string import ascii_letters, digits
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

USER_DIR = 'users'
ENCRYPTED_DIR = 'encrypted'
os.makedirs(USER_DIR, exist_ok=True)
os.makedirs(ENCRYPTED_DIR, exist_ok=True)

# ------------------------- BEFORE MIDTERM: RSA KEY GENERATION -------------------------
def save_key_to_txt(filename, key_bytes):
    with open(filename, 'w') as f:
        hex_key = key_bytes.hex()
        f.write(hex_key)

def generate_rsa_keys(username):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    save_key_to_txt(f'{USER_DIR}/{username}_private.txt', private_bytes)
    save_key_to_txt(f'{USER_DIR}/{username}_public.txt', public_bytes)

    return private_key, public_key

# ------------------------- BEFORE MIDTERM: DATA ENCRYPTION -------------------------
def encrypt_data(data, aes_key):
    iv = secrets.token_bytes(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    encoded = base64.b32encode(iv + ciphertext).decode()  # Base32 gives alphanumeric only
    return ''.join(c for c in encoded if c in ascii_letters + digits)

def decrypt_data(encoded, aes_key):
    raw = base64.b32decode(encoded.upper() + '=' * ((8 - len(encoded) % 8) % 8))
    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

def encrypt_aes_key(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_aes_key(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# ------------------------- AFTER MIDTERM: DIGITAL SIGNATURE -------------------------
def sign_data(data_bytes, private_key):
    signature = private_key.sign(
        data_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    hash_value = hashlib.sha256(signature).hexdigest()
    print(f"\n🔏 Digital Signature Hash (SHA-256): {hash_value}")
    return signature

def verify_signature(data_bytes, signature, public_key):
    try:
        public_key.verify(
            signature,
            data_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# ------------------------- MAIN FLOW -------------------------
def main():
    sender = input("Enter sender name: ").lower()
    recipient = input("Enter recipient name: ").lower()
    message = input("Enter your secret message: ")

    # -------- BEFORE MIDTERM WORK --------
    print("\n🚨🚨🚨 Before Mid Term...")
    print("\n📥 Generating RSA keys...")
    sender_priv, sender_pub = generate_rsa_keys(sender)
    rec_priv, rec_pub = generate_rsa_keys(recipient)
    print("🔑 RSA keys generated and saved in 'users/' folder.")

    aes_key = secrets.token_bytes(16)

    print("\n🔐 Encrypting the message...")
    encrypted_msg = encrypt_data(message, aes_key)
    print(f"\n🔒 Encrypted Message (Alphanumeric Only):\n{encrypted_msg}")

    print("\n🔑 Encrypting AES key with recipient’s public key...")
    encrypted_aes_key = encrypt_aes_key(aes_key, rec_pub)
    with open(f"{ENCRYPTED_DIR}/aes_key_for_{recipient}.bin", "wb") as f:
        f.write(encrypted_aes_key)

    # -------- AFTER MIDTERM WORK --------
    print("\n🚨🚨🚨 After Mid Term...")
    print("🧾 Signing encrypted message with sender’s private key...")
    signature = sign_data(encrypted_msg.encode(), sender_priv)

    print("\n📬 Verifying signature on recipient side...")
    if verify_signature(encrypted_msg.encode(), signature, sender_pub):
        print("✅ Signature verified. Data is authentic.")
        with open(f"{ENCRYPTED_DIR}/aes_key_for_{recipient}.bin", "rb") as f:
            encrypted_aes_key = f.read()
        decrypted_aes = decrypt_aes_key(encrypted_aes_key, rec_priv)
        decrypted_msg = decrypt_data(encrypted_msg, decrypted_aes)
        print(f"\n📨 Decrypted Message:\n{decrypted_msg}")
    else:
        print("❌ Signature verification failed.")

if __name__ == "__main__":
    main()