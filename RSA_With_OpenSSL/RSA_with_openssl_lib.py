from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Save file helper
def save_file(filename, content):
    with open(filename, "wb") as f:
        f.write(content)

# Load file helper
def load_file(filename):
    with open(filename, "rb") as f:
        return f.read()

#Encryption
try:
    # Generate private key & write to disk
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    save_file("RSA_With_OpenSSL/PrivateKey.pem", pem_private)

    # Generate public key
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    save_file("RSA_With_OpenSSL/PublicKey.pem", pem_public)

    # Load plaintext from file
    plaintext = load_file("RSA_With_OpenSSL/Plaintext.txt")

    # Encrypt plaintext with the public key
    # Encrypts the plaintext using the public key with OAEP padding using SHA256 hash algorithm.
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save ciphertext to file
    save_file("RSA_With_OpenSSL/Ciphertext.txt", ciphertext)

    print("Encryption successful!")
except Exception as e:
    print(f"Encryption failed: {e}")


#Decryption
try:
    # Load private key from file
    pem_private = load_file("RSA_With_OpenSSL/PrivateKey.pem")
    private_key = serialization.load_pem_private_key(
        pem_private,
        password=None,
        backend=default_backend()
    )

    # Load ciphertext from file
    ciphertext = load_file("RSA_With_OpenSSL/Ciphertext.txt")

    # Decrypt ciphertext with the private key
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save decrypted plaintext to file
    save_file("RSA_With_OpenSSL/Decrypted.txt", plaintext)

    print("Decryption successful!")
except Exception as e:
    print(f"Decryption failed: {e}")

Plaintext = load_file("RSA_With_OpenSSL/Plaintext.txt")    
Decrypted_text = load_file("RSA_With_OpenSSL/Decrypted.txt")

if Plaintext == Decrypted_text :
    print("Plaintext and Decrypted-text match!")
    print("RSA Encryption - Decryption Successfully Done!")
else:
    print("Unsuccessful RSA Encryption-Decryption!")
