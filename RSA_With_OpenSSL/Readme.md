# RSA using OpenSSL

## Importing Required Libraries: 
- The script imports necessary modules from the cryptography library for performing RSA encryption and decryption.
- For cryptography 'pycryptodome' and 'cryptography' library is recommended to use than 'pyopenssl' library.

## Save and Load File Helper Functions:
- Two helper functions (save_file and load_file) are defined to save data to files and load data from files, respectively.

## Encryption:
- The script generates an RSA private key of length 2048 bits with a public exponent of 65537. 
- The private key is then serialized in PEM format without encryption and saved to a file named "PrivateKey.pem".
- The corresponding public key is derived from the private key and serialized in PEM format, then saved to a file named "PublicKey.pem".
- Plaintext data is loaded from the file "Plaintext.txt".
- The plaintext is encrypted using the RSA public key with OAEP padding and SHA256 hash algorithm.
- The resulting ciphertext is saved to a file named "Ciphertext.txt".

## Decryption:
- The script loads the private key from the file "PrivateKey.pem".
- It loads the ciphertext from the file "Ciphertext.txt".
- The ciphertext is decrypted using the RSA private key with the same OAEP padding and SHA256 hash algorithm used during encryption.
- The decrypted plaintext is saved to a file named "Decrypted.txt".

## Comparison and Verification:
- The original plaintext is loaded from "Plaintext.txt" and decrypted text from "Decrypted.txt".
- The plaintext and decrypted text are compared. If they match, it prints a success message; otherwise, it prints a failure message.

### Explanation of Encryption Parameters:

- padding.OAEP: Optimal Asymmetric Encryption Padding.
- mgf=padding.MGF1(algorithm=hashes.SHA256()): Mask Generation Function using SHA256.
- algorithm=hashes.SHA256(): Hashing algorithm used (SHA256).
- label=None: Optional label to distinguish different uses of the same key, often set to None.

### Explanation of Decryption Parameters:
- Same as encryption, including OAEP padding, MGF1, SHA256 algorithm, and label.
- The use of OAEP padding with SHA256 ensures that the encryption process is secure and resistant to chosen-plaintext attacks. The decryption process utilizes the private key corresponding to the public key used for encryption, ensuring that only the intended recipient can decrypt the ciphertext.


link for reference: [https://pycryptodome.readthedocs.io/en/latest/src/cipher/oaep.html](https://pycryptodome.readthedocs.io/en/latest/src/cipher/oaep.html)