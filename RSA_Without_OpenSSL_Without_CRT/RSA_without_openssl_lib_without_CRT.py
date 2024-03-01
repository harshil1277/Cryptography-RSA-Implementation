import random
import gmpy2


def extended_gcd(e, phi):
    # Modulo inverse for calculating d
    if e == 0:
        return (phi, 0, 1)
    else:
        g, a, b = extended_gcd(phi % e, e)
        return (g, b - (phi // e) * a, a)


def encryption(e, n):
    # Reading plaintext
    try:
        with open("RSA_Without_OpenSSL_Without_CRT/Plaintext.txt", "r") as file:
            m = file.read().strip()
    except FileNotFoundError:
        print("Plaintext file not found.")
        return

    # Encryption
    try:
        m_int = int.from_bytes(m.encode(), byteorder='big')
        c = pow(m_int, e, n)
    except ValueError:
        print("Error converting plaintext to integer for encryption.")
        return

    # Writing ciphertext
    try:
        with open("RSA_Without_OpenSSL_Without_CRT/Ciphertext.txt", "w") as file:
            file.write(str(c))
    except IOError:
        print("Error writing ciphertext to file.")
        return

    print("Encryption successful.")


def decryption(d, n):
    # Reading ciphertext
    c = ""
    try:
        with open("RSA_Without_OpenSSL_Without_CRT/Ciphertext.txt", "r") as file:
            c = file.read().strip()
    except FileNotFoundError:
        print("Ciphertext file not found.")
        return

    # Decrypt
    try:
        c = int(c)    
        M = pow(c, d, n)
        M_int = int(M)
        M_str = M_int.to_bytes((M_int.bit_length() + 7) // 8, byteorder='big').decode()
    except ValueError:
        print("Invalid ciphertext format or decryption error.")
        return
    except UnicodeDecodeError:
        print("Error decoding decrypted bytes to string.")
        return

    # Writing decrypted text
    try:
        with open("RSA_Without_OpenSSL_Without_CRT/Decrypted.txt", "w") as file:
            file.write(M_str)
    except IOError:
        print("Error writing decrypted text to file.")
        return

    print("Decryption successful.")


if __name__ == "__main__":

    p = 0
    q = 0

    # generate p
    while True:
        p = random.getrandbits(512)
        p |= 1 << 511
        p |= 1
        p = gmpy2.mpz(p)

        if gmpy2.is_prime(p):
            break
    
    print("Generated first prime number 'p'.")
            

    # generate q
    while True:
        q = random.getrandbits(512)
        q |= 1 << 511
        q |= 1

        q = gmpy2.mpz(q)

        if gmpy2.is_prime(q):
            break
    print("Generated second prime number 'q'.")

    n = p * q
    phi = (p - 1) * (q - 1)

    # generate e
    e = 0
    while True:
        e = random.randint(1, phi)
        e = gmpy2.mpz(e)
        if gmpy2.gcd(e, phi) == 1:
            break

    try:
        with open("RSA_Without_OpenSSL_Without_CRT/PublicKey.txt", "w") as file:
            file.write(str(e) + "\n")
            file.write(str(n))
    except IOError:
        print("Error writing public key to file.")
        exit()

    print("Successfully generated public key 'e' and 'n'.")

    # calculate d
    g, a, b = extended_gcd(e, phi)
    d = 0
    if g != 1:
        print("Modular Inverse does not exist")
    else:
        d = a % phi

    try:
        with open("RSA_Without_OpenSSL_Without_CRT/PrivateKey.txt", "w") as file:
            file.write(str(d))
    except IOError:
        print("Error writing private key to file.")
        exit()

    print("Successfully Calculated private key 'd'.")

    encryption(e, n)
    decryption(d, n)

    try:
        with open("RSA_Without_OpenSSL_Without_CRT/Plaintext.txt", "r") as file:
            plaintext = file.read().strip()

        with open("RSA_Without_OpenSSL_Without_CRT/Decrypted.txt", "r") as file:
            Decryptedtext = file.read().strip()

        if plaintext == Decryptedtext:
            print("Plaintext and Decrypted-text match!") 
            print("RSA Successfully Implemented!")
        else:
            print("Plaintext and Decrypted-text don't match!")
    except FileNotFoundError:
        print("Plaintext or Decrypted text file not found.")
