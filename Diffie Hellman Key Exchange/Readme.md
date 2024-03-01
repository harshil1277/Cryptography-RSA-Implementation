# Diffie Hellman Secret Key Exchange (Uisng OpenSSL)

- To run the bash file, make sure you are on Linux environment or Git bash terminal
- Go to the directory where 'DH_key_exchange.sh' is present.
- Open terminal and type './DH_key_exchange.sh'
- All the key files and bin files would be generated in that dictionary itself

## DH Parameter Generation

```bash
# Get the directory of the Bash script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Generate Diffie-Hellman parameters
openssl dhparam -out "$DIR/dhparams.pem" 2048
```
- This section generates Diffie-Hellman parameters, which are necessary for both Alice and Bob to generate their private and public keys.
- The DIR variable is set to the directory where the Bash script is located.
- The openssl dhparam command generates Diffie-Hellman parameters with a key size of 2048 bits and saves them to a file named dhparams.pem in the directory specified by DIR.

## Generate Alice's Private and Public Key
```bash
# Generate Alice's private key and public key
openssl genpkey -paramfile "$DIR/dhparams.pem" -out "$DIR/alice_private.pem"
openssl pkey -in "$DIR/alice_private.pem" -pubout -out "$DIR/alice_public.pem"
```
- This section generates Alice's private key and corresponding public key using the Diffie-Hellman parameters generated in the previous step.
- The openssl genpkey command generates Alice's private key (alice_private.pem) based on the Diffie-Hellman parameters (dhparams.pem).
- The openssl pkey command extracts Alice's public key from her private key and saves it to a file named alice_public.pem.


## Generate Bob's Private and Public Key
```bash
openssl genpkey -paramfile "$DIR/dhparams.pem" -out "$DIR/bob_private.pem"
openssl pkey -in "$DIR/bob_private.pem" -pubout -out "$DIR/bob_public.pem"
```
- Similar to the previous section, this part generates Bob's private key and corresponding public key using the same set of Diffie-Hellman parameters.
- The openssl genpkey command generates Bob's private key (bob_private.pem) based on the Diffie-Hellman parameters (dhparams.pem).
- The openssl pkey command extracts Bob's public key from his private key and saves it to a file named bob_public.pem.

## Sharing Public Key
This section involves the exchange of public keys between Alice and Bob, which is not explicitly implemented in the script but assumed to be performed out-of-band. Alice needs to send her public key to Bob, and Bob needs to send his public key to Alice.

## Calculate shared secret key for Alice
```bash
openssl pkeyutl -derive -inkey "$DIR/alice_private.pem" -peerkey "$DIR/bob_public.pem" -out "$DIR/alice_shared_secret.bin"
``` 
- This section calculates the shared secret key for Alice using her private key and Bob's public key.
- The openssl pkeyutl command performs the key derivation process, deriving the shared secret key from Alice's private key (alice_private.pem) and Bob's public key (bob_public.pem).
- The derived shared secret key is saved to a binary file named alice_shared_secret.bin.

## Calculate shared secret key for Bob
```bash
openssl pkeyutl -derive -inkey "$DIR/bob_private.pem" -peerkey "$DIR/alice_public.pem" -out "$DIR/bob_shared_secret.bin"
``` 
- Similarly, this section calculates the shared secret key for Bob using his private key and Alice's public key.
- The openssl pkeyutl command derives the shared secret key from Bob's private key (bob_private.pem) and Alice's public key (alice_public.pem).
- The derived shared secret key is saved to a binary file named bob_shared_secret.bin.

## Intrepret Shared Secret Key
```bash
 # Convert shared secret keys to hexadecimal format
alice_shared_secret_hex= $(xxd -p "$DIR/alice_shared_secret.bin")
bob_shared_secret_hex= $(xxd -p "$DIR/bob_shared_secret.bin")
``` 

- This section converts the shared secret keys from binary format to hexadecimal format for easier interpretation.
- The xxd -p command converts the contents of the binary files alice_shared_secret.bin and bob_shared_secret.bin to hexadecimal.
- The hexadecimal representations of the shared secret keys are stored in the variables alice_shared_secret_hex and bob_shared_secret_hex.
