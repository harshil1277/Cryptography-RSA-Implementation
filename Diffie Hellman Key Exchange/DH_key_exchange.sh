#!/bin/bash

# Get the directory of the Bash script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Generate Diffie-Hellman parameters
openssl dhparam -out "$DIR/dhparams.pem" 2048

# Generate Alice's private key and public key
openssl genpkey -paramfile "$DIR/dhparams.pem" -out "$DIR/alice_private.pem"
openssl pkey -in "$DIR/alice_private.pem" -pubout -out "$DIR/alice_public.pem"

# Generate Bob's private key and public key
openssl genpkey -paramfile "$DIR/dhparams.pem" -out "$DIR/bob_private.pem"
openssl pkey -in "$DIR/bob_private.pem" -pubout -out "$DIR/bob_public.pem"

# Calculate shared secret key for Alice
openssl pkeyutl -derive -inkey "$DIR/alice_private.pem" -peerkey "$DIR/bob_public.pem" -out "$DIR/alice_shared_secret.bin"

# Calculate shared secret key for Bob
openssl pkeyutl -derive -inkey "$DIR/bob_private.pem" -peerkey "$DIR/alice_public.pem" -out "$DIR/bob_shared_secret.bin"

# Convert shared secret keys to hexadecimal format
alice_shared_secret_hex=$(xxd -p "$DIR/alice_shared_secret.bin")
bob_shared_secret_hex=$(xxd -p "$DIR/bob_shared_secret.bin")

# Display the shared secret keys
echo "Shared Secret Key for Alice: $alice_shared_secret_hex"
echo "Shared Secret Key for Bob: $bob_shared_secret_hex"

