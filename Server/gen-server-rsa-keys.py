from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization

# Generate a new private key
private_key = crypto.PKey()
private_key.generate_key(crypto.TYPE_RSA, 2048)

# Write the private key to a PEM file
with open('private_key.pem', 'wb') as private_key_file:
    private_key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key))

# Extract the public key from the private key
public_key = private_key.to_cryptography_key().public_key()

# Write the public key to a PEM file
with open('public_key.pem', 'wb') as public_key_file:
    public_key_file.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))