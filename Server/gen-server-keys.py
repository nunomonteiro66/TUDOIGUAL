from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Choose an elliptic curve
curve = ec.SECP256K1()

# Generate a private key
private_key = ec.generate_private_key(curve, default_backend())

# Extract the public key from the private key
public_key = private_key.public_key()

# Serialize the private key
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize the public key
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('private_key.pem', 'wb') as private_key_file:
    private_key_file.write(private_key_pem)

with open('public_key.pem', 'wb') as public_key_file:
    public_key_file.write(public_key_pem)