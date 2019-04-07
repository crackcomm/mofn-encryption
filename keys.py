import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


ephemeral_key = X25519PrivateKey.from_private_bytes(
    base64.b64decode('mA2VZGJi53Ou5I8qzuydeEspg88f+BNpmAYNCggJNn4='))

secret_alice = X25519PrivateKey.from_private_bytes(
    base64.b64decode('+JWfxVeY3010+/QuLI+k6/arzoJAUSa9RBmMMmNyPFg='))
secret_bob = X25519PrivateKey.from_private_bytes(
    base64.b64decode('WODsbbfdimTNLysWiql7ZrQXgEXD7bYnqxnMzYNUrH8='))
secret_joe = X25519PrivateKey.from_private_bytes(
    base64.b64decode('oFhusg9jW7GFbXq/lC2yVkViTySlt795LDRQ9O+WXUA='))
