import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def private_bytes(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )


def public_bytes(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)


def b64_encode_private(private_key):
    return base64.b64encode(private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ))


def exchange_key(private_key, public_key):
    return X25519PrivateKey.from_private_bytes(private_key).exchange(public_key)


def print_key(private_key):
    print('private', base64.b64encode(private_bytes(private_key)))
    print('public', base64.b64encode(public_bytes(private_key)))
