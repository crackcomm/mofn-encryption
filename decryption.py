import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from util import print_key, public_bytes, exchange_key
from keys import secret_alice, secret_bob, secret_joe, ephemeral_key

# From encrypted file import shared public keys.
from encryption import shared_alice, shared_bob, shared_joe

# Alice is initiator of the decryption.
# Alice computes shared keys for Bob and Joe.
# Notice we only know Alice secret at this point.
shared_alice_joe = shared_alice.exchange(shared_joe.public_key())
shared_alice_bob = shared_alice.exchange(shared_bob.public_key())

# Last key required is key we can compute using only Joe or Bob secret.
# We have to ask Joe to compute a shared key because Bob is on vacation.
shared_bob_joe = shared_joe.exchange(shared_bob.public_key())

# This is the point when we can start constructing encryption secret.
ephemeral_alice_joe = exchange_key(
    shared_alice_joe, ephemeral_key.public_key())
ephemeral_alice_bob = exchange_key(
    shared_alice_bob, ephemeral_key.public_key())
ephemeral_bob_joe = exchange_key(shared_bob_joe, ephemeral_key.public_key())


def main():
    # Derive a secret key from 3 secrets generated from at least 2 keys.
    backend = default_backend()
    hkdf = HKDF(
        algorithm=hashes.BLAKE2s(32),
        length=32,
        salt=public_bytes(ephemeral_key),
        info=b'MofN-Encryption-demo',
        backend=backend
    )
    key = hkdf.derive(ephemeral_alice_joe + b'\x01' +
                      ephemeral_alice_bob + b'\x02' + ephemeral_bob_joe)

    print(base64.b64encode(key))


if __name__ == "__main__":
    main()
