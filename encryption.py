import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from util import print_key, public_bytes, exchange_key
from keys import secret_alice, secret_bob, secret_joe, ephemeral_key

# We have only access to 3 public keys and we have to compute secrets for them.
# Use ephemeral key to generate shared keys which public parts are shared.
# Public parts of these keys are shared in the encrypted blob header.
shared_alice = exchange_key(ephemeral_key, secret_alice.public_key())
shared_bob = exchange_key(ephemeral_key, secret_bob.public_key())
shared_joe = exchange_key(ephemeral_key, secret_joe.public_key())

# We are now beholding 3 keys and each separately is known only to us  and owner of the secret counterpart.
# We can now initialize a handshake to generate 3 shared secret keys.
shared_alice_bob = exchange_key(shared_alice, shared_bob.public_key())
shared_alice_joe = exchange_key(shared_alice, shared_joe.public_key())
shared_bob_joe = exchange_key(shared_bob, shared_joe.public_key())

# This is the point when we can start constructing encryption secret.
ephemeral_alice_joe = shared_alice_joe.exchange(ephemeral_key.public_key())
ephemeral_alice_bob = shared_alice_bob.exchange(ephemeral_key.public_key())
ephemeral_bob_joe = shared_bob_joe.exchange(ephemeral_key.public_key())


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
