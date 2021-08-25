from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def my_encript(msg, pubkey):
    # parts = pubkey.splitlines()
    public_key = serialization.load_pem_public_key(
        pubkey,
        backend=default_backend()
    )
    encrypted = public_key.encrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return encrypted


def my_decrypt(msg, prikey):
    private_key = serialization.load_pem_private_key(
        prikey,
        password=None,
        backend=default_backend()
    )
    original_message = private_key.decrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return original_message
