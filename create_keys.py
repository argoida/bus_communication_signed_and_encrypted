from ecdsa import SigningKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def more_keys():
    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
            backend=default_backend()
        )
    for i in range(1,10):
        public_key = private_key.public_key()
        pripem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        pubpem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        sk = SigningKey.generate()  # uses NIST192p
        vk = sk.verifying_key
        signature = sk.sign(b"message")
        assert vk.verify(signature, b"message")
        print(f'    "{i}": {"{"}')
        print('        "crypt_private": ', pripem, ",")
        print('        "crypt_public": ', pubpem, ",")
        print('        "signature_private": ', sk.to_pem(), ",")
        print('        "signature_public": ', vk.to_pem())
        print("    },")

more_keys()

