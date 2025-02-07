from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import base64, os

def main():
    with open("alice.pem", mode="rb") as f:
        their_pubkey = serialization.load_pem_public_key(f.read())
    
    with open("bob.pem", mode="rb") as f:
        my_pubkey = serialization.load_pem_public_key(f.read())

    with open("alice.pfx", mode="rb") as f:
        their_privkey = serialization.load_pem_private_key(f.read(), password=None)

    with open("bob.pfx", mode="rb") as f:
        my_privkey = serialization.load_pem_private_key(f.read(), password=None)

    shared_secret = my_privkey.exchange(ec.ECDH(), their_pubkey)
    other_shared_secret = their_privkey.exchange(ec.ECDH(), my_pubkey)

    sk_txt = base64.b64encode(shared_secret[:32]).decode("utf-8")
    sb_txt = base64.b64encode(shared_secret).decode("utf-8")

    print("sharedSecretKey", sk_txt)
    print("sharedBits", sb_txt)

    print("sk match", sk_txt == base64.b64encode(other_shared_secret[:32]).decode("utf-8"))
    print("bits match", sb_txt == base64.b64encode(other_shared_secret).decode("utf-8"))

    # shared secret has 384 bits. to use it with aes gcm, key must be truncated to 256 bits.
    aesgcm = AESGCM(shared_secret[:32])
    other_aesgcm = AESGCM(other_shared_secret[:32])

    iv = os.urandom(96 // 8)
    message = "Hello world!"
    encrypted_message = aesgcm.encrypt(iv, message.encode("ascii"), b"")
    print("encrypted message", encrypted_message)

    decrypted_message = other_aesgcm.decrypt(iv, encrypted_message, b"")
    print("decrypted message", decrypted_message)


if __name__ == "__main__":
    main()
