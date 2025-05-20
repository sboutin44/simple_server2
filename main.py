from flask import Flask

# RSA
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# AES
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def gen_rsa_keys()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    keys = [private_key, public_key]
    return keys

def rsa_encrypt(plaintext)
    message = b"hello world"
    public_key = gen_rsa_keys()[1]
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def AES_dec(ciphertext):
    key = get_random_bytes(16)  # 128-bit key
    iv = get_random_bytes(16)   # Initialization vector

    # Message to decryopt
    # Example of input b'This is a secret message.'
    data = ciphertext

    # Decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(pad(data, AES.block_size))

    # Print Base64-encoded output (for readability/transmission)
    print("Decrypted (base64):", base64.b64encode(ciphertext).decode())

    return base64.b64encode(plaintext).decode()


def AES_enc(plaintext):
    # AES key must be 16, 24, or 32 bytes long
    key = get_random_bytes(16)  # 128-bit key
    iv = get_random_bytes(16)   # Initialization vector

    # Message to encrypt
    # Example of input b'This is a secret message.'
    data = plaintext

    # Encrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))

    # Print Base64-encoded output (for readability/transmission)
    print("Encrypted (base64):", base64.b64encode(ciphertext).decode())

    return base64.b64encode(ciphertext).decode()

app = Flask(__name__)

@app.route('/')
def encrypted_hello():
    text = b'Hello, World!'
    ciphertext = AES_enc(text)
    text = "Encrypted Text: " + ciphertext
    return text

if __name__ == '__main__':
    app.run(port=5000)

