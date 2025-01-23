from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
import base64


def Main():
    #privateKey = ec.generate_private_key(ec.SECP256K1())
    privateKey = rsa.generate_private_key(65537, 1024)
    publicKey = privateKey.public_key()

    elliptic = False

    password = b"testpass"
    encryption = serialization.NoEncryption()
    if password:
        encryption = serialization.BestAvailableEncryption(password)

    if elliptic:
        privateKey = ec.generate_private_key(ec.SECP256K1())
        publicKey = privateKey.public_key()

    privateKeySerialized = privateKey.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    privateKeyB64 = base64.b64encode(privateKeySerialized)

    publicKeySerialized = publicKey.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    publicKeyB64 = base64.b64encode(publicKeySerialized)

    print("\nPrivate Key:")
    print(privateKey)
    print(privateKeySerialized)
    print(privateKeyB64)

    print("\nPublic Key:")
    print(publicKey)
    print(publicKeySerialized)
    print(publicKeyB64)

    #password = b"wrongpass"

    readPrivateKey = serialization.load_pem_private_key(base64.b64decode(privateKeyB64), password)
    print(readPrivateKey)
    readPublicKey = serialization.load_pem_public_key(base64.b64decode(publicKeyB64))
    print(readPublicKey)

    message = b"Test message to encrypt and decrypt"

    #publicKey.encrypt()
    encryptedMessage = None
    if elliptic:
        encryptedMessage = message ^ publicKey.public_numbers().e
    else:
        encryptedMessage = readPublicKey.encrypt(message, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    print(encryptedMessage)

    decryptedMessage = None
    if elliptic:
        decryptedMessage = encryptedMessage ^ privateKey.private_numbers().public_numbers.e
    else:
        decryptedMessage = readPrivateKey.decrypt(encryptedMessage, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    print(decryptedMessage)

if __name__ == "__main__":
    Main()