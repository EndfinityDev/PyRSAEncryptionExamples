from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from hashlib import sha256
import base64
import math

def MakeKeyPair(keySize : int) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    privateKey = rsa.generate_private_key(65537, keySize)
    publicKey = privateKey.public_key()
    return privateKey, publicKey

def StoreKeyPair(privateKey : rsa.RSAPrivateKey, publicKey : rsa.RSAPublicKey, password : bytes | None = None) -> None:
    encryption = serialization.NoEncryption()
    if password:
        encryption = serialization.BestAvailableEncryption(password)
    privateKeySerialized = privateKey.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    privateKeyB64 = base64.b64encode(privateKeySerialized)
    publicKeySerialized = publicKey.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    publicKeyB64 = base64.b64encode(publicKeySerialized)
    with open("Signing/private.key", "wb") as privateKeyFile:
        privateKeyFile.write(privateKeyB64)
    with open("Signing/public.key", "wb") as publicKeyFile:
        publicKeyFile.write(publicKeyB64)

def GenerateKeyPair(keySize : int = 1024, password : bytes | None = None) -> None:
    privateKey, publicKey = MakeKeyPair(keySize)
    StoreKeyPair(privateKey, publicKey, password)

def LoadKeyPair(password : bytes | None = None) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    privateKey = None
    publicKey = None
    with open("Signing/private.key", "rb") as privateKeyFile:
        privateKeyB64 = privateKeyFile.read()
        privateKeySerialized = base64.b64decode(privateKeyB64)
        privateKey = serialization.load_pem_private_key(privateKeySerialized, password)
    with open("Signing/public.key", "rb") as publicKeyFile:
        publicKeyB64 = publicKeyFile.read()
        publicKeySerialized = base64.b64decode(publicKeyB64)
        publicKey = serialization.load_pem_public_key(publicKeySerialized)
    return privateKey, publicKey

def LoadPrivateKey(password : bytes | None = None) -> rsa.RSAPrivateKey:
    privateKey = None
    with open("Signing/private.key", "rb") as privateKeyFile:
        privateKeyB64 = privateKeyFile.read()
        privateKeySerialized = base64.b64decode(privateKeyB64)
        print(len(privateKeySerialized))
        privateKey = serialization.load_pem_private_key(privateKeySerialized, password)
    return privateKey

def LoadPublicKey() -> rsa.RSAPublicKey:
    publicKey = None
    with open("Signing/public.key", "rb") as publicKeyFile:
        publicKeyB64 = publicKeyFile.read()
        publicKeySerialized = base64.b64decode(publicKeyB64)
        print(len(publicKeySerialized))
        publicKey = serialization.load_pem_public_key(publicKeySerialized)
    return publicKey

def SignData(data : bytes, password : bytes | None) -> bytes:
    privateKey = LoadPrivateKey(password)
    signature = privateKey.sign(data, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
    return signature

def AuthenticateData(signature : bytes, data : bytes) -> bool:
    publicKey = LoadPublicKey()
    try:
        publicKey.verify(signature, data, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
    except InvalidSignature:
        return False
    return True

def Main():
    password = b"12345678910a"
    hashedPassword = None
    if password:
        hashedPassword = sha256(password).digest()
    keySize = 1024
    GenerateKeyPair(keySize, hashedPassword)
    data = b"This data is to be signed and verified using an asymetric public-private RSA key pair and an optional hashed password. Large data may need to be hashed before being signed and verified"
    print(len(data))
    #print(data)
    signature = SignData(data, hashedPassword)
    print(signature)
    isAuthenticated = AuthenticateData(signature, data)
    print(isAuthenticated)

if __name__ == "__main__":
    Main()