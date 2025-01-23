from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
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
    with open("Encryption/private.key", "wb") as privateKeyFile:
        privateKeyFile.write(privateKeyB64)
    with open("Encryption/public.key", "wb") as publicKeyFile:
        publicKeyFile.write(publicKeyB64)

def GenerateKeyPair(keySize : int = 1024, password : bytes | None = None) -> None:
    privateKey, publicKey = MakeKeyPair(keySize)
    StoreKeyPair(privateKey, publicKey, password)

def LoadKeyPair(password : bytes | None = None) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    privateKey = None
    publicKey = None
    with open("Encryption/private.key", "rb") as privateKeyFile:
        privateKeyB64 = privateKeyFile.read()
        privateKeySerialized = base64.b64decode(privateKeyB64)
        privateKey = serialization.load_pem_private_key(privateKeySerialized, password)
    with open("Encryption/public.key", "rb") as publicKeyFile:
        publicKeyB64 = publicKeyFile.read()
        publicKeySerialized = base64.b64decode(publicKeyB64)
        publicKey = serialization.load_pem_public_key(publicKeySerialized)
    return privateKey, publicKey

def LoadPrivateKey(password : bytes | None = None) -> rsa.RSAPrivateKey:
    privateKey = None
    with open("Encryption/private.key", "rb") as privateKeyFile:
        privateKeyB64 = privateKeyFile.read()
        privateKeySerialized = base64.b64decode(privateKeyB64)
        print(len(privateKeySerialized))
        privateKey = serialization.load_pem_private_key(privateKeySerialized, password)
    return privateKey

def LoadPublicKey() -> rsa.RSAPublicKey:
    publicKey = None
    with open("Encryption/public.key", "rb") as publicKeyFile:
        publicKeyB64 = publicKeyFile.read()
        publicKeySerialized = base64.b64decode(publicKeyB64)
        print(len(publicKeySerialized))
        publicKey = serialization.load_pem_public_key(publicKeySerialized)
    return publicKey

def EncodeData(data : bytes) -> bytes:
    #_, publicKey = LoadKeyPair(password)
    publicKey = LoadPublicKey()
    keySizeBytes = int(publicKey.key_size / 8) - 66 # supposedly 66 bytes is metadata?
    dataLen = len(data)
    steps = int(math.ceil(float(dataLen) / keySizeBytes))
    encryptedData = b""
    for i in range(steps):
        imin = i * keySizeBytes
        imax = min((i + 1) * keySizeBytes, dataLen)
        tempData = data[imin:imax]
        encryptedData += publicKey.encrypt(tempData, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    #encryptedData = publicKey.encrypt(data, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    return encryptedData

def DecodeData(data : bytes, password : bytes | None = None) -> bytes:
    #privateKey, _ = LoadKeyPair(password)
    privateKey = LoadPrivateKey(password)
    keySizeBytes = int(privateKey.key_size / 8)
    dataLen = len(data)
    steps = int(math.ceil(float(dataLen) / keySizeBytes))
    decryptedData = b""
    for i in range(steps):
        imin = i * keySizeBytes
        imax = min((i + 1) * keySizeBytes, dataLen)
        tempData = data[imin:imax]
        decryptedData += privateKey.decrypt(tempData, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    #return privateKey.decrypt(data, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    return decryptedData

def Main() -> None:
    password = b"abcdef9"
    hashedPassword = None
    if password:
        hashedPassword = sha256(password).digest()
    keySize = 1024
    GenerateKeyPair(keySize, hashedPassword)
    data = b"This is a test message that is to be encrypted and decrypted using an asymetric RSA public-private key pair and an optional hashed password.\nThis is a long message that gets split and encoded using the same key pair. In a real scenario this message should be encrypted using symmetric keys, then that data should be encrypted asymetrically."
    print(data)
    print(len(data))
    encodedData = EncodeData(data)
    with open("Encryption/encrypted.bin", "wb") as encryptedFile:
        encryptedFile.write(encodedData)
    print(encodedData)
    print(len(encodedData))
    decodedData = DecodeData(encodedData, hashedPassword)
    print(decodedData)
    with open("Encryption/decrypted.txt", "wb") as decryptedFile:
        decryptedFile.write(decodedData)
    

if __name__ == "__main__":
    Main()