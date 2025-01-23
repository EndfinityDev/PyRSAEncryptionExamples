from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from hashlib import sha256
import base64
import os

KEY_SIZE = 1024
KEY_SIZE_BYTES = int(1024/8) 
ED_KEY_SIZE = 32
ED_IV_SIZE = 16

class EncryptionData:
    def __init__(self, key : bytes, initVector : bytes):
        self.Key = key
        self.InitVector = initVector

    def Serialize(self) -> bytes:
        return self.Key + self.InitVector
    
    @staticmethod
    def Deserialize(data : bytes) -> "EncryptionData":
        key = data[:32]
        initVector = data[32:]
        return EncryptionData(key, initVector)

def BuildEncryptionData() -> EncryptionData:
    key = os.urandom(ED_KEY_SIZE)
    initVector = os.urandom(ED_IV_SIZE)
    return EncryptionData(key, initVector)

def EncryptData(data : bytes, encryptionData : EncryptionData) -> bytes:
    cipher = Cipher(algorithms.AES(encryptionData.Key), modes.CTR(encryptionData.InitVector))
    encryptor = cipher.encryptor()
    encryptedData = encryptor.update(data) + encryptor.finalize()
    return encryptedData

def DecryptData(data : bytes, encryptionData : EncryptionData) -> bytes:
    cipher = Cipher(algorithms.AES(encryptionData.Key), modes.CTR(encryptionData.InitVector))
    decryptor = cipher.decryptor()
    decryptedData = decryptor.update(data) + decryptor.finalize()
    return decryptedData

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
    with open("FullEncryption/private.key", "wb") as privateKeyFile:
        privateKeyFile.write(privateKeyB64)
    with open("FullEncryption/public.key", "wb") as publicKeyFile:
        publicKeyFile.write(publicKeyB64)

def StoreSignKeyPair(privateKey : rsa.RSAPrivateKey, publicKey : rsa.RSAPublicKey, password : bytes | None = None) -> None:
    encryption = serialization.NoEncryption()
    if password:
        encryption = serialization.BestAvailableEncryption(password)
    privateKeySerialized = privateKey.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    privateKeyB64 = base64.b64encode(privateKeySerialized)
    publicKeySerialized = publicKey.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    publicKeyB64 = base64.b64encode(publicKeySerialized)
    with open("FullEncryption/private_sign.key", "wb") as privateKeyFile:
        privateKeyFile.write(privateKeyB64)
    with open("FullEncryption/public_sign.key", "wb") as publicKeyFile:
        publicKeyFile.write(publicKeyB64)

def LoadKeyPair(password : bytes | None = None) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    privateKey = None
    publicKey = None
    with open("FullEncryption/private.key", "rb") as privateKeyFile:
        privateKeyB64 = privateKeyFile.read()
        privateKeySerialized = base64.b64decode(privateKeyB64)
        privateKey = serialization.load_pem_private_key(privateKeySerialized, password)
    with open("FullEncryption/public.key", "rb") as publicKeyFile:
        publicKeyB64 = publicKeyFile.read()
        publicKeySerialized = base64.b64decode(publicKeyB64)
        publicKey = serialization.load_pem_public_key(publicKeySerialized)
    return privateKey, publicKey

def LoadSignKeyPair(password : bytes | None = None) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    privateKey = None
    publicKey = None
    with open("FullEncryption/private_sign.key", "rb") as privateKeyFile:
        privateKeyB64 = privateKeyFile.read()
        privateKeySerialized = base64.b64decode(privateKeyB64)
        privateKey = serialization.load_pem_private_key(privateKeySerialized, password)
    with open("FullEncryption/public_sign.key", "rb") as publicKeyFile:
        publicKeyB64 = publicKeyFile.read()
        publicKeySerialized = base64.b64decode(publicKeyB64)
        publicKey = serialization.load_pem_public_key(publicKeySerialized)
    return privateKey, publicKey

def EncodeKeyRSA(encryptionData : EncryptionData, publicKey : rsa.RSAPublicKey) -> bytes:
    encryptedData = publicKey.encrypt(encryptionData.Serialize(), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    return encryptedData

def DecodeKeyRSA(encodedData : bytes, privateKey : rsa.RSAPrivateKey) -> EncryptionData:
    decryptedData = privateKey.decrypt(encodedData, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    return decryptedData

def SignData(data : bytes, privateKey : rsa.RSAPrivateKey) -> bytes:
    signature = privateKey.sign(data, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
    return signature

def AuthenticateData(signature : bytes, publicKey : rsa.RSAPublicKey, data : bytes) -> bool:
    try:
        publicKey.verify(signature, data, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
    except InvalidSignature:
        return False
    return True

def Encryption() -> bytes:
    data = b"This is a large set of data to be split and encrypted with symmetric keys, then encrypted with asymmetric keys and signed with asymmetric keys.\nAfter that the data is to be authenticated and decrypted."

    password : bytes | None = b"SuperSecretPassword321"
    passwordHash : bytes | None = None
    if password:
        passwordHash = sha256(password).digest()

    signPassword : bytes | None = b"P4$$w0Rd!!1"
    signPasswordHash : bytes | None = None
    if signPassword:
        signPasswordHash = sha256(signPassword).digest()

    encryptionData = BuildEncryptionData()
    #print(encryptionData.Serialize())

    encryptedData = EncryptData(data, encryptionData)
    #print(encryptedData)

    privateKey, publicKey = MakeKeyPair(KEY_SIZE)
    #print(privateKey)
    #print(publicKey)
    StoreKeyPair(privateKey, publicKey, passwordHash)

    encodedKey = EncodeKeyRSA(encryptionData, publicKey)
    #print(encodedKey)
    #print(len(encodedKey))
    #print(KEY_SIZE_BYTES)
    assert len(encodedKey) == KEY_SIZE_BYTES

    privateSignKey, publicSignKey = MakeKeyPair(KEY_SIZE)
    #print(privateSignKey)
    #print(publicSignKey)

    StoreSignKeyPair(privateSignKey, publicSignKey, signPasswordHash)

    encodedDataPackage = encodedKey + encryptedData

    signature = SignData(encodedDataPackage, privateSignKey)
    print(signature)
    signatureSize = len(signature).to_bytes(4)
    print(signatureSize)

    encodedDataPackage = signatureSize + signature + encodedDataPackage

    print(encodedDataPackage)
    with open("FullEncryption/encoded_package.bin", "wb") as encodedPackageFile:
        encodedPackageFile.write(encodedDataPackage)

    return data

def Decryption() -> bytes:
    password : bytes | None = b"SuperSecretPassword321"
    passwordHash : bytes | None = None
    if password:
        passwordHash = sha256(password).digest()

    signPassword : bytes | None = b"P4$$w0Rd!!1"
    signPasswordHash : bytes | None = None
    if signPassword:
        signPasswordHash = sha256(signPassword).digest()

    encodedDataPackage = b""
    with open("FullEncryption/encoded_package.bin", "rb") as encodedPackageFile:
        encodedDataPackage = encodedPackageFile.read()

    signatureSize = int.from_bytes(encodedDataPackage[:4])
    signatureOffset = 4 + signatureSize
    signature = encodedDataPackage[4:signatureOffset]

    encodedData = encodedDataPackage[signatureOffset:]

    _, publicSignKey = LoadSignKeyPair(signPasswordHash)
    isAuthenticated = AuthenticateData(signature, publicSignKey, encodedData)
    print(isAuthenticated)
    assert isAuthenticated

    encodedKey = encodedData[:KEY_SIZE_BYTES]
    encodedData = encodedData[KEY_SIZE_BYTES:]

    privateKey, _ = LoadKeyPair(passwordHash)
    decodedKey = DecodeKeyRSA(encodedKey, privateKey)
    encryptionData = EncryptionData.Deserialize(decodedKey)
    #print(decodedKey)
    #print(len(encryptionData.Key), len(encryptionData.InitVector))

    decryptedData = DecryptData(encodedData, encryptionData)
    print(decryptedData)
    with open("FullEncryption/output.txt", "wb") as outFile:
        outFile.write(decryptedData)

    return decryptedData

def Main():
    result = Encryption() == Decryption()
    print(result)
    assert result

if __name__ == "__main__":
    Main()