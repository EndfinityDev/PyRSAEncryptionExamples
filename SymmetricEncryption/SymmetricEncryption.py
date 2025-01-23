from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class EncryptionData:
    def __init__(self, key : bytes, initVector : bytes):
        self.Key = key
        self.InitVector = initVector
        #self.KeyLen = len(key)
        #self.IVLen = len(initVector)

    def Serialize(self) -> bytes:
        #keyLen = len(self.Key).to_bytes(4)
        #ivLen = len(self.InitVector).to_bytes(4)
        return self.Key + self.InitVector
    
    @staticmethod
    def Deserialize(data : bytes) -> "EncryptionData":
        #keyLen = int.from_bytes(data[:4])
        #ivLen = int.from_bytes(data[4:8])
        #key = data[8:(8+keyLen)]
        #initVector = data[(8+keyLen):(8+keyLen+ivLen)]
        key = data[:32]
        initVector = data[32:]
        return EncryptionData(key, initVector)

def BuildEncryptionData() -> EncryptionData:
    key = os.urandom(32)
    initVector = os.urandom(16)
    return EncryptionData(key, initVector)

def GenerateEncryptionData() -> None:
    encryptionData = BuildEncryptionData()
    serializedED = encryptionData.Serialize()
    with open("SymmetricEncryption/encryption_data.bin", "wb") as encryptionDataFile:
        encryptionDataFile.write(serializedED)

def LoadEncryptionData() -> EncryptionData:
    encryptionData = None
    with open("SymmetricEncryption/encryption_data.bin", "rb") as encryptionDataFile:
        data = encryptionDataFile.read()
        encryptionData = EncryptionData.Deserialize(data)
    return encryptionData

def EncryptData(data : bytes) -> bytes:
    encryptionData = LoadEncryptionData()
    cipher = Cipher(algorithms.AES(encryptionData.Key), modes.CTR(encryptionData.InitVector))
    encryptor = cipher.encryptor()
    encryptedData = encryptor.update(data) + encryptor.finalize()
    return encryptedData

def DecryptData(data : bytes) -> bytes:
    encryptionData = LoadEncryptionData()
    cipher = Cipher(algorithms.AES(encryptionData.Key), modes.CTR(encryptionData.InitVector))
    decryptor = cipher.decryptor()
    decryptedData = decryptor.update(data) + decryptor.finalize()
    return decryptedData


def Main():
    print(LoadEncryptionData().Serialize())
    GenerateEncryptionData()

    data = b"This is a test message encrypted with a symmetric key."
    print(len(data))
    encryptedData = EncryptData(data)
    print(encryptedData)
    decryptedData = DecryptData(encryptedData)
    print(decryptedData)


if __name__ == "__main__":
    Main()