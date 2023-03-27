import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
class userdata:
    def __init__(self, details: list[str], passwords: list[str]) -> None:
        self.details = details
        self.passwords = passwords



def hashit(password: str, salt = os.urandom(16)) -> tuple[bytes, bytes]:
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    while ",".encode() in salt:
        salt.replace(",".encode(), "".encode())
    return salt, key

def createAccount(password: str) -> None:
    salt, key = hashit(password)
    with open("passwordmanager/key.key", "wb") as k:
        k.write(salt + ",".encode())
        k.write(key)

def login(password: str) -> None:
    salt: str
    key: str
    with open("passwordmanager/key.key", "rb") as k:
        saltkey = k.read().split(",".encode())
        salt, key = saltkey
    entered = hashit(password, salt)
    return entered[1] == key

def encrypt(details: list[str], filename: str) -> None:
    key: bytes
    with open("passwordmanager/key.key", "rb") as k:
        key = k.read().split(",".encode())[1]

    key = hashit(key.decode(), key)[1]
    f = Fernet(key)
    details = [f.encrypt(detail.encode()) for detail in details]
    
    with open(filename, "ab") as f:
        f.write(",".encode().join(details) + "\n".encode())

def getPasswords(filename: str) -> str:
    key: bytes
    with open("passwordmanager/key.key", "rb") as k:
        key = k.read().split(",".encode())[1]

    key = hashit(key.decode(), key)[1]
    f = Fernet(key)
    with open(filename, "rb") as p:
        lines = p.read().split("\n".encode())
        if lines[-1] == b"":
            lines.pop()
        
        return [[f.decrypt(string).decode() for string in data] for data in [line.split(",".encode()) for line in lines]]
        
            
            
if __name__ == "__main__":
    if not os.path.isfile("passwordmanager/key.key"):
        createAccount(input("Creating an account. enter password"))

    if not login(input("Enter password")):
        exit()

    encrypt(["account, username, password"], "passwordmanager/accounts.dat")
    encrypt(["account2, username2, password2"], "passwordmanager/accounts.dat")
    encrypt(["name", "sortcode", "accountno", "16", "exp", "3"], "passwordmanager/bankcards.dat")
    print(getPasswords("passwordmanager/bankcards.dat"))
    #print(getPasswords("passwordmanager/bankcards.dat"))