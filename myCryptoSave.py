from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
import sys 

with open("chavePublica.txt", "rb") as file:
    public_key_pem = file.read()

public_key = serialization.load_pem_public_key(
    public_key_pem,
    backend=default_backend()
)


plaintext = b"testeeeeeeeee"
if len(sys.argv)>1:
    #plaintext = sys.argv[1].encode()
    file_name = sys.argv[1]
    with open(file_name, "rb") as file:
        plaintext = file.read()
#print(plaintext)
#ciphertext = cipher.update(plaintext) + cipher.finalize()
ciphertext = public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
data = {
    "message": ciphertext.hex()  
}

with open("textoCriptografado.json", "w") as file:
    json.dump(data, file)
    
with open("textoCriptografado.txt", "wb") as file:
    file.write(ciphertext)
