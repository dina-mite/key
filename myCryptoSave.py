from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
import sys 

def split_string_into_parts(input_string, part_length):
    return [input_string[i:i + part_length] for i in range(0, len(input_string), part_length)]

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
print(len(plaintext))
#ciphertext = cipher.update(plaintext) + cipher.finalize()

part_length = 190

subparts = split_string_into_parts(plaintext, part_length)

for i, subpart in enumerate(subparts, 1):
    print(f"Parte {i}: {subpart}")

    ciphertext = public_key.encrypt(
        subpart,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    data = {
        "message": ciphertext.hex()  
    }

    with open("textoCriptografado_"+str(i)+".json", "w") as file:
        json.dump(data, file)
        
    with open("textoCriptografado_"+str(i)+".txt", "wb") as file:
        file.write(ciphertext)
