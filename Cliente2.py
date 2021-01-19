import socket
import sys
import time
import cryptography
import hashlib

var = 0
confere = 0
s = socket.socket()
host = input(str("Por favor entre com o nome do host:"))
port = 1234

from cryptography.fernet import Fernet
symmetric_key = Fernet.generate_key()
f_cli2 = Fernet(symmetric_key)

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

while confere == 0:
    try:
        s.connect((host,port))
        print("conectado com Usuario 1")
    except:
        print("conexão com Usuario 1 falhou")

    #recebendo chave publica de cli 1
    if var == 0:
            var = 1
            key_cli1 = s.recv(1024)

    with open('key_cli1.pem', 'wb') as f:
        f.write(key_cli1)

    with open("key_cli1.pem", "rb") as key_file:
        key_cli1 = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )


    #gerando as chaves do cli 2
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    #salvando as chaves do cli 2
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('private_key.pem', 'wb') as f:
        f.write(pem)
        
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    s.send(pem)

    with open('public_key.pem', 'wb') as f:
        f.write(pem)

    #enviando chave simetrica
    encrypted_symmetric_key = key_cli1.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    s.send(encrypted_symmetric_key)

    #enviando hash assinado da chave simetrica
    h = hashlib.md5()
    h.update(symmetric_key)
    hash_symmetric_key = h.hexdigest()
    signature = private_key.sign(
        hash_symmetric_key.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
        hashes.SHA256()
        )
    s.send(signature)
    s.send(hash_symmetric_key.encode())

    if var == 1:
        var = 0
        confirma = s.recv(1024)
        if confirma.decode() == "1":
            print("Esta conexão esta segura")
            confere = 1
        else:
            print("Tentando estabelecer uma conexão segurança")
            confere = 0
            

while 1:
    h = hashlib.md5()
    #decriptando mensagem
    re_message = s.recv(1024)
    original_message = f_cli2.decrypt(re_message)
    original_message = original_message.decode()

    hash_remessage = s.recv(1024)
    h.update(original_message.encode())
    if(h.hexdigest() == hash_remessage.decode()):
       print("Usuario1:>>",original_message)
    else:
        print("Mensagem suspeita!!")
       
    #encriptando a mensagem
    message = input(str("Você:>>"))
    message = message.encode()
    encrypted = f_cli2.encrypt(message)
    s.send(encrypted)
    
    
    h.update(message)
    s.send(h.hexdigest().encode())
    


