import socket
import sys
import time
import cryptography
import hashlib


var = 0
confere = 0
s= socket.socket()
host = socket.gethostname()
print("Usuario 1 host:", host)
port = 1234
s.bind((host,port))
print("Usuario 1 ativado com sucesso")
s.listen(1)
conn,addr = s.accept()
print("Conectado com usuario 2")

from cryptography.fernet import Fernet

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

while confere == 0:
        #gerando chaves cli 1
        private_key1 = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
                )
        public_key1 = private_key1.public_key()

        #salvando as chaves do cli 1
        pem = private_key1.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
        )
        with open('private_key1.pem', 'wb') as f:
                f.write(pem)
        pem = public_key1.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        conn.send(pem)

        with open('public_key1.pem', 'wb') as f:
                f.write(pem)

        #recebendo chave publica cli2
        if var == 0:
                var = 1
                key_cli2 = conn.recv(1024)

        with open('key_cli2.pem', 'wb') as f:
                f.write(key_cli2)

        with open("key_cli2.pem", "rb") as key_file:
                key_cli2 = serialization.load_pem_public_key(
                        key_file.read(),
                        backend=default_backend()
                )
        #recebendo chave simetrica do cliente2
        if var == 1:
                var = 2
                symmetric_key_cli2 = conn.recv(1024)
                symmetric_key_cli2 = private_key1.decrypt(
                    symmetric_key_cli2,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                f_cli2 = Fernet(symmetric_key_cli2)
                
                
        #recebendo hash da chave simetrica do cliente2 e verificando se são iguais
        if var == 2:
               try:
                       var = 0
                       hash_symmetric_key_cli2 = conn.recv(1024)
                       hash_mens = conn.recv(1024)
                       key_cli2.verify(
                               hash_symmetric_key_cli2,
                               hash_mens,
                               padding.PSS(
                                       mgf=padding.MGF1(hashes.SHA256()),
                                       salt_length=padding.PSS.MAX_LENGTH
                                ),
                                hashes.SHA256()
                        )
               except:
                       print("Assinatura invalida")
                       conn.close()
               h = hashlib.md5()
               h.update(symmetric_key_cli2)
               if (hash_mens.decode() == h.hexdigest()):
                       print("Esta conexão esta segura")
                       confere = 1
                       conn.send("1".encode())
               else:
                       conn.send("0".encode())
                       print("Tentando estabelecer uma conexão segurança")
                       confere = 0
                       
while 1:
        h = hashlib.md5()
        #encriptando mensagem
        message = input(str("Você:>>"))
        message = message.encode()
        encrypted = f_cli2.encrypt(message)
        conn.send(encrypted)

        h.update(message)
        conn.send(h.hexdigest().encode())
            
        #decriptando a mensagem
        re_message = conn.recv(1024)
        original_message = f_cli2.decrypt(re_message)
        original_message = original_message.decode()

        hash_remessage = conn.recv(1024)
        h.update(original_message.encode())
        if(h.hexdigest() == hash_remessage.decode()):
                print("Usuario2:>>",original_message)
        else:
                print("Mensagem suspeita!!")
