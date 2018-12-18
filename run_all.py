import os, random, struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from timeit import default_timer as timer
import matplotlib.pyplot as plt

key = get_random_bytes(16)
iv = get_random_bytes(16)
aes = AES.new(key, AES.MODE_CBC, iv)
read_size = 512

def encrypt(input_file, enc_file):
    file_size = os.path.getsize(input_file)
    with open(enc_file, 'wb') as fout:
        fout.write(struct.pack('<Q', file_size))
        fout.write(iv)
        with open(input_file, 'rb') as fin:
            while True:
                data = fin.read(read_size)
                n = len(data)
                if n == 0:
                    break
                elif n % 16 != 0:
                    data += ' ' * (16 - n % 16) #
                encrypted_data = aes.encrypt(data)
                fout.write(encrypted_data)


def decrypt(enc_file, verification_file):
    with open(enc_file, 'rb') as fin:
        file_size = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
        iv = fin.read(16)
        aes = AES.new(key, AES.MODE_CBC, iv)
        with open(verification_file, 'wb') as fout:
            while True:
                data = fin.read(read_size)
                n = len(data)
                if n == 0:
                    break
                decrpted_data = aes.decrypt(data)
                n = len(decrpted_data)
                if file_size > n:
                    fout.write(decrpted_data)
                else:
                    fout.write(decrpted_data[:file_size]) # <- remove padding on last block
                file_size -= n

input_files=['bigfile.txt', 'smallfile.txt']
enc_files=['q1aAnsBigFile.enc', 'q1aAnsSmallFile.enc']
verification_files=['q1aVeriBigFile.txt', 'q1aVeriSmallFile.enc']
capture_time=[]
for i in range(2):
    start = timer()
    encrypt(input_files[i], enc_files[i])
    end = timer()
    capture_time.append(end-start)
    start = timer()
    decrypt(enc_files[i], verification_files[i])
    end = timer()
    capture_time.append(end-start)

plt.plot(capture_time[:2], label='1 MB file AES 128 CBC')
plt.plot(capture_time[2:4], label='1 KB file AES 128 CBC')

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
import matplotlib.pyplot as plt
from timeit import default_timer as timer

nonce = Random.get_random_bytes(8)
count = Counter.new(64, nonce)
key = Random.get_random_bytes(16)

def encrypt(input_file, enc_file):
    encrypt = AES.new(key, AES.MODE_CTR, counter=count)
    with open(enc_file, 'wb') as fout:
        with open(input_file, 'rb') as fin:
            data = fin.read()
            encrypted = encrypt.encrypt(data)
            fout.write(encrypted)

def decrypt(enc_file, verification_file):
    count = Counter.new(64, nonce)
    decrypt = AES.new(key, AES.MODE_CTR, counter=count)
    with open(enc_file, 'rb') as fin:
        with open(verification_file, 'wb') as fout:
            data = fin.read()
            decrypted = decrypt.decrypt(data)
            fout.write(decrypted)

input_files=['bigfile.txt', 'smallfile.txt']
enc_files=['q1bAnsBigFile.enc', 'q1bAnsSmallFile.enc']
verification_files=['q1bVeriBigFile.txt', 'q1bVeriSmallFile.enc']
capture_time=[]
for i in range(2):
    start = timer()
    encrypt(input_files[i], enc_files[i])
    end = timer()
    capture_time.append(end-start)
    start = timer()
    decrypt(enc_files[i], verification_files[i])
    end = timer()
    capture_time.append(end-start)

plt.plot(capture_time[:2], label='1 MB file AES 128 CTR')
plt.plot(capture_time[2:4], label='1 KB file AES 128 CTR')

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
import matplotlib.pyplot as plt
from timeit import default_timer as timer

nonce = Random.get_random_bytes(8)
count = Counter.new(64, nonce)
key = Random.get_random_bytes(32)

def encrypt(input_file, enc_file):
    encrypt = AES.new(key, AES.MODE_CTR, counter=count)
    with open(enc_file, 'wb') as fout:
        with open(input_file, 'rb') as fin:
            data = fin.read()
            encrypted = encrypt.encrypt(data)
            fout.write(encrypted)

def decrypt(enc_file, verification_file):
    count = Counter.new(64, nonce)
    decrypt = AES.new(key, AES.MODE_CTR, counter=count)
    with open(enc_file, 'rb') as fin:
        with open(verification_file, 'wb') as fout:
            data = fin.read()
            decrypted = decrypt.decrypt(data)
            fout.write(decrypted)

input_files=['bigfile.txt', 'smallfile.txt']
enc_files=['q1cAnsBigFile.enc', 'q1cAnsSmallFile.enc']
verification_files=['q1cVeriBigFile.txt', 'q1cVeriSmallFile.enc']
capture_time=[]
for i in range(2):
    start = timer()
    encrypt(input_files[i], enc_files[i])
    end = timer()
    capture_time.append(end-start)
    start = timer()
    decrypt(enc_files[i], verification_files[i])
    end = timer()
    capture_time.append(end-start)

plt.plot(capture_time[:2], label='1 MB file AES 256 CTR')
plt.plot(capture_time[2:4], label='1 KB file AES 256 CTR')

from Crypto.Hash import SHA256
from Crypto.Hash import SHA512
from Crypto.Hash import SHA3_256
from timeit import default_timer as timer
import matplotlib.pyplot as plt
import numpy as np
input_files=['smallfile.txt','bigfile.txt']
capture_time=[]
for input_file in input_files:
    start = timer()
    with open(input_file, 'rb') as fin:
        data = fin.read()
        hash=SHA256.new()
        hash.update(data)
        print('SHA256')
        print(hash.hexdigest())
    end = timer()
    capture_time.append(end-start)
    start = timer()
    with open(input_file, 'rb') as fin:
        data = fin.read()
        hash=SHA512.new()
        hash.update(data)
        print('SHA512')
        print(hash.hexdigest())
    end = timer()
    capture_time.append(end-start)
    start = timer()
    with open(input_file, 'rb') as fin:
        data = fin.read()
        hash=SHA3_256.new()
        hash.update(data)
        print('SHA3_256')
        print(hash.hexdigest())
    end = timer()
    capture_time.append(end-start)

plt.plot(capture_time[0:3], label='1 KB file hash')
plt.plot(capture_time[3:6], label='1 MB file hash')
plt.xticks(range(3), ['SHA256','SHA512','SHA3_256'])


# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
# from Crypto import Random
# from Crypto.Hash import SHA3_256
# import os, struct
# import matplotlib.pyplot as plt
# from timeit import default_timer as timer
#
# random_generator = Random.new().read
# keys = RSA.generate(2048, random_generator)
# with open('id_rsa2048', 'wb') as fin:
#     fin.write(keys.export_key('PEM'))
# with open('id_rsa2048.pub', 'wb') as fin:
#     fin.write(keys.publickey().exportKey("PEM") )
#
# def encrypt(input_file, enc_file):
#     pub_key = RSA.importKey(open('id_rsa2048.pub').read())
#     cipher = PKCS1_OAEP.new(pub_key)
#     size = 214
#     file_size = os.path.getsize(input_file)
#     with open(enc_file, 'wb') as fout:
#         with open(input_file, 'rb') as fin:
#             while True:
#                 data = fin.read(size)
#                 if len(data)==0:
#                     break
#                 encd = cipher.encrypt(data)
#                 fout.write(encd)
#
# def decrypt(enc_file, verification_file):
#     priavte_key = RSA.importKey(open('id_rsa2048').read())
#     with open(enc_file, 'rb') as fin:
#         cipher = PKCS1_OAEP.new(priavte_key)
#         with open(verification_file, 'wb') as fout:
#             while True:
#                 data = fin.read(256)
#                 if len(data) == 0:
#                     break
#                 fout.write(cipher.decrypt(data))
#
# input_files=['bigfile.txt', 'smallfile.txt']
# enc_files=['q1eAnsBigFile.enc', 'q1eAnsSmallFile.enc']
# verification_files=['q1eVeriBigFile.txt', 'q1eVeriSmallFile.enc']
# capture_time=[]
# for i in range(2):
#     start = timer()
#     encrypt(input_files[i], enc_files[i])
#     end = timer()
#     capture_time.append(end-start)
#     start = timer()
#     decrypt(enc_files[i], verification_files[i])
#     end = timer()
#     capture_time.append(end-start)
#
# plt.plot(capture_time[:2], label='1 MB file RSA 2048')
# plt.plot(capture_time[2:4], label='1 KB file RSA 2048')


# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
# from Crypto import Random
# from Crypto.Hash import SHA3_256
# import os, struct
# import matplotlib.pyplot as plt
# from timeit import default_timer as timer
#
# random_generator = Random.new().read
# keys = RSA.generate(3072, random_generator)
# with open('id_rsa3072', 'wb') as fin:
#     fin.write(keys.export_key('PEM'))
# with open('id_rsa3072.pub', 'wb') as fin:
#     fin.write(keys.publickey().exportKey("PEM") )
#
# def encrypt(input_file, enc_file):
#     pub_key = RSA.importKey(open('id_rsa3072.pub').read())
#     cipher = PKCS1_OAEP.new(pub_key)
#     size = 342
#     file_size = os.path.getsize(input_file)
#     with open(enc_file, 'wb') as fout:
#         with open(input_file, 'rb') as fin:
#             while True:
#                 data = fin.read(size)
#                 if len(data)==0:
#                     break
#                 encd = cipher.encrypt(data)
#                 fout.write(encd)
#
# def decrypt(enc_file, verification_file):
#     priavte_key = RSA.importKey(open('id_rsa3072').read())
#     with open(enc_file, 'rb') as fin:
#         cipher = PKCS1_OAEP.new(priavte_key)
#         with open(verification_file, 'wb') as fout:
#             while True:
#                 data = fin.read(384)
#                 if len(data) == 0:
#                     break
#                 fout.write(cipher.decrypt(data))
#
# input_files=['bigfile.txt', 'smallfile.txt']
# enc_files=['q1fAnsBigFile.enc', 'q1fAnsSmallFile.enc']
# verification_files=['q1fVeriBigFile.txt', 'q1fVeriSmallFile.enc']
# capture_time=[]
# for i in range(2):
#     start = timer()
#     encrypt(input_files[i], enc_files[i])
#     end = timer()
#     capture_time.append(end-start)
#     start = timer()
#     decrypt(enc_files[i], verification_files[i])
#     end = timer()
#     capture_time.append(end-start)
#
# plt.plot(capture_time[:2], label='1 MB file RSA 3072')
# plt.plot(capture_time[2:4], label='1 KB file RSA 3072')

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import utils
import matplotlib.pyplot as plt
from timeit import default_timer as timer

private_key = dsa.generate_private_key(
    key_size=2048,
    backend=default_backend()
)

def sign(digest, chosen_hash):
    return private_key.sign(digest, utils.Prehashed(chosen_hash))

def verify(signature, digest, chosen_hash):
    try:
        public_key = private_key.public_key()
        public_key.verify(signature, digest, utils.Prehashed(chosen_hash))
        return True
    except:
        return False
capture_time=[]
for file in ['bigfile.txt', 'smallfile.txt']:
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash, default_backend())
    hasher.update(open(file, 'rb').read())
    digest = hasher.finalize()
    start = timer()
    end = timer()
    capture_time.append(end-start)
    signature = sign(digest, chosen_hash)
    start = timer()
    if verify(signature, digest, chosen_hash):
        print('Verification successfull')
    else:
        print('Verification failed')
    end = timer()
    capture_time.append(end-start)
plt.plot(capture_time[:2], label='1 MB file DSA 2048')
plt.plot(capture_time[2:4], label='1 KB file DSA 2048')


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import utils
import matplotlib.pyplot as plt
from timeit import default_timer as timer

private_key = dsa.generate_private_key(
    key_size=3072,
    backend=default_backend()
)

def sign(digest, chosen_hash):
    return private_key.sign(digest, utils.Prehashed(chosen_hash))

def verify(signature, digest, chosen_hash):
    try:
        public_key = private_key.public_key()
        public_key.verify(signature, digest, utils.Prehashed(chosen_hash))
        return True
    except:
        return False
capture_time=[]
for file in ['bigfile.txt', 'smallfile.txt']:
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash, default_backend())
    hasher.update(open(file, 'rb').read())
    digest = hasher.finalize()
    start = timer()
    end = timer()
    capture_time.append(end-start)
    signature = sign(digest, chosen_hash)
    start = timer()
    if verify(signature, digest, chosen_hash):
        print('Verification successfull')
    else:
        print('Verification failed')
    end = timer()
    capture_time.append(end-start)
plt.plot(capture_time[:2], label='1 MB file DSA 3072')
plt.plot(capture_time[2:4], label='1 KB file DSA 3072')
plt.ylabel('time(s)')
plt.xticks(range(2), ['Encryption','Decryption'])
plt.grid(axis='y', linestyle='-')
plt.legend()
plt.show()
