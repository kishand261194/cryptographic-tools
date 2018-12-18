from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import os, struct
import matplotlib.pyplot as plt
from timeit import default_timer as timer

start_key=timer()
random_generator = Random.new().read
keys = RSA.generate(3072, random_generator)
end_key=timer()

def get_time_per_byte(capture_time):
    return [capture_time[0]/(1024*1024), capture_time[1]/(1024*1024),
            capture_time[2]/(1024),capture_time[3]/(1024)]

with open('id_rsa3072', 'wb') as fin:
    fin.write(keys.export_key('PEM'))
with open('id_rsa3072.pub', 'wb') as fin:
    fin.write(keys.publickey().exportKey("PEM") )

def encrypt(input_file, enc_file):
    t_time=0
    pub_key = RSA.importKey(open('id_rsa3072.pub').read())
    cipher = PKCS1_OAEP.new(pub_key)
    size = 342
    file_size = os.path.getsize(input_file)
    with open(enc_file, 'wb') as fout:
        with open(input_file, 'rb') as fin:
            while True:
                data = fin.read(size)
                if len(data)==0:
                    break
                start = timer()
                encd = cipher.encrypt(data)
                end = timer()
                t_time+=(end-start)
                fout.write(encd)
    return t_time
def decrypt(enc_file, verification_file):
    t_time=0
    priavte_key = RSA.importKey(open('id_rsa3072').read())
    with open(enc_file, 'rb') as fin:
        cipher = PKCS1_OAEP.new(priavte_key)
        with open(verification_file, 'wb') as fout:
            while True:
                data = fin.read(384)
                if len(data) == 0:
                    break
                start = timer()
                pt=cipher.decrypt(data)
                end = timer()
                t_time+=(end-start)
                fout.write(pt)
    return t_time

input_files=['bigfile.txt', 'smallfile.txt']
enc_files=['q1fAnsBigFile.enc', 'q1fAnsSmallFile.enc']
verification_files=['q1fVeriBigFile.txt', 'q1fVeriSmallFile.enc']
capture_time=[]
for i in range(2):
    capture_time.append(encrypt(input_files[i], enc_files[i]))
    capture_time.append(decrypt(enc_files[i], verification_files[i]))

plt.plot(capture_time[:2], label='1 MB file')
plt.plot(capture_time[2:4], dashes=[6, 2], label='1 KB file')
plt.xticks(range(2), ['Encryption','Decryption'])
plt.ylabel('time(s)')
plt.grid(axis='y', linestyle='-')
plt.legend()
plt.savefig('q1f.png')
time_per_byte=get_time_per_byte(capture_time)
print('Total time')
print('Encryption -  1MB: %E, 1KB: %E' %(capture_time[0], capture_time[2]))
print('Decryption -  1MB: %E, 1KB: %E' %(capture_time[1], capture_time[3]))
print('Per Byte')
print('Encryption -  1MB: %E, 1KB: %E' %(time_per_byte[0], time_per_byte[2]))
print('Decryption -  1MB: %E, 1KB: %E' %(time_per_byte[1], time_per_byte[3]))
print('Key Gen')
print('Time: %E' %(end_key-start_key))
