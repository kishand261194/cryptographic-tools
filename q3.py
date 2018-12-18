from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
import matplotlib.pyplot as plt
from timeit import default_timer as timer

nonce = Random.get_random_bytes(8)
count = Counter.new(64, nonce)
start_key=timer()
key = Random.get_random_bytes(32)
end_key=timer()

def get_time_per_byte(capture_time):
    return [capture_time[0]/(1024*1024), capture_time[1]/(1024*1024),
            capture_time[2]/(1024),capture_time[3]/(1024)]

def encrypt(input_file, enc_file):
    encrypt = AES.new(key, AES.MODE_CTR, counter=count)
    with open(enc_file, 'wb') as fout:
        with open(input_file, 'rb') as fin:
            data = fin.read()
            start = timer()
            encrypted = encrypt.encrypt(data)
            end = timer()
            fout.write(encrypted)
    return(end-start)
def decrypt(enc_file, verification_file):
    count = Counter.new(64, nonce)
    decrypt = AES.new(key, AES.MODE_CTR, counter=count)
    with open(enc_file, 'rb') as fin:
        with open(verification_file, 'wb') as fout:
            data = fin.read()
            start = timer()
            decrypted = decrypt.decrypt(data)
            end = timer()
            fout.write(decrypted)
    return(end-start)

input_files=['bigfile.txt', 'smallfile.txt']
enc_files=['q1cAnsBigFile.enc', 'q1cAnsSmallFile.enc']
verification_files=['q1cVeriBigFile.txt', 'q1cVeriSmallFile.enc']
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
plt.savefig('q1c.png')
time_per_byte=get_time_per_byte(capture_time)
print('Total time')
print('Encryption -  1MB: %E, 1KB: %E' %(capture_time[0], capture_time[2]))
print('Decryption -  1MB: %E, 1KB: %E' %(capture_time[1], capture_time[3]))
print('Per Byte')
print('Encryption -  1MB: %E, 1KB: %E' %(time_per_byte[0], time_per_byte[2]))
print('Decryption -  1MB: %E, 1KB: %E' %(time_per_byte[1], time_per_byte[3]))
print('Key Gen')
print('Time: %E' %(end_key-start_key))
