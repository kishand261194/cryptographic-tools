import os, random, struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from timeit import default_timer as timer
import matplotlib.pyplot as plt
start_key=timer()
key = get_random_bytes(16)
end_key=timer()
iv = get_random_bytes(16)
aes = AES.new(key, AES.MODE_CBC, iv)
read_size = 512
def get_time_per_byte(capture_time):
    return [capture_time[0]/(1024*1024), capture_time[1]/(1024*1024),
            capture_time[2]/(1024),capture_time[3]/(1024)]


def encrypt(input_file, enc_file):
    file_size = os.path.getsize(input_file)
    t_time=0
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
                start = timer()
                encrypted_data = aes.encrypt(data)
                end = timer()
                t_time+=(end-start)
                fout.write(encrypted_data)
    return t_time

def decrypt(enc_file, verification_file):
    t_time=0
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
                start = timer()
                decrpted_data = aes.decrypt(data)
                end = timer()
                t_time+=(end-start)
                n = len(decrpted_data)
                if file_size > n:
                    fout.write(decrpted_data)
                else:
                    fout.write(decrpted_data[:file_size]) # <- remove padding on last block
                file_size -= n
    return t_time
input_files=['bigfile.txt', 'smallfile.txt']
enc_files=['q1aAnsBigFile.enc', 'q1aAnsSmallFile.enc']
verification_files=['q1aVeriBigFile.txt', 'q1aVeriSmallFile.enc']
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
plt.savefig('q1a.png')
time_per_byte=get_time_per_byte(capture_time)
print('Total time')
print('Encryption -  1MB: %E, 1KB: %E' %(capture_time[0], capture_time[2]))
print('Decryption -  1MB: %E, 1KB: %E' %(capture_time[1], capture_time[3]))
print('Per Byte')
print('Encryption -  1MB: %E, 1KB: %E' %(time_per_byte[0], time_per_byte[2]))
print('Decryption -  1MB: %E, 1KB: %E' %(time_per_byte[1], time_per_byte[3]))
print('Key Gen')
print('Time: %E' %(end_key-start_key))
