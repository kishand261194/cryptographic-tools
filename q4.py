from Crypto.Hash import SHA256
from Crypto.Hash import SHA512
from Crypto.Hash import SHA3_256
from timeit import default_timer as timer
import matplotlib.pyplot as plt
import numpy as np
input_files=['smallfile.txt','bigfile.txt']
capture_time=[]

def get_time_per_byte(capture_time):
    return [capture_time[0]/(1024), capture_time[1]/(1024),
            capture_time[2]/(1024),capture_time[3]/(1024*1024),
            capture_time[4]/(1024*1024),capture_time[5]/(1024*1024)]

for input_file in input_files:
    with open(input_file, 'rb') as fin:
        data = fin.read()
        start = timer()
        hash=SHA256.new()
        hash.update(data)
        end = timer()
        print('SHA_256: ', hash.hexdigest())
        capture_time.append(end-start)
    with open(input_file, 'rb') as fin:
        data = fin.read()
        start = timer()
        hash=SHA512.new()
        hash.update(data)
        hash.hexdigest()
        end = timer()
        print('SHA_512: ', hash.hexdigest())
        capture_time.append(end-start)
    with open(input_file, 'rb') as fin:
        start = timer()
        data = fin.read()
        hash=SHA3_256.new()
        hash.update(data)
        end = timer()
        print('SHA3_256: ', hash.hexdigest())
    capture_time.append(end-start)

plt.plot(capture_time[0:3], label='1 KB file')
plt.plot(capture_time[3:6], dashes=[6, 2], label='1 MB file')
plt.xticks(range(3), ['SHA256','SHA512','SHA3_256'])
plt.ylabel('time(s)')
plt.grid(axis='y', linestyle='-')
plt.legend()
plt.savefig('q1d.png')
time_per_byte=get_time_per_byte(capture_time)
print('Total time')
print('SHA256 -  1MB: %E, 1KB: %E' %(capture_time[3], capture_time[0]))
print('SHA_512 -  1MB: %E, 1KB: %E' %(capture_time[4], capture_time[1]))
print('SHA3_256 -  1MB: %E, 1KB: %E' %(capture_time[5], capture_time[2]))
print('Per Byte')
print('SHA256 -  1MB: %E, 1KB: %E' %(time_per_byte[3], time_per_byte[0]))
print('SHA_512 -  1MB: %E, 1KB: %E' %(time_per_byte[4], time_per_byte[1]))
print('SHA3_256 -  1MB: %E, 1KB: %E' %(time_per_byte[5], time_per_byte[2]))
