from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import utils
import matplotlib.pyplot as plt
from timeit import default_timer as timer
start_key=timer()
private_key = dsa.generate_private_key(
    key_size=3072,
    backend=default_backend()
)
end_key=timer()

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
    signature = sign(digest, chosen_hash)
    end = timer()
    capture_time.append(end-start)
    start = timer()
    check=verify(signature, digest, chosen_hash)
    end = timer()
    capture_time.append(end-start)
    if check:
        print('Verification successfull')
    else:
        print('Verification failed')
plt.plot(capture_time[:2], label='1 MB file')
plt.plot(capture_time[2:4], dashes=[6, 2], label='1 KB file')
plt.xticks(range(2), ['Sign','Verify'])
plt.ylabel('time(s)')
plt.grid(axis='y', linestyle='-')
plt.legend()
plt.savefig('q1h.png')
print('Total time')
print('Signing -  1MB: %E, 1KB: %E' %(capture_time[0], capture_time[2]))
print('Verification -  1MB: %E, 1KB: %E' %(capture_time[1], capture_time[3]))
print('Key Gen')
print('Time: %E' %(end_key-start_key))
