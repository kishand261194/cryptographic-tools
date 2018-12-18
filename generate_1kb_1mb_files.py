import random
import string
def generate_random_file(size):
    return ''.join([random.choice(string.ascii_letters) for i in range(size)])
with open('bigfile.txt', 'w') as f:
    f.write(generate_random_file(1024*1024))
with open('smallfile.txt', 'w') as f:
    f.write(generate_random_file(1024))
