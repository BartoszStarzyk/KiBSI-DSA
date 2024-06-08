import Crypto.Util.number as num
import Crypto.Random.random as rand
from hashlib import sha1
from math import gcd


class elGammal:
    def __init__(self, key_len):
        self.key_len = key_len
        self.p = num.getPrime(self.key_len)
        self.g = rand.randint(1, self.p-1)
        self.k = None
        self.private_key = None
        self.public_key = None

    def gen_key(self):
        self.private_key = rand.randint(1, self.p- 1)
        self.public_key = self.g ** self.private_key  % self.p

    def sign(self, msg):
        h_m = int(sha1(msg.encode()).hexdigest(), 16)
        while True:
            k = rand.getrandbits(self.key_len)
            if gcd(k, self.p-1) == 1:
                self.k = k
                break
        a = pow(self.g, self.k, self.p)
        k_inv = pow(self.k, -1, self.p - 1)
        b = (k_inv * (h_m - self.private_key * a)) % (self.p - 1)
        return (a, b)

    def verify(self,msg, sig, key):
        a, b = sig
        p, g, y = key
        h_m = int(sha1(msg.encode()).hexdigest(), 16)
        return (pow(y, a) * pow(a, b)) % p==pow(g, h_m, p)

    def export_own_public_key(self, filepath, key='public'):
        with open(filepath, 'w') as f:
            if key=='public':
                k = (self.p, self.g, self.public_key)
            elif key=='private':
                k = (self.p, self.g, self.private_key)
            f.write(",".join(map(str, k)))

    def load_foreign_public_key(self, fp):
        with open(fp, 'r') as f:
            p, g, y = tuple(map(int, f.readline().split(",")))
        return p, g, y
    
    def load_message(self, fp):
        with open(fp, "r") as file:
            lines = [line.rstrip() for line in file]
            print(lines)
            msg = "\n".join(lines)
        return msg
    
if __name__ == "__main__":
    eg = elGammal(20)
    eg.gen_key()
    m = 'blablabla'
    a, b = eg.sign(m)
    print(m ,a, b)
    print(eg.p, eg.g)
    print(eg.private_key)
    print(eg.public_key)
    print(eg.verify(m, eg.public_key, a, b, eg.p, eg.g))

# TODO : dlaczego takie wolne