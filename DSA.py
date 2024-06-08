import Crypto.Util.number as num
import Crypto.Random.random as rand
from hashlib import sha1
from math import gcd

class DSA:
    def __init__(self, key_len=1024):
        self.key_len = key_len
        self.q = num.getPrime(160)
        self.t = 0
        self.p = self.gen_p()
        self.g = self.gen_g()
        self.private_key = None  # private key
        self.public_key = None  # public key

    def gen_p(self):
        while True:
            k = rand.getrandbits(self.key_len - self.q.bit_length())
            p = k * self.q + 1
            if num.isPrime(p):
                return p

    def gen_g(self):
        while True:
            h = rand.randint(2, self.p - 2)
            g = pow(h, (self.p - 1) // self.q, self.p)
            if g > 1:
                return g

    def gen_key(self):
        self.private_key = rand.randint(1, self.q - 1)
        self.public_key = pow(self.g, self.private_key, self.p)

    def sign(self, msg):
        h_m = int(sha1(msg.encode()).hexdigest(), 16)
        while True:
            k = rand.randint(1, self.q - 1)
            if gcd(k, self.q) == 1:
                break
        r = pow(self.g, k, self.p) % self.q
        k_inv = pow(k, -1, self.q)
        s = (k_inv * (h_m + self.private_key * r)) % self.q
        return (r, s)

    def verify(self, msg, sig, key):
        r, s = sig
        q, p, g, y = key
        if not (0 < r < q and 0 < s < q):
            return False
        h_m = int(sha1(msg.encode()).hexdigest(), 16)
        w = pow(s, -1, q)
        u1 = (h_m * w) % q
        u2 = (r * w) % q
        v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
        return v == r
    
    def export_own_public_key(self, filepath, key='public'):
        with open(filepath, 'w') as f:
            if key=='public':
                k = (self.q, self.p, self.g, self.public_key)
            elif key=='private':
                k = (self.q, self.p, self.g, self.private_key)
            f.write(",".join(map(str, k)))

    def load_foreign_public_key(self, fp):
        with open(fp, 'r') as f:
            q, p, g, y = tuple(map(int, f.readline().split(",")))
        return q, p, g, y
    
    def load_message(self, fp):
        with open(fp, "r") as file:
            lines = [line.rstrip() for line in file]
            print(lines)
            msg = "\n".join(lines)
        return msg

if __name__ == "__main__":
    dsa1 = DSA()
    dsa1.gen_key()
    dsa1.export_own_public_key('dsa1_pub.txt', "public")
    m1 = 'dsa1'
    r1, s1 = dsa1.sign(m1)

    dsa2 = DSA()
    dsa2.gen_key()
    dsa2.export_own_public_key('dsa2_pub.txt', "public")
    m2 = 'dsa2'
    r2, s2 = dsa2.sign(m2)

    v1 = dsa1.verify(m2, r2, s2, *dsa2.load_foreign_public_key('dsa2_pub.txt'))
    v2 = dsa2.verify(m1, r1, s1, *dsa1.load_foreign_public_key('dsa1_pub.txt'))
    v3 = dsa2.verify(m1, r1, s1, *dsa1.load_foreign_public_key('dsa2_pub.txt'))
    print(v1, v2, v3)

