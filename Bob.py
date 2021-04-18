from HMAC import HMAC, hashlib
from RSA_Signature import RSA_Sig
import sys, time

def read_hmac(keyfname, fout):
    with open(keyfname, "r") as f:
        key = f.read()
    h = HMAC(key, hashlib.sha256)
    with open(fout, "r") as fin:
        msg = fin.readline()[:-1]
        hmac = fin.read()
    return (msg, hmac, h.verify(msg, hmac))

def read_rsa(fout):
    cipher = RSA_Sig(2048)
    with open(fout, "rb") as fin:
        msg = fin.readline()[:-1]
        sig = fin.read()
    return (msg.decode(), sig.decode(), cipher.verify(msg, bytes.fromhex(sig.decode()), sender='alice'))

def main():
    iters = 1
    if len(sys.argv) > 2:
        try:
            iters = int(sys.argv[2])
        except ValueError:
            print("Invalid number of iterations!")
            return
    start = time.time()
    if sys.argv[1] == "hmac":
        for i in range(iters):
            (msg, hmac, verified) = read_hmac("secretkey.txt", "mactext")
            if i == iters - 1:
                print(f"Message received: {msg}\nDigest received: {hmac}")
                print(f"Verified: {verified}")
    elif sys.argv[1] == "rsa":
        for i in range(iters):
            (msg, sig, verified) = read_rsa("sigtext")
            if i == iters - 1:
                print(f"Message received: {msg}\nSignature received: {sig}")
                print(f"Verified: {verified}")
    print(f"Average time elapsed: {(time.time() - start) / iters} s") if iters > 1 else None

if __name__ == "__main__":
    main()