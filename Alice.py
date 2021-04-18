from HMAC import HMAC, hashlib
from RSA_Signature import RSA_Sig
import sys, time, random, string

def hmac_write(msg, key):
    h = HMAC(key, hashlib.sha256)
    return h.hash(msg).hexdigest()

def rsa_write(cipher, msg):
    return cipher.sign(msg).hex()

def main():
    iters = 1
    if len(sys.argv) > 2:
        try:
            iters = int(sys.argv[2])
        except ValueError:
            print("Invalid number of iterations!")
            return
    if len(sys.argv) > 1:
        if sys.argv[1] == "birthday":
            cnt = 0
            key = "2967232053729551"
            h = HMAC(key, hashlib.sha256)
            for i in range(iters):
                collision = False
                d = {}
                while not collision:
                    rndm_str = "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
                    digest = h.hash(rndm_str).hexdigest()[:2]
                    if digest not in d:
                        d[digest] = rndm_str
                    elif d[digest] != rndm_str:
                        collision = True
                    cnt += 1
            if iters == 1:
                print(f"{d[digest]} and {rndm_str} have the same hash: {digest}, ", end="")
            print(f"{cnt/iters} average messages tried until collision")
            return
        msg = input("Enter a message to send to Bob: ")
        start = time.time()
        if sys.argv[1] == "hmac":
            with open("secretkey.txt", "r") as f:
                key = f.read()
            for i in range(iters):
                digest = hmac_write(msg, key)
            with open("mactext", "wb+") as fout:
                fout.write(bytearray(msg.encode()) + b'\n')
                fout.write(bytearray(digest.encode()))
            print(f"Key is: {key}\nHash digest is: {digest}")
        elif sys.argv[1] == "rsa":
            cipher = RSA_Sig(2048)
            cipher.gen_keys()
            cipher.write_pub("alice")
            for i in range(iters):
                sig = rsa_write(cipher, msg)
            with open("sigtext", "wb+") as fout:
                fout.write(bytearray(msg.encode()) + b'\n')
                fout.write(bytearray(sig.encode()))
            print(f"Signature is: {sig}")
        else:
            print(f"{sys.argv[1]} is not a valid authentication option!")
        print(f"Average time elapsed: {(time.time() - start) / iters} s") if iters > 1 else None
    else:
        print("Not enough arguments. Please provide the authentication method you wish to use as a command line argument to the program.")

if __name__ == "__main__":
    main()