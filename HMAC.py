import hmac
import hashlib

class HMAC:
    def __init__(self, key, hash_func):
        self.key = bytearray(key.encode())
        self.hash_func = hash_func

    def hash(self, msg):
        return hmac.new(self.key, bytearray(msg.encode()), self.hash_func)

    def verify(self, msg, received_hmac):
        return self.hash(msg).hexdigest() == received_hmac