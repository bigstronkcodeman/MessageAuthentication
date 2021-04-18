from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256

class RSA_Sig:
    def __init__(self, key_bits = 2048):
        self.key_bits = key_bits
        self.keypair = None

    def gen_keys(self):
        self.keypair = RSA.generate(self.key_bits)
        self.priv = self.keypair
        self.pub = self.keypair.publickey()

    def write_pub(self, name = ""):
        if self.keypair:
            with open(f"{name}{'_' if name else ''}public.pem", "wb") as fpub:
                fpub.write(self.pub.export_key())

    def read_keys(self, name = ""):
        with open(f"{name}{'_' if name else ''}private.pem", "rb") as fpriv, open(f"{name}{'_' if name else ''}public.pem", "rb") as fpub:
            self.priv = RSA.import_key(fpriv.read())
            self.pub = RSA.import_key(fpub.read())

    def sign(self, msg):
        hash = SHA256.new(msg.encode())
        signer = PKCS115_SigScheme(self.keypair)
        signature = signer.sign(hash)
        return signature

    def verify(self, msg, sig, sender=""):
        with open(f"{sender}{'_' if sender else ''}public.pem", "rb") as fpub:
            sender_pub = RSA.import_key(fpub.read())
        hash = SHA256.new(msg)
        verifier = PKCS115_SigScheme(sender_pub)
        try:
            verifier.verify(hash, sig)
            return True
        except:
            return False
        