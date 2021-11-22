from Crypto.PublicKey import RSA  # Generates public and private keys
from Crypto.Signature import PKCS1_v1_5  # Special algorithm that generate signatures
from Crypto.Hash import SHA256
import Crypto.Random  # Generates Random number
import binascii  # Converts binary to ascii and the other way around
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import binascii
import sys

class Wallet:
    def __init__(self, node_id):
        self.private_key = None
        self.public_key = None
        self.node_id = node_id

    def create_keys(self):
        private_key, public_key = self.generate_keys()
        self.private_key = private_key
        self.public_key = public_key

    def save_keys(self):
        if self.public_key is not None and self.private_key is not None:
            try:
                with open('wallet-{}.txt'.format(self.node_id), mode='w') as f:
                    f.write(self.public_key)
                    f.write('\n')
                    f.write(self.private_key)
                return True
            except (IOError, IndexError):
                print('ERROR:       save_keys       Saving wallet file failed.')
                return False

    def load_keys(self):
        try:
            with open('wallet-{}.txt'.format(self.node_id), mode='r') as f:
                keys = f.readlines()
                public_key = keys[0][:-1]  # -1 because the character \n when we write the file wallet.txt above
                private_key = keys[1]
                self.public_key = public_key
                self.private_key = private_key
            return True
        except (IOError, IndexError):
            print('ERROR:       load_keys       Loading wallet file failed.')
            return False

    def generate_keys(self):
        
        private_key = ec.generate_private_key(ec.SECP384R1())
        if (len(sys.argv)>1):type=int(sys.argv[1])

        if (type==1): private_key = ec.generate_private_key(ec.SECP192R1())
        elif (type==2): private_key = ec.generate_private_key(ec.SECP224R1())
        elif (type==3): private_key = ec.generate_private_key(ec.SECP256K1())
        elif (type==4): private_key = ec.generate_private_key(ec.SECP256R1())
        elif (type==5): private_key = ec.generate_private_key(ec.SECP384R1())
        elif (type==6): private_key = ec.generate_private_key(ec.SECP521R1())
        elif (type==7): private_key = ec.generate_private_key(ec.BrainpoolP256R1())
        elif (type==8): private_key = ec.generate_private_key(ec.BrainpoolP384R1())
        elif (type==9): private_key = ec.generate_private_key(ec.BrainpoolP512R1())
        vals = private_key.private_numbers()
        no_bits=vals.private_value.bit_length()
        print (f"Private key value: {vals.private_value}. Number of bits {no_bits}")
        
        public_key = private_key.public_key()
        vals=public_key.public_numbers()
        enc_point=binascii.b2a_hex(vals.encode_point()).decode()
        print (f"\nPublic key encoded point: {enc_point} \nx={enc_point[2:(len(enc_point)-2)//2+2]} \ny={enc_point[(len(enc_point)-2)//2+2:]}")
        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
        der = private_key.private_bytes(encoding=serialization.Encoding.DER,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
        print ("\nPrivate key (PEM):\n",pem.decode())
        print ("Private key (DER):\n",binascii.b2a_hex(der))
        pem1 = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
        der1 = public_key.public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)
        print ("\nPublic key (PEM):\n",pem1.decode())
        print ("Public key (DER):\n",binascii.b2a_hex(der1))
        #private_key = ECC.generate(curve='P-256')
        #private_key = ec.generate_private_key(ec.SECP256K1())
        #return (binascii.hexlify(private_key.export_key(format='DER')).decode('ascii'), binascii.hexlify(public_key.export_key(format='DER')).decode('ascii'))
        der = private_key
        der1 = private_key
        return (binascii.b2a_hexder(der.export_key(format='DER')).decode(), binascii.b2a_hexder(der1.export_key(format='DER')).decode())

    def sign_transaction(self, sender, recipient, amount):
        h = SHA256.new((str(sender) + str(recipient) + str(amount)).encode('utf8'))
        #signature = signer.sign(h)
        signature = DSS.new(ECC.import_key(self.private_key), 'fips-186-3').sign(h)
        return binascii.hexlify(signature).decode('ascii')

    @staticmethod
    def verify_transaction(transaction):
        # If is MINING sender, we don't have to validate, because MINING does't have a valid signature.
        public_key = ECC.import_key(binascii.unhexlify(transaction.sender))
        verifier = DSS.new(public_key, 'fips-186-3')
        h = SHA256.new((str(transaction.sender) + str(transaction.recipient) + str(transaction.amount)).encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(transaction.signature))

  