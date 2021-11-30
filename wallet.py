from Crypto.Hash import SHA256
from Crypto.Hash import SHA3_256
import binascii  # Converts binary to ascii and the other way around
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils

from cryptography import exceptions
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
        
        private_key = ec.generate_private_key(ec.SECP256R1())
       
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
        private_key = pem
        public_key = pem1
        return ((private_key).decode(), (public_key).decode())
        #return (binascii.b2a_hex(private_key.export_key(format='DER')).decode('ascii'), binascii.b2a_hex(public_key.export_key(format='DER')).decode('ascii'))

    def sign_transaction(self, sender, recipient, amount):
        
        h = SHA3_256.new((str(sender) + str(recipient) + str(amount)).encode('utf8'))
        signature = DSS.new(ECC.import_key(self.private_key), 'fips-186-3').sign(h)
        #return binascii.hexlify(signature).decode('ascii')
        print('\nsignature: {}\n'.format(signature.hex()))
        #return signature.hex()
        #print(binascii.hexlify(signature).decode())
        return binascii.hexlify(signature).decode()
       
    '''
    Raises: ValueError – if the signature is not authentic
    and it always return False if it is successful.
    So rather than checking the return value, you need to check if the method raises an exception.
    '''
    @staticmethod
    def verify_transaction(transaction):
        # If is MINING sender, we don't have to validate, because MINING does't have a valid signature.
        public_key = ECC.import_key(transaction.sender)
        #verifier = DSS.new(public_key, 'fips-186-3')
        h = SHA3_256.new((str(transaction.sender) + str(transaction.recipient) + str(transaction.amount)).encode('utf8'))
        verifier = DSS.new(public_key, 'fips-186-3')
        try:
           verifier.verify(h, binascii.unhexlify(transaction.signature))
           print ("The message is authentic.")
        except ValueError:
           print ("The message is not authentic.")
           #return (verifier.verify(h, binascii.unhexlify(transaction.signature)))
        return (binascii.unhexlify(transaction.signature))
        