import base64
import secrets
from fractions import Fraction
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Util.number import getPrime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

class CryptoUtils:
    
    @staticmethod    
    def to_bytes(integer):
        return integer.to_bytes((integer.bit_length() + 7) // 8, byteorder='big')
    
    @staticmethod
    def generate_probable_prime(num_bits=128):   
        return getPrime(num_bits)

    @staticmethod
    def hash(data):
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(data)
        return int.from_bytes(digest.finalize(), byteorder='big')
       
    @staticmethod   
    def encrypt(encrypted_secretnumber, data):
        key_bytes = CryptoUtils.to_bytes(encrypted_secretnumber)[:24]        
        cipher = Cipher(algorithms.TripleDES(key_bytes), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(algorithms.TripleDES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()  

    @staticmethod
    def decrypt(key, encrypted_data): 
        key = key[:24]    
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())      
        decryptor = cipher.decryptor()       
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(algorithms.TripleDES.block_size).unpadder()      
        return unpadder.update(decrypted_padded_data) + unpadder.finalize()

class Share:
    def __init__(self, index=0, encrypted_share=0, share=0, commitmentproof=0, secretkeyproof=0, encrypted_text=None):
        self._index = index
        self._encrypted_share = encrypted_share
        self._share = share
        self._commitmentproof = commitmentproof
        self._secretkeyproof = secretkeyproof
        self._encrypted_text = encrypted_text if encrypted_text is not None else bytes()

    @property
    def index(self):
        return self._index

    @property
    def encrypted_share(self):
        return self._encrypted_share

    @property
    def share(self):
        return self._share

    @property
    def commitmentproof(self):
        return self._commitmentproof

    @property
    def secretkeyproof(self):
        return self._secretkeyproof

    @property
    def encrypted_text(self):
        return self._encrypted_text

class ExternalShares:
    def __init__(self, shares, modulus, encrypted_text):
        self.shares = shares 
        self.modulus = modulus
        self.encrypted_text = encrypted_text

    @property
    def shares(self):
        return self._shares

    @shares.setter
    def shares(self, value):
        self._shares = value

    @property
    def modulus(self):
        return self._modulus
    
    @modulus.setter
    def modulus(self, value):
        self._modulus = value

    @property
    def encrypted_text(self):
        return self._encrypted_text
    
    @encrypted_text.setter
    def encrypted_text(self, value):
        self._encrypted_text = value

    @encrypted_text.setter
    def encrypted_text(self, value):
        self._encrypted_text = value
    
    def to_dict(self):
        return {
            'shares': self.shares,
            'modulus': self.modulus,
            'encrypted_text': self.encrypted_text
        }
  
class PublishedShares:
    def __init__(self, commitments=None, encrypted_shares=None, sharesproof=None, commitmentproof=0, encrypted_text=None):
        self.commitments = commitments if commitments is not None else []
        self.encrypted_shares = encrypted_shares if encrypted_shares is not None else []
        self.sharesproof = sharesproof if sharesproof is not None else []
        self.commitmentproof = commitmentproof
        self.encrypted_text = encrypted_text if encrypted_text is not None else bytes()

    def get_share(self, index, secret_key, info, public_keys):
        gpo = info.group_prime_order
        gpo_minus = gpo - 1
        #commitmentProducts
        cp_inverse = pow(secret_key, -1, gpo_minus)
        share_value = pow(self.encrypted_shares[index], cp_inverse, gpo)
        witnessValue = 11  

        data_for_hash = b''.join([
            CryptoUtils.to_bytes(public_keys[index]),
            CryptoUtils.to_bytes(self.encrypted_shares[index]),
            CryptoUtils.to_bytes(pow(info.generator_G, witnessValue, gpo)),
            CryptoUtils.to_bytes(pow(share_value, witnessValue, gpo))
        ])        
         
        commitmentproof =  CryptoUtils.hash(data_for_hash) % gpo
        secretkeyproof = (witnessValue - secret_key * commitmentproof) % (gpo - 1)

        return Share(index=index, encrypted_share=self.encrypted_shares[index], share=share_value, 
                     commitmentproof=commitmentproof, secretkeyproof=secretkeyproof)

    #TODO Refazer a verificação dos shares baseado nos hashes      

class PublicInfoPVSS:
    def __init__(self, n, t, group_prime_order, generator_g, generator_G):
        self.n = n
        self.t = t
        self.group_prime_order = group_prime_order
        self.num_bits = group_prime_order.bit_length()
        self.generator_g = generator_g
        self.generator_G = generator_G
        self.enc_key = None



class PVSSEngine:
    def __init__(self, public_info):
        self.public_info = public_info

    def generate_secret(self):
        return secrets.randbelow(self.public_info.group_prime_order)

    def generate_public_key(self, secret_key):
        return pow(self.public_info.generator_G, secret_key, self.public_info.group_prime_order)

    def generate_secret_keys(self, n):
        secret_keys_set = set()
        while len(secret_keys_set) < n:
            secret_keys_set.add(CryptoUtils.generate_probable_prime(self.public_info.num_bits))
        return list(secret_keys_set)

    def general_publish_shares(self, secretdata, public_keys):
        secretnumber = self.generate_secret()
        secret_enc_key = self.generate_public_key(secretnumber)
        encrypted_data = CryptoUtils.encrypt(secret_enc_key, secretdata)
        return self.publish_shares(secretnumber, encrypted_data, public_keys)

    def publish_shares(self, secretnumber, encrypted_data, public_keys):
        t, n, g, gpo = self.public_info.t, self.public_info.n, self.public_info.generator_g, self.public_info.group_prime_order
        gpo_minus = gpo - 1
        #generatorWitnessCommitment e publicKeyWitnessCommitment
        shares, encrypted_shares, commitmentProducts = [], [], []
        coefficients = [secretnumber] + [secrets.randbelow(gpo_minus) for _ in range(1, t)]
        commitments = [pow(g, coef, gpo) for coef in coefficients]
        
        witnessValue = 11

        data_hash_string = ""
        for i in range(1, n + 1):
            share_value = sum(coef * pow(i, exp, gpo_minus) for exp, coef in enumerate(coefficients)) % gpo_minus
            encrypted_share = pow(public_keys[i - 1], share_value, gpo)
            encrypted_shares.append(encrypted_share)
            shares.append(share_value)

            exp = 1
            mult = commitments[0]
            for j in range(1, t):
                exp = (exp * i) % gpo_minus
                mult = (mult * pow(commitments[j], exp, gpo)) % gpo
            commitmentProducts.append(mult)

            genWC_i = pow(g, witnessValue, gpo)
            pkWC_i = pow(public_keys[i - 1], witnessValue, gpo)

            data_hash_string += str(commitmentProducts[-1]) + str(encrypted_share) + str(genWC_i) + str(pkWC_i)

        data_for_hash = CryptoUtils.to_bytes(int(data_hash_string))
        commitmentproof, sharesproof = self.generate_proofs(data_for_hash, shares, witnessValue)

        return PublishedShares(commitments, encrypted_shares, sharesproof, commitmentproof, encrypted_data)
    
    def generate_proofs(self, data_for_hash, shares, witnessValue):
        gpo = self.public_info.group_prime_order    
        hash_value = CryptoUtils.hash(bytes(data_for_hash))    
        commitmentproof = hash_value % gpo     
        sharesproof = [(witnessValue - share_value * commitmentproof) % gpo for share_value in shares]
        return commitmentproof, sharesproof    

    def general_combine_shares(self, shares):
        share_indexs = [share.index for share in shares]
        encrypted_secret = self.combine_shares(share_indexs, shares)
        return CryptoUtils.decrypt(CryptoUtils.to_bytes(encrypted_secret), shares[0].encrypted_text)

    def combine_shares(self, share_indexes, shares):
        gpo = self.public_info.group_prime_order
        reconstructedSecret = 1
        # Pré-calcula os denominadores para cada coeficiente de interpolação
        denominators = []
        for i in range(len(share_indexes)):
            denominator = 1
            for j in range(len(share_indexes)):
                if j != i:
                    denominator *= (share_indexes[i] - share_indexes[j])
            denominators.append(denominator)
        # Calcula os coeficientes de interpolação e usa-os para reconstruir o segredo
        for i in range(len(share_indexes)):
            numerator = 1
            for j in range(len(share_indexes)):
                if j != i:
                    numerator *= (share_indexes[j] + 1)
            interpolationCoeff = Fraction(numerator, denominators[i]).numerator // Fraction(numerator, denominators[i]).denominator
            reconstructedSecret *= pow(shares[i].share, interpolationCoeff, gpo)
            reconstructedSecret %= gpo

        return reconstructedSecret

class PVSSSplitCombine:
    def __init__(self, n, t ):
        self.n = n
        self.t = t
        self.group_prime_order = 0
        self.g1 = 0
        self.g2 = 0
   
    def pvss_split(self, secretdata):
        self.group_prime_order = CryptoUtils.generate_probable_prime()
        self.g1 = CryptoUtils.generate_probable_prime()
        self.g2 = CryptoUtils.generate_probable_prime()
        
        pi = PublicInfoPVSS(self.n, self.t, self.group_prime_order, self.g1, self.g2)
        engine = PVSSEngine(pi)
        
        secret_keys = engine.generate_secret_keys(self.n)
        public_keys = [engine.generate_public_key(sk) for sk in secret_keys]
        published_shares = engine.general_publish_shares(secretdata.encode(), public_keys)
        
        shares = {
            i: base64.b64encode(CryptoUtils.to_bytes(published_shares.get_share(i, secret_keys[i], pi, public_keys).share)).decode('utf-8')
            for i in range(self.n)
        }

        encoded_encr_data= base64.b64encode(published_shares.encrypted_text).decode('utf-8')

        encoded_gpo = base64.b64encode(CryptoUtils.to_bytes(self.group_prime_order)).decode('utf-8')

        #TODO Incluir as provas, quando necessário

        return ExternalShares(shares, encoded_gpo, encoded_encr_data)

    def pvss_combine(self, external_shares):        
        decode_gpo_bytes = base64.b64decode(external_shares.modulus)
        decoded_gpo = int.from_bytes(decode_gpo_bytes, byteorder='big')
        
        pi = PublicInfoPVSS(self.n, self.t, decoded_gpo, self.g1, self.g2)
        engine = PVSSEngine(pi)

        encrypted_text = base64.b64decode(external_shares.encrypted_text)
        
        shares = [None] * len(external_shares.shares)

        for i_str, encoded_share in external_shares.shares.items():
            i = int(i_str) 
            encoded_share_bytes = base64.b64decode(encoded_share)
            share_value = int.from_bytes(encoded_share_bytes, byteorder='big')
            shares[i] = Share(index=i, encrypted_share=None, share=share_value, encrypted_text=encrypted_text)
            
        secret = engine.general_combine_shares(shares)

        return secret.decode()



def pvss_split(n, k, data): 

    psc = PVSSSplitCombine(n, k)

    external_shares = psc.pvss_split(data)

    shares = []

    for index in external_shares.shares:
        shares.append({
           "x": index,
           "y": external_shares.shares[index]
       })

    secret_share = {
        "encrypted_text": external_shares.encrypted_text,
        "modulus": external_shares.modulus,
        "shares": shares
    }

    return secret_share

def pvss_combine(n, k, secret_share):     

    psc = PVSSSplitCombine(n, k)

    shares = {}

    for share in secret_share["shares"]:
        shares.update({share["x"]:share["y"]})

    external_shares = ExternalShares(shares, secret_share["modulus"], secret_share["encrypted_text"])

    secret = psc.pvss_combine(external_shares)

    return secret
