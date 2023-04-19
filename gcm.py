import aes
import struct
import binascii
import math
from PIL import Image



#input data
'''
plaintext: P
AAD: A
ini_vector ~ nonce: IV  (recommend 96 bit)

GCM: protect A and P
'''

#Output data
'''
ciphertext: C
authencication tag: T
'''

class GCMmode(object):
    def __init__(self, key, IV, A, tag_len) -> None:
        self._key: bytes = key
        self._IV: bytes = IV
        self.len_IV: int = len(IV)

        self._A: bytes = A
        self.len_A: int = len(A)
        self._tag_len: int = tag_len

    #aes encrypt & decrypt, use in cmac
    def _aes_encrypt(self, block: bytes) -> bytes:
        key = aes.AES(self._key)
        return key.encrypt(block)

    def _aes_decrypt(self, block: bytes) -> bytes:
        key = aes.AES(self._key)
        return key.decrypt(block)

    #xor function
    def _xor(self, a: bytes, b: bytes) -> bytes:
        return bytes([x ^ y for x, y in zip(a, b)])
    

    #increment function used in generate counter mode
    def incre_func(self, X: bytes, s: int):
        X = bin(int.from_bytes(X, byteorder='big', signed=False))[2:] # binary string
        lsb_x = (int(X[-s:], 2) + 1) % (2**s)
        lsb_x = format(lsb_x, f'0{s}b')
        inc_s = X[:len(X) - s] + lsb_x
        inc_s = int(inc_s, 2).to_bytes((len(inc_s) + 7) // 8, byteorder='big') # byte string
        return inc_s

    #multiplication operation on block
    def mul(self, x: bytes, y: bytes) -> bytes:
        x = aes.bytes_to_long(x)
        y = aes.bytes_to_long(y)

        R = int('11100001' +'0'*120, 2)
        z = 0
        v = y
        for i in range(0, 128):
            if x & (1 << i):
                z ^= v
            if v & 1:
                v >>= 1
                v ^= R
            else:
                v >>= 1
        return aes.long_to_bytes(z)   

    #GHASH function
    def ghash_func(self, x: bytes, H: bytes) -> bytes:
        y = self.mul(x[0: 16], H)
        for i in range(16, int(len(x)/16)):
            pre = self._xor(x[i: i+16], y)
            y = self.mul(pre, H)
        return y
    
    #GCTR function
    def GCTR(self, icb: bytes, x: bytes):
        n = math.ceil(len(x)/16)
        cb = icb
        cipher = b''
        for i in range(0, n-1):
            cp = self._aes_encrypt(cb)
            y = self._xor(x[16 * i: 16 * i + 16], cp) 
            cb = self. incre_func(cb, 32)
            cipher += y
        cp = (self._aes_encrypt(cb))[:len(x) - 16*(n-1)]
        y_ = self._xor(x[16*(n-1):], cp)
        cipher += y_
        return cipher
    
    #Algorithm for the Authenticated Encryption Function
    def encrypt_gcm(self, P: bytes) -> bytes:
        _hash = self._aes_encrypt(b'\x00' * 16)

        #define block J0
        if len(self._IV) == 12:
            j0 = self._IV + b'\x00'*3+b'\x01'
        else:
            s = 16 * math.ceil(len(self._IV)/16) - len(self._IV)
            j0 = self.ghash_func(self._IV + b'\x00'*(s + 8) + aes.long_to_bytes(len(self._IV), 8), _hash)

        # #mã hóa plaintexts
        cipher = self.GCTR(j0, P)

        #define u and v: lưu độ dài của C: ciphertext và A: additional authen data
        u = 16 * math.ceil(len(cipher)/16) - len(cipher)
        v = 16 * math.ceil(len(self._A)/16) - len(self._A)

        #define a block s as follow
        A_gen = self._A + b'\x00'*v + cipher + b'\x00'*u + aes.long_to_bytes(len(self._A), 8) + aes.long_to_bytes(len(cipher), 8) 
        s = self.ghash_func(A_gen, _hash)
        #tag of the plaintext
        tag = self.GCTR(j0, s)[:self._tag_len]
        return cipher, tag
    
    #authencicated decryption function
    def decrypt_gcm(self, cp: bytes, tag: bytes):
        if len(tag) != self._tag_len:
            print('FAIL')
        _hash = self._aes_encrypt(b'\x00'*16)
        
        #define block j0
        if len(self._IV) == 12:
            j0 = self._IV + b'\x00'*3+b'\x01'
        else:
            s = 16 * math.ceil(len(self._IV)/16) - len(self._IV)
            j0 = self.ghash_func(self._IV + b'\x00'*(s + 8) + aes.long_to_bytes(len(self._IV), 8), _hash)
        
        #find plaintext
        plaintext = self.GCTR(self.incre_func(j0, 32), cp)

        #define u and v: lưu độ dài của C: ciphertext và A: additional authen data
        u = 16 * math.ceil(len(cp)/16) - len(cp)
        v = 16 * math.ceil(len(self._A)/16) - len(self._A)

        #define a block s as follow
        A_gen = self._A + b'\x00'*v + cp + b'\x00'*u + aes.long_to_bytes(len(self._A), 8) + aes.long_to_bytes(len(cp), 8) 
        s = self.ghash_func(A_gen, _hash)

        tag_new = self.GCTR(j0, s)[:self._tag_len]
        print('new: ', tag_new)
        print('old: ', tag)
        if tag_new == tag:
            return plaintext
        else:
            return 'FAIL'
        
#test vector
'''
key = b'sixteen bit key.'
IV = b'12byte nonce'
A = b'hello'
tag_len = 16
msg = b'minhquan iot k65 dai hoc bach khoa ha noi minhquan iot k65 dai hoc bach khoa ha noi minhquan iot k65 dai hoc bach khoa ha noi'

gcm = GCMmode(key, IV, A, tag_len)

cptext, tag = gcm.encrypt_gcm(msg)
print('cp: ', cptext)
pt = gcm.decrypt_gcm(cptext, tag)
print('pt: ', pt)
'''

key = b'sixteen bit key.'
IV = b'12byte nonce'
A = b'hello'
tag_len = 16
#msg = b''
img = Image.open('D:\SIP_LAP_Project\Security_System\security_system\lena_img.jpg')
msg = img.tobytes()
gcm = GCMmode(key, IV, A, tag_len)

cptext, tag = gcm.encrypt_gcm(msg)
#print(cptext)
print(len(msg), len(cptext))
print(cptext+tag)
