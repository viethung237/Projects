
from aes import AES, long_to_bytes, bytes_to_long, _copy_bytes
from binascii import hexlify, unhexlify
import struct
from PIL import Image
import math
class CCMmode(object):
    def __init__(self, key, nonce, assoc, mac_len) -> None:
        self._block_size: int = 16
        """The block size of the underlying cipher, in bytes."""

        self._key: bytes = key
        self._nonce: bytes = nonce
        self._assoc: bytes = assoc
        #none and associated data for cipher instance
        self._mac_len: int = mac_len
        self._assoc_len: int = len(assoc)

        #block size value
        if self._block_size != 16:
            raise ValueError("CCM mode is only available for ciphers"
                             " that operate on 128 bits blocks")

        # MAC tag length (Tlen)
        if mac_len not in (4, 6, 8, 10, 12, 14, 16):
            raise ValueError("Parameter 'mac_len' must be even"
                             " and in the range 4..16 (not %d)" % mac_len)

        # Nonce value
        if not (nonce and 7 <= len(nonce) <= 13):
            raise ValueError("Length of parameter 'nonce' must be"
                             " in the range 7..13 bytes")


    def _xor(self, a: bytes, b: bytes) -> bytes:
        return bytes([x ^ y for x, y in zip(a, b)])

    #pad/unpad bit '0' to full of block
    def _pad(self, data: bytes) -> bytes:
        padding_length: int = self._block_size - (len(data) % self._block_size)
        padding: bytes = b'\x00' * padding_length
        return data + padding

    def _unpad(self, data: bytes) -> bytes:
        padding_length: int = data[-1]
        return data[:-padding_length]


    #aes encrypt & decrypt, use in cmac
    def _aes_encrypt(self, block: bytes) -> bytes:
        key = AES(self._key)
        return key.encrypt(block)

    def _aes_decrypt(self, block: bytes) -> bytes:
        key = AES(self._key)
        return key.decrypt(block)

    #CTR cipher, by formatting the counter (A.3)
    #ctr = len(msg) || nonce || counter
    def ctr_gen(self, count: int) -> bytes:
        s: bytes = b''
        #generate CTR and encrypt ctr
        for i in range(count + 1):
            
            ctr_i: bytes = struct.pack('B', self.q - 1) + self._nonce + long_to_bytes(i, self.q)
            s_i: bytes = self._aes_encrypt(ctr_i)
            s += s_i
        return s
            

    #encrypt func
    def encrypt(self, msg: bytes) -> bytes:
        self._msg: bytes = msg
        self._msg_len: int = len(msg)
        
        #generate tag of the msg
        _tag: bytes = self.mac_gen(self._msg)
        #CTR cipher
        s: bytes = self.ctr_gen(math.ceil(len(msg) / 16))
        _s: bytes = s[self._block_size:]

        cp: bytes = self._xor(msg, _s[:self._msg_len]) + self._xor(_tag, (s[:self._block_size])[:self._mac_len])
        return cp       
    
    def verify(self, ciphertext: bytes) -> bytes:
        self._ciphertext: bytes = ciphertext
        self._len_cp: int = len(ciphertext)

        #check cipher length & mac length
        if self._len_cp < self._mac_len:
            raise ValueError('mac length is not greater than cipher length')

        #CTR cipher
        s: bytes = self.ctr_gen(math.ceil((self._len_cp - self._mac_len) / 16) +16)
        S = s[self._block_size:]

        #received plaintext
        pt = self._xor(self._ciphertext[:self._len_cp - self._mac_len], S[:self._len_cp - self._mac_len])

        #compare new tag and initial tag
        self._t = self._xor(self._ciphertext[-self._mac_len:], s[:self._mac_len])
        _tag = self.mac_gen(pt)
        if self._t != _tag:
            raise ValueError('tag after generate is not equal to initial tag')
        else:
            return pt, 'valid'



    def mac_gen(self, text) -> bytes:
        # Formatting control information and nonce
        self.q:int = 15 - len(self._nonce)  # length of Q, the encoded message length


        flags: int = (64 * (self._assoc_len > 0) + 8 * ((self._mac_len - 2) // 2) +      \
                 (self.q - 1))
        # b_0 and assoc_len_encoded
        b_0:bytes = struct.pack("B", flags) + self._nonce + long_to_bytes(len(text), self.q)

        # Formatting associated data
        # Encoded 'a' is concatenated with the associated data 'A'
        assoc_len_encoded = b''
        if self._assoc_len > 0:
            if self._assoc_len < (2 ** 16 - 2 ** 8):
                enc_size = 2
            elif self._assoc_len < (2 ** 32):
                assoc_len_encoded = b'\xFF\xFE'
                enc_size = 4
            else:
                assoc_len_encoded = b'\xFF\xFF'
                enc_size = 8
            assoc_len_encoded += long_to_bytes(self._assoc_len, enc_size)
        assoc_len_encoded = self._pad(assoc_len_encoded + self._assoc)
        
        msg_pad = self._pad(text)
        b = assoc_len_encoded + msg_pad
        
        #CMAC
        pre_block = self._aes_encrypt(b_0)
        for i in range(0, len(b), self._block_size):
            pre_block = self._aes_encrypt(self._xor(b[i: i + self._block_size], pre_block))
        _tag = pre_block[:self._mac_len]
        return _tag




#test_vector
"""
key1 = unhexlify('404142434445464748494a4b4c4d4e4f')
key2 = unhexlify('414142434445464748494a4b4c4d4e4f')

nonce = unhexlify('101112131415161718191a1b')
mac_len = 16
assoc = unhexlify('000102030405060708090a0b0c0d0e0f10111213')
#msg = b''
img = Image.open('D:\SIP_LAP_Project\Security_System\security_system\lena_img.jpg')
msg1 = img.tobytes()
msg2 = bytearray(msg1)
msg2[-1] += 1
msg2 = bytes(msg2)
ccm1 = CCMmode(key1, nonce, assoc, mac_len)
cp1 = ccm1.encrypt(msg1)
cp2 = ccm1.encrypt(msg2)
index1 = []
index1_u =[]
cp1 = bin(bytes_to_long(cp1))[2:]
for i in range(0,len(cp1),8):
    index1.append(cp1[i:i+8])
for i in index1:
    index1_u.append(int(i,2))
cp2 = bin(bytes_to_long(cp2))[2:]
index2 = []
index2_u =[]
for i in range(0,len(cp2),8):
    index2.append(cp2[i:i+8])
for i in index2:
    index2_u.append(int(i,2))
s_u = 0
for i in range(len(index1_u)):
    s_u += abs(index1_u[i] - index2_u[i])
print(s_u/(255*len(index1_u)))
print(s_u)
print(len(index1))
print(cp1)
#print(s/len(index1))
"""



"""
ccm1 = CCMmode(key1, nonce, assoc, mac_len)
cp1 = ccm1.encrypt(msg)
ccm2 = CCMmode(key2, nonce, assoc, mac_len)
cp2 = ccm2.encrypt(msg)
cp1 = bin(bytes_to_long(cp1))[2:]
index1 = []
index1_u =[]
for i in range(0,len(cp1),8):
    index1.append(cp1[i:i+8])
for i in index1:
    index1_u.append(int(i,2))
cp2 = bin(bytes_to_long(cp2))[2:]
index2 = []
index2_u =[]
for i in range(0,len(cp2),8):
    index2.append(cp2[i:i+8])
for i in index2:
    index2_u.append(int(i,2))
s = 0
s_u = 0
for i in range(len(index1)) :
    if index1[i]!= index2[i]:
        s+=1
for i in range(len(index1_u)):
    s_u += abs(index1_u[i] - index2_u[i])
#print(s/len(index1))

print(s_u/(255*len(index1_u)))
"""



key = unhexlify('404142434445464748494a4b4c4d4e4f')

nonce = unhexlify('101112131415161718191a1b')
mac_len = 16
assoc = unhexlify('000102030405060708090a0b0c0d0e0f10111213')
#msg = b''
img = Image.open('non_Dicom_image.jpg')
msg1 = img.tobytes()
ccm = CCMmode(key, nonce, assoc, mac_len)
cp1 = bytearray(ccm.encrypt(msg1))
msg2 = bytearray(msg1)
msg2[-1] += 1
msg2 = bytes(msg2)
cp2  = bytearray(ccm.encrypt(msg2))
cp1_u =[]
for i in cp1 :
    cp1_u.append(bin(i)[2:])
cp2_u=[]
for j in cp2 :
    cp2_u.append(bin(j)[2:])
t = 0
for i in range(len(cp1_u)):
    if cp1_u[i] == cp2_u[i]:
        t += 1

    else :
        t+= 0
print(t/len(cp1_u))
s = 0
print(cp1 == cp2)
for i in range(10):
    print(cp1[i],cp2[i])
    
    #s+= abs(cp1[i] - cp2[i])/255 
#print(s)
"""
pt, _ = ccm.verify(cp)

img_copy = Image.frombytes(img.mode, img.size, pt)

# Save the copy to a new file
img_copy.save('image_copy.jpg')
"""