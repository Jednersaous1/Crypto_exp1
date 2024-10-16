import base64
#1

string1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
bytess = bytes.fromhex(string1)
base_res = base64.b64encode(bytess)
print(base_res.decode())

#2

string2 = "1c0111001f010100061a024b53535009181c"
string3 = "686974207468652062756c6c277320657965"
xor_res = bytearray()
for i in range(len(bytes.fromhex(string2))):
    xor_res.append(bytes.fromhex(string2)[i] ^ bytes.fromhex(string3)[i])
print(xor_res.hex())

#3

from collections import Counter

def xor_with_key(ciphertext, key):
    return bytes([b ^ key for b in ciphertext])

def score_plaintext(plaintext):
    frequency = {
        'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
        'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
        'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
        'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
        'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974,
        'z': 0.074, ' ': 13.0
    }

    return sum(frequency.get(chr(byte), 0) for byte in plaintext.lower())

def find_best_key(ciphertext):
    best_score = 0
    best_key = None
    best_plaintext = None

    for key in range(256):
        plaintext = xor_with_key(ciphertext, key)
        score = score_plaintext(plaintext)

        if score > best_score:
            best_score = score
            best_key = key
            best_plaintext = plaintext

    return best_key, best_plaintext

def main():
    hex_ciphertext = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    ciphertext = bytes.fromhex(hex_ciphertext)

    key, plaintext = find_best_key(ciphertext)

    print(f"Best key: {chr(key)} (hex: {key:02x})")
    print(f"Decrypted message: {plaintext.decode('utf-8', errors='ignore')}")

if __name__ == "__main__":
    main()

#4

from operator import itemgetter, attrgetter
latter_frequency = {
    'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .15000
}
def English_Scoring(t):
    return sum([latter_frequency.get(chr(i),0) for i in t.lower()])     

def Single_XOR(s,single_character) :
    t = b''
    for i in s:
        t = t+bytes([i^single_character])
    return t

def ciphertext_XOR(s,single_character) :
    _data = []
    s = bytes.fromhex(s)
    ciphertext = Single_XOR(s,single_character)
    score = English_Scoring(ciphertext)
    data = {
        'Single character' : single_character,
        'ciphertext' : ciphertext,
        'score' : score
    }
    _data.append(data)
    score = sorted(_data, key = lambda score:score['score'], reverse=True)[0]
    return score


if __name__ == '__main__':
    _data = []
    s = open('D:\密码\exp1\\a.txt').read().splitlines()
    for i in s :
        # print(i)
        for j in range(256):
            data = ciphertext_XOR(i,j)
            _data.append(data)
    best_score = sorted(_data, key = lambda score:score['score'], reverse=True)[0]
    print(best_score)
    for i in best_score :
        print("{}: {}".format(i.title(), best_score[i]))

#5

string4 = "Burning 'em, if you ain't quick and nimble"
string5 = "I go crazy when I hear a cymbal"

key1 = "ICE"

def xor_decrypt(ciphertext, key):
    key_bytes = key.encode()
    key_length = len(key_bytes)
    ciphertext_bytes = ciphertext.encode()
    
    plaintext = bytearray()
    
    for i in range(len(ciphertext_bytes)):
        plaintext.append(ciphertext_bytes[i] ^ key_bytes[i % key_length])
    
    return plaintext.hex()

print(xor_decrypt(string4,key1)+xor_decrypt(string5,key1))

#6

import string
import re
from operator import itemgetter, attrgetter
import base64


def English_Scoring(t):
    latter_frequency = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .15000
    }
    return sum([latter_frequency.get(chr(i),0) for i in t.lower()])     

def Single_XOR(s,single_character) :
    t = b''
    for i in s:
        t = t+bytes([i^single_character])

    return t

def ciphertext_XOR(s) :
    _data = []
    for single_character in range(256):
        ciphertext = Single_XOR(s,single_character)
        #print(ciphertext)
        score = English_Scoring(ciphertext)
        data = {
          'Single character' : single_character,
          'ciphertext' : ciphertext,
          'score' : score
        }
        _data.append(data)
    score = sorted(_data, key = lambda score:score['score'], reverse=True)[0]
    # print(score['ciphertext'])
    return score

def Repeating_key_XOR(_message,_key) :
    cipher = b''
    length = len(_key)
    for i in range(0,len(_message)) :
        cipher = cipher + bytes([_message[i]^_key[i % length]])
        # print(cipher.hex())
    return cipher

def hamming_distance(a,b) :
    distance = 0
    for i ,j in zip(a,b) :
        byte = i^j
        distance = distance + sum(k == '1' for k in bin(byte) )
    return distance

def Get_the_keysize(ciphertext) :
    data = []
    for keysize in range(2,41) :
        block = [ciphertext[i:i+keysize] for i in range(0,len(ciphertext),keysize)]
        distances = []
        for i in range(0,len(block),2) :
            try:
                block1 = block[i]
                block2 = block[i+1]
                distance = hamming_distance(block1,block2)
                distances.append(distance / keysize)
            except :
                break
        _distance = sum(distances) / len(distances)
        _data = {
            'keysize' : keysize,
            'distance': _distance
        }
        data.append(_data)
    _keysize = sorted(data, key = lambda distance:distance['distance'])[0]
    # print("123456789456123",_keysize)
    #_keysize = min(data,key = lambda distance:distance['diatance'])
    return _keysize




def Break_repeating_key_XOR(ciphertext):
    
    # Guess the length of the key
    _keysize = Get_the_keysize(ciphertext)
    keysize = _keysize['keysize']
    print(keysize)
    key = b''
    cipher = b''
    block = [ciphertext[i:i+keysize] for i in range(0,len(ciphertext),keysize)]
    for i in range(0 , keysize) :
        new_block = []
        t = b''
        for j in range(0,len(block)-1) :
            s= block[j]
            t=t+bytes([s[i]])
        socre = ciphertext_XOR(t)
        key = key + bytes([socre['Single character']])
        # cipher = cipher + socre['ciphertext']
    # print(cipher)
    for k in range(0,len(block)) :
        cipher = cipher+Repeating_key_XOR(block[k],key)
    # print(key)
    return cipher,key
      # sorted(data, key = lambda distance:distance['distance'])[0]
    
 


if __name__ == '__main__' :
    with open('D:\密码\exp1\\b.txt') as of :
        ciphertext = of.read()
        ciphertext = base64.b64decode(ciphertext)
    cipher,key = Break_repeating_key_XOR(ciphertext)
    print("cipher:",cipher,"\nkey:",key)


