def xor_decrypt(ciphertext, key):
    key_bytes = bytes.fromhex(key)
    key_length = len(key_bytes)
    ciphertext_bytes = bytes.fromhex(ciphertext)
    
    plaintext = bytearray()
    
    for i in range(len(ciphertext_bytes)):
        plaintext.append(ciphertext_bytes[i] ^ key_bytes[i % key_length])
    
    return plaintext.decode(errors='ignore')


cipher_text = "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070"

key_hex = "66396e89c9dbd8cb9874352acd6395102eafce78aa7fed28a006bc98d29c5b69b0339a19f8aa401a9c6d708f80c066c763fef0123148cdd8e82d05ba98777335daefcecd59c433a6b268b60bf4ef03c9a61100bb09a3161edc704a3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

plain_text = xor_decrypt(ciphertext = cipher_text, key = key_hex)
print(plain_text)