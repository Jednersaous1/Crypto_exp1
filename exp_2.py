from collections import Counter

def xor_decrypt(ciphertext, key):
    return bytes([c ^ key[i % len(key)] for i, c in enumerate(ciphertext)])

def calculate_ic(text):
    n = len(text)
    freqs = Counter(text)
    ic = sum(f * (f - 1) for f in freqs.values()) / (n * (n - 1)) if n > 1 else 0
    return ic

def find_key_length(ciphertext, max_key_len=40):
    ic_values = []
    for key_len in range(1, max_key_len + 1):
        segments = [ciphertext[i::key_len] for i in range(key_len)]
        ic = sum(calculate_ic(segment) for segment in segments) / key_len
        ic_values.append((key_len, ic))
    likely_key_length = max(ic_values, key=lambda x: x[1])[0]
    return likely_key_length

def find_key(ciphertext, key_length):
    key = bytearray()
    for i in range(key_length):
        segment = ciphertext[i::key_length]
        freq = Counter(segment)
        most_common_byte, _ = freq.most_common(1)[0]
        key_byte = most_common_byte ^ ord(' ')
        key.append(key_byte)
    return bytes(key)

def main():
    # Example ciphertext (replace with your actual data)
    ciphertext = bytes.fromhex('3b101c091d53320c000910')

    print("Cracking the ciphertext...")
    
    # Step 1: Determine likely key length
    key_length = find_key_length(ciphertext)
    print(f"Likely key length: {key_length}")
    
    # Step 2: Determine the key
    key = find_key(ciphertext, key_length)
    print(f"Recovered key: {key.hex()}")

    # Step 3: Decrypt the ciphertext
    plaintext = xor_decrypt(ciphertext, key)
    print(f"Decrypted plaintext: {plaintext.decode('utf-8', errors='ignore')}")

if __name__ == "__main__":
    main()
