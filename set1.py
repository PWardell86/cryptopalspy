from math import ceil
import base64

int_to_b64 = {
    0: "A", 1: "B", 2: "C", 3: "D", 4: "E", 5: "F", 6: "G", 7: "H",
    8: "I", 9: "J", 10: "K", 11: "L", 12: "M", 13: "N", 14: "O", 15: "P",
    16: "Q", 17: "R", 18: "S", 19: "T", 20: "U", 21: "V", 22: "W", 23: "X",
    24: "Y", 25: "Z", 26: "a", 27: "b", 28: "c", 29: "d", 30: "e", 31: "f",
    32: "g", 33: "h", 34: "i", 35: "j", 36: "k", 37: "l", 38: "m", 39: "n",
    40: "o", 41: "p", 42: "q", 43: "r", 44: "s", 45: "t", 46: "u", 47: "v",
    48: "w", 49: "x", 50: "y", 51: "z", 52: "0", 53: "1", 54: "2", 55: "3",
    56: "4", 57: "5", 58: "6", 59: "7", 60: "8", 61: "9", 62: "+", 63: "/"
}

character_frequencies = {
    " ": 13, "E": 12.02, "T": 9.10, "A": 8.12, "O": 7.68, "I": 7.31, "N": 6.95, "S": 6.28, "R": 6.02, "H": 5.92,
    "D": 4.32, "L": 3.98, "U": 2.88, "C": 2.71, "M": 2.61, "F": 2.30, "Y": 2.11, "W": 2.09, "G": 2.03,
    "P": 1.82, "B": 1.49, "V": 1.11, "K": 0.69, "X": 0.17, "Q": 0.11, "J": 0.10, "Z": 0.07
}


def encode_n_bits(l_bytes: bytes, n: int) -> list:
    n_bit_sum = 0
    every_n = 0
    sums = []
    bits = []
    for byte in l_bytes:
        for i in range(8):
            bit = ((byte << i) & 128) >> 7
            bits.append(bit)
    for bit in bits:
        n_bit_sum = n_bit_sum << 1 | bit
        every_n += 1
        if every_n == n:
            sums.append(int_to_b64[n_bit_sum])
            n_bit_sum = 0
            every_n = 0
    return sums

def b64encode(l_bytes: bytes) -> str:
    return ''.join(encode_n_bits(l_bytes, 6))

def hex_to_b64(hex_str: str) -> str:
    return b64encode(bytes.fromhex(hex_str))

def xor_buffers(buffer1, buffer2):
    bytes1 = bytes.fromhex(buffer1)
    bytes2 = bytes.fromhex(buffer2)
    return bytes([byte1 ^ byte2 for byte1, byte2 in zip(bytes1, bytes2)]).hex()

def score_text(text):
    score = 0
    freq = {}
    for char in text:
        if char in freq:
            freq[char] += 1
        else:
            freq[char] = 1
    for key in freq:
        freq[key] = freq[key] / len(text) * 100
    
    for key in freq:
        try:
            if key.upper() in character_frequencies:
                score += abs(character_frequencies[key.upper()] - freq[key])
            # Account for non-letter characters, and penalize them greater if they aren't 
            # punctuation or whitespace or stuff
            elif ord(key) < 32 or ord(key) > 126:
                score += 150
            else:
                score += 50
        except TypeError:
            score += 100000
    return score

def xor_single_byte(byte_list, byte):
    return bytes([byte2 ^ byte for byte2 in byte_list])

def highest_scoring_decryption(byte_list):
    decoded = [xor_single_byte(byte_list, i).decode(errors="ignore") for i in range(128)]
    least_error = min(decoded, key=lambda x: score_text(x))
    return least_error

def print_all_decryptions_with_score(byte_list):
    decoded = [xor_single_byte(byte_list, i).decode(errors="ignore") for i in range(128)]
    for dec in sorted(decoded, key=lambda x: score_text(x), reverse=True):
        print(dec, score_text(dec))

def find_single_bit_encrypted_string():
    with open("4.txt", "r") as f:
        lines = f.readlines()
    return [highest_scoring_decryption(line.rstrip()) for line in lines]

def repeating_key_encrypt(key, message, encoding):
    i = 0
    out_bytes = []
    message_bytes = bytes(message, encoding)
    # print(i, len(message))
    while i < len(message):
        for byte in bytes(key, encoding):
            if i >= len(message):
                break
            out_bytes.append(byte ^ message_bytes[i])
            i += 1
    return bytes(out_bytes).hex()

def hamming_distance(string1, string2):
    dist = 0
    bits1 = bit_array(bytes(string1, "utf-8"))
    bits2 = bit_array(bytes(string2, "utf-8"))
    smaller = min(len(bits1), len(bits2))
    larger = max(len(bits1), len(bits2))
    for i in range(smaller):
        dist += 1 if bits1[i] != bits2[i] else 0
    
    return dist + larger - smaller
    
def bit_array(byte_list):
    bits = []
    for byte in byte_list:
        for i in range(8):
            bits.append(((byte << i) & 128) >> 7)
    return bits
            
def probable_keys(message, n_keys):
    key_sizes = range(2, 41)
    normal_dists = []
    for key_size in key_sizes:
        ham_dist_1 = hamming_distance(message[:key_size], message[key_size:2*key_size])
        ham_dist_2 = hamming_distance(message[2*key_size:3*key_size], message[3*key_size:4*key_size])
        normal_dists.append((key_size, (ham_dist_1 + ham_dist_2) / (2* key_size)))
    
    return sorted(normal_dists, key=lambda x: x[1])[:n_keys]
    
def transpose_blocks(byte_list, key_size):
    blocks = ceil(len(byte_list) / key_size)
    transposed_blocks = [bytearray() for _ in range(blocks)]
    i = 0
    for byte in byte_list:
        if i >= blocks:
            i = 0
        transposed_blocks[i].append(byte)
        i += 1
    return transposed_blocks

def decrypt_repeating_key(string):
    p_keys = probable_keys(string, 10)
    keys = []
    for p_key, _ in p_keys:
        blocks = transpose_blocks(bytes(string, "utf-8"), p_key)
        block_keys = []
        for block in blocks:
            block_keys.append(highest_scoring_decryption(block))
        keys.append("".join(block_keys))
    return keys
    
if __name__ == '__main__':
    # print(hex_to_b64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
    # print(xor_buffers("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))
    # print(highest_scoring_decryption("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
    # print(print_all_decryptions_with_score("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"))
    # results = find_single_bit_encrypted_string()
    # for result in sorted(results, key=lambda x: x[0][1], reverse=True):
    #     print(result)
    # print('\n'.join(find_single_bit_encrypted_string()))
    s = "Despite the expensive reconstructions, both vessels were considered obsolescent by the eve of World War II, and neither saw significant action in the early years of the war. In 1944 both underwent upgrades to their anti-aircraft suite before transferring to Singapore. Fuso and Yamashiro were the only two Japanese battleships at the Battle of Surigao Strait, the southernmost action of the Battle of Leyte Gulf, and both were lost in the early hours of 25 October 1944 to torpedoes and naval gunfire."
    encrypted = repeating_key_encrypt("8o7werionwdvp983-89", s, "utf-8")


    # print(encrypted)
    encrypted_string = bytes.fromhex(encrypted).decode("utf-8")
    # print(encrypted_string)
    # print(probable_keys(encrypted_string, 5))

    print(print_all_decryptions_with_score(bytes(encrypted, "utf-8")))
    # for key in decrypt_repeating_key(encrypted_string):
    #     print(key)
    # print(decrypt_repeating_key(encrypted_string))
    # with open("6.txt", "r") as file:
    #     b64 = file.read()
    #     print(highest_scoring_decryption(base64.b64decode(b64)))
