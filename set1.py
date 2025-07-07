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
    "E": 12.02, "T": 9.10, "A": 8.12, "O": 7.68, "I": 7.31, "N": 6.95, "S": 6.28, "R": 6.02, "H": 5.92,
    "D": 4.32, "L": 3.98, "U": 2.88, "C": 2.71, "M": 2.61, "F": 2.30, "Y": 2.11, "W": 2.09, "G": 2.03,
    "P": 1.82, "B": 1.49, "V": 1.11, "K": 0.69, "X": 0.17, "Q": 0.11, "J": 0.10, "Z": 0.07
}

freq = " ETAOINSHRDLCUMWFGYPBVKJXQZ"

def reverse_dict(d):
    return {v: k for k, v in d.items()}

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
    occurances = get_character_occurances(text)

    score = 0
    total_chars = len(text)
    for char, n in occurances.items():
        if char in character_frequencies:
            expected_occurance = (character_frequencies[char] / 100) * total_chars
            score += 1 - (abs(expected_occurance - n * total_chars) / expected_occurance)
        elif ord(char) < 32 or ord(char) > 126:
            score += n / total_chars

    return score 

def get_character_occurances(text):
    occurances = {}
    for char in text:
        if char in occurances:
            occurances[char] += 1
        else:
            occurances[char] = 1
    return occurances

def xor_single_byte(byte_list, byte):
    return bytes([byte2 ^ byte for byte2 in byte_list])

def best_decryption(byte_list):
    decoded = [xor_single_byte(byte_list, i).decode(errors="ignore") for i in range(128)]
    return max(decoded, key=lambda x: score_text(x))

def get_key_for_best_decryption(byte_list):
    scores_key = [(score_text(xor_single_byte(byte_list, key).decode()), key) for key in range(128)]
    return max(scores_key, key=lambda x: x[0])[1]

def print_all_decryptions_with_score(byte_list):
    decoded = [xor_single_byte(byte_list, i).decode() for i in range(128)]
    for dec in sorted(decoded, key=lambda x: score_text(x), reverse=True):
        print(dec, score_text(dec))

def find_single_bit_encrypted_string():
    with open("4.txt", "r") as f:
        lines = f.readlines()
    return [best_decryption(bytes.fromhex(line.rstrip())) for line in lines]

def repeating_key_encrypt(key, message, encoding):
    i = 0
    out_bytes = []
    if type(message) is not bytes:
        message_bytes = bytes(message, encoding)
    else:
        message_bytes = message
    while i < len(message):
        for byte in bytes(key, encoding):
            if i >= len(message):
                break
            out_bytes.append(byte ^ message_bytes[i])
            i += 1
    return bytes(out_bytes)

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

def decrypt_repeating_key(byte_list):
    string = byte_list.decode()
    p_keys = probable_keys(string, 5)
    keys = []
    for p_key, _ in p_keys:
        blocks = transpose_blocks(bytes(string, "utf-8"), p_key)
        block_keys = []
        for block in blocks:
            block_keys.append(chr(get_key_for_best_decryption(block)))
        keys.append("".join(block_keys))
    return keys
    
if __name__ == '__main__':
    results = find_single_bit_encrypted_string()
    for result in sorted(results, key=lambda x: x[0][1], reverse=True):
        print(result)
