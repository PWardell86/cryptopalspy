import set1
from random import randbytes
from tqdm import tqdm 

def assert_equal(expected, actual):
    if (expected != actual):
        print(f"Expected did not equal actual.\nExpected: {expected}\nActual: {actual}")

def test_challenge5():
    expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    key = "ICE"
    message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    actual = set1.repeating_key_encrypt(key, message, "utf-8")
    for i in range(len(actual)):
        if actual[i] != expected[i]:
            print((actual[i], expected[i], i, message[i // 2 - 2: i//2 + 2]))

    assert_equal(expected, actual)

def test_hamming_distance():
    expected = 37
    actual = set1.hamming_distance("this is a test", "wokka wokka!!!")
    assert_equal(expected, actual)

def test_probable_keys():
    key_lengths = range(2, 41)
    message_length = 20
    n_random_strings = range(10)
    correct = 0
    message = randbytes(message_length).decode("utf-8")
    for key_length in tqdm(key_lengths):
        key = randbytes(key_length).decode("utf-8", errors="ignore")
        encrypted_string = set1.repeating_key_encrypt(key, message, "utf-8")
        p_keys = [p_key for p_key, _ in set1.probable_keys(encrypted_string, 10)]
        if key_length in p_keys:
            correct += 1
    frac_correct = correct / (len(key_lengths) * 40 * len(n_random_strings))
    print(f"probable_keys() error: {100 * (1 - frac_correct)}%")

test_set = [
    test_challenge5,
    test_hamming_distance,
    test_probable_keys
]

if __name__ == "__main__":
    for test in test_set:
        test()
        