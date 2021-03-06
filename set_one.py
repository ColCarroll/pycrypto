import base64
import binascii
from collections import Counter
import itertools
import os
from Crypto.Cipher import AES

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
CORPUS = os.path.join(DATA_DIR, 'idleness.txt')


def hex_to_base64(hex_str):
    return base64.b64encode(binascii.unhexlify(hex_str)).decode('ascii')


def fixed_xor(hex_str, key):
    x, y = binascii.unhexlify(hex_str), binascii.unhexlify(key)
    return binascii.hexlify(bytes([a ^ b for a, b in zip(x, y)])).decode('ascii')


def _get_english_scorer():
    with open(CORPUS, 'rb') as buff:
        counts = Counter(buff.read())
    return counts


def single_byte_xor(array, byte):
    return bytes([j ^ byte for j in array])


def break_single_byte_xor(array, scorer=_get_english_scorer()):
    if not isinstance(array, bytes):
        array = binascii.unhexlify(array)
    best_score = 0
    best_candidate = b''
    for byte in range(128):
        xord = single_byte_xor(array, byte)
        score = sum(scorer[j] for j in xord)
        if score > best_score:
            best_score = score
            best_candidate = xord
    return best_candidate, best_score


def challenge_four():
    scorer = _get_english_scorer()
    best_score = 0
    best_candidate = ""
    with open(os.path.join(DATA_DIR, '4.txt'), 'r') as buff:
        for row in buff:
            candidate, score = break_single_byte_xor(row.strip(), scorer)
            if score > best_score:
                best_score = score
                best_candidate = candidate
    return best_candidate


def repeating_key_xor(string, key):
    generators = [bytes(string, 'ascii'), itertools.cycle(bytes(key, 'ascii'))]
    return binascii.hexlify(bytes([b ^ k for b, k in zip(*generators)]))


def bit_sum(integer):
    return sum((integer >> j) & 1 for j in range(integer.bit_length()))


def byte_distance(a, b):
    return sum(bit_sum(j ^ k) for j, k in zip(a, b))


def hamming_distance(string_one, string_two):
    return byte_distance(bytes(string_one, 'ascii'), bytes(string_two, 'ascii'))


def block_bytes(iterable, size):
    blocks = [iterable[j:j + size] for j in range(0, len(iterable), size)]
    missing = size - len(blocks[-1])
    blocks[-1] += b'\x00' * missing
    return blocks


def _b64_file(filename):
    with open(filename, 'rb') as buff:
        data = base64.b64decode(buff.read().strip())
    return data


def _data(problem_number):
    return _b64_file(os.path.join(DATA_DIR, '{}.txt'.format(problem_number)))


def repeating_xor_keysize(data_bytes=_data(6), n_blocks=4):
    best_key, best_distance = 0, 8
    for size in range(2, 40):
        distance = 0
        tot = 0
        for a, b in itertools.combinations(block_bytes(data_bytes, size)[:n_blocks], 2):
            distance += byte_distance(a, b) / size
            tot += 1
        distance /= tot
        if distance < best_distance:
            best_distance = distance
            best_key = size
    return best_key


def break_repeating_key_xor(data_bytes=_data(6)):
    scorer = _get_english_scorer()
    key_size = repeating_xor_keysize(data_bytes)
    transposed = map(bytes, zip(*block_bytes(data_bytes, key_size)))
    decrypted = [break_single_byte_xor(encrypted, scorer)[0] for encrypted in transposed]
    return b''.join(bytes(j) for j in zip(*decrypted))


def decrypt_aes_ecb(ciphertext=_data(7), key='YELLOW SUBMARINE'):
    return AES.new(key, AES.MODE_ECB).decrypt(ciphertext)


def _eight_data():
    data = []
    with open(os.path.join(DATA_DIR, '8.txt'), 'r') as buff:
        for row in buff:
            data.append(binascii.unhexlify(row.strip()))
    return data


def detect_aes_ecb(data_bytes=_eight_data()):
    min_count = float('inf')
    aes_row = ''
    for row in data_bytes:
        byte_count = len(Counter(row).keys())
        if byte_count < min_count:
            min_count = byte_count
            aes_row = binascii.hexlify(row)
    return aes_row
