from nose.tools import assert_equal

from set_one import hex_to_base64, fixed_xor, break_single_byte_xor, challenge_four,\
    repeating_key_xor, hamming_distance, bit_sum, repeating_xor_keysize, break_repeating_key_xor


def test_challenge_one():
    hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f6"\
        "9736f6e6f7573206d757368726f6f6d"
    base64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert_equal(hex_to_base64(hex_str), base64_str)


def test_challenge_two():
    hex_str = "1c0111001f010100061a024b53535009181c"
    key = "686974207468652062756c6c277320657965"
    expected = "746865206b696420646f6e277420706c6179"
    calculated = fixed_xor(hex_str, key)
    assert_equal(calculated, expected)


def test_challenge_three():
    hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    expected = "Cooking MC's like a pound of bacon"
    calculated, _ = break_single_byte_xor(hex_str)
    assert_equal(calculated.decode('ascii'), expected)


def test_challenge_four():
    calculated = challenge_four()
    assert_equal(calculated.decode('ascii'), "Now that the party is jumping\n")


def test_challenge_five():
    string_to_encrypt = '''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''
    key = 'ICE'
    encrypted = repeating_key_xor(string_to_encrypt, key).decode('ascii')
    expected = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272'\
               'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    assert_equal(encrypted, expected)


def test_challenge_six():
    assert_equal(bit_sum(8), 1)
    assert_equal(bit_sum(9), 2)
    assert_equal(bit_sum(15), 4)
    assert_equal(hamming_distance('this is a test', 'wokka wokka!!!'), 37)
    assert_equal(repeating_xor_keysize(), 29)
    decrypted = break_repeating_key_xor()
    print(decrypted.decode('ascii'))
