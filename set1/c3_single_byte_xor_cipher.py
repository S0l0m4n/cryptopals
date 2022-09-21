#!/usr/bin/python3

# Cryptopals Challenges
# Set 1, Challenge 3
# Work out the key for XORing a particular hex string to decrypt the message.
# The string is:
#   1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
# The decrypted text is:
#   "Cooking MC's like a pound of bacon"
# achieved with a key of 0x58.

MIN_ALPHA = 65  # ord('A') = 65
MAX_ALPHA = 122 # ord('z') = 122

text_enc = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

def xor(x, y):
    return hex(int(x, 16) ^ int(y, 16))

# Usage: singleByteCipherHex("1b3737", '0x50') = '4b6767'
def singleByteCipherHex(text, key):
    # create the cipher by duplicating the key character to be as long as text
    key_byte_count = len(text) // 2 + len(text) % 2
    cipher = key_byte_count * key[2:] # drop the '0x' part of the key string
    # xor each byte to decrypt text: this will be in hex
    text_dec = xor(text, cipher)
    return text_dec[2:] # drop the '0x' at the start

# Usage: splitHexIntoArray("4b6767") = [75, 103, 103]
def splitHexIntoIntArray(x):
    return [ int(x[i:i+2],16) for i in range(0, len(x), 2) ]

# Usage: [*mapIsAlphaOverIntArray([75, 123, 103])] = [True, False, True]
def mapIsAlphaOverIntArray(hex_array):
    return map(lambda x: (MIN_ALPHA <=x) and (x <= MAX_ALPHA), hex_array)

def printHexAsByteString(hex_output):
    try:
        byte_string = bytes.fromhex(hex_output)
    except ValueError: 
        byte_string = b'0'
    return byte_string

for c in range(0x00, 0xff):
    print("{0:3d}. [0x{1:02x}]".format(c, c), end=' ')
    # encrypt the text with single-byte XOR cipher
    hex_output = singleByteCipherHex(text_enc, hex(c))
    hex_array = splitHexIntoIntArray(hex_output)
    # count how many alphabetical characters in the text
    # NB: we use `list` because otherwise the map object will be consumed
    alpha_list = list(mapIsAlphaOverIntArray(hex_array))
    # reveal sum of alphabetical characters in the text
    # NB: `sum` can add boolean values
    print("#alpha = {} {}".format(
        sum(alpha_list), printHexAsByteString(hex_output)))
