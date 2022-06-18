#!/usr/bin/python3

# Cryptopals Challenges
# Set 1, Challenge 3
# Work out the key for XORing a particular hex string to decrypt the message.
# The string is:
#   1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
# The decrypted text is:
#   "Cooking MC's like a pound of bacon"
# achieved with a key of 0x58.

text_enc = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

def xor(x, y):
    return hex(int(x, 16) ^ int(y, 16))

def singleByteCipher(text, key):
    # create the cipher by duplicating the key character to be as long as text
    key_byte_count = len(text) // 2 + len(text) % 2
    cipher = key_byte_count * key[2:] # drop the '0x' part of the key string
    # xor each byte to decrypt text: this will be in hex
    text_dec = xor(text, cipher)
    text_dec = text_dec[2:] # drop the '0x' at the start
    # try to convert the output to characters
    try:
        output = bytes.fromhex(text_dec)
    except ValueError:
        output = b'0'
    return output

for c in range(0x00, 0xff):
    print("{0:3d}. [0x{1:02x}]".format(c, c), end=' ')
    print(singleByteCipher(text_enc, hex(c)))
