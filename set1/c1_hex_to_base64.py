#!/usr/bin/python3

# Cryptopals Challenges
# Set 1, Challenge 1
# Convert a hex string into a base64 string

import base64

x = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

y = base64.b64encode(bytes.fromhex(x))  # returns a bytes object

print(y.decode())
