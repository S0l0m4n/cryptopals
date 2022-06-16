#!/usr/bin/python3

# Cryptopals Challenges
# Set 1, Challenge 2
# Write a function which takes two fixed-sized buffers and produces their XOR
# combination
# e.g:
#   1c0111001f010100061a024b53535009181c ^ 686974207468652062756c6c277320657965
# = 746865206b696420646f6e277420706c6179

x = "1c0111001f010100061a024b53535009181c"
y = "686974207468652062756c6c277320657965"

def xor(x, y):
    return hex(int(x, 16) ^ int(y, 16))

print(xor(x, y))
