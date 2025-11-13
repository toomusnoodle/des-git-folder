import pytest
from des import ascii_to_bits_in_list, pc1_permutation, generate_subkeys, xor_round_substitution, des_encrypt, shifts, bits_to_blocks, create_initialization_vector

# --- ascii_to_bits_in_list tests ---
def test_ascii_to_bits_basic():
    bits = ascii_to_bits_in_list(list("12345678"))
    assert isinstance(bits, list)
    assert all(bit in ["0", "1"] for bit in bits)

def test_ascii_to_bits_padding():
    for x in range(0,100):
        bits = ascii_to_bits_in_list(list(str(x*"*")))
        assert len(bits) % 64 == 0  # Should be multiple of 64

# --- pc1_permutation tests ---
def test_pc1_permutation_length():
    bits = ascii_to_bits_in_list(list("12345678"))
    permuted = pc1_permutation(bits)
    assert len(permuted) == 56

# --- generate_subkeys tests ---
def test_generate_subkeys_length():
    bits = ascii_to_bits_in_list(list("12345678"))
    permuted = pc1_permutation(bits)
    subkeys = generate_subkeys(permuted)
    assert len(subkeys) == 16
    assert all(len(k) == 48 for k in subkeys)

# --- bits_to_blocks tests ---
# that padding works
def test_bits_to_blocks():
    for x in range(0,100):
        bits = ascii_to_bits_in_list(list(x*"*"))
        blocks = bits_to_blocks(bits)
        assert len(blocks[x//8]) == 64  # Blocks should be 64 bits


# --- xor_round_substitution tests ---
def test_xor_round_substitution_type():
    for x in range(0,100):
        bits = ascii_to_bits_in_list(list(x*"*"))
        blocks = bits_to_blocks(bits)
        permuted = pc1_permutation(bits)
        subkeys = generate_subkeys(permuted)
        initialization_vector = create_initialization_vector()
        ciphertext = xor_round_substitution(blocks, subkeys, initialization_vector)
        bits = bin(int(ciphertext, 16))[2:].zfill(len(ciphertext) * 4)
        assert isinstance(bits, str)
        assert len(bits) >= 128 # Tests that final_output is > 128 
        assert len(bits) == (x//8 +2) *64 # Tests that final_output is multiple of 64