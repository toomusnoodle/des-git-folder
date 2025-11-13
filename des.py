# Global matrix variables, start at 1 when 0 is used in Python lists
# so -1 is done on all called positions

# Initial Permutation (IP)

import os

ip = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

# Final Permutation (FP)
fp = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

# Expansion E (32 → 48 bits)
e = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22,
    23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]

# Permutation P (32 → 32 bits)
p = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
]

# PC-1 (64 → 56 bits)
pc1 = [
    57, 49, 41, 33, 25, 17, 9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38,
    30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4,
]

# PC-2 (56 → 48 bits)
pc2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32,
]

# S-boxes (8 boxes, each 4x16)
sbox = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]

# Left shift schedule
shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def ascii_to_bits_in_list(h: list) -> list:
    """
    Converts a 1-8 character ASCII string into bits
    PKCS-style padding blocks 8 byte long
    Returns the bits as a list of '0' and '1' strings.
    """
    list_to_dec = [ord(c) for c in h]

    list_of_64bit_inputs = []

    block_amount = len(list_to_dec) // 8 + 1
    for x in range(block_amount*8):
        if x < len(list_to_dec):
            list_of_64bit_inputs.append(list_to_dec[x])
        else:
            list_of_64bit_inputs.append((block_amount*8)-len(list_to_dec))
    input_as_bits = "".join([format(x, "08b") for x in list_of_64bit_inputs])
    return list(input_as_bits)


def bits_to_blocks(plaintext_as_bits: list) -> list:
    """
    Takes list of bits that's divisible by 64, and returns into a list,
    of 64 length lists.
    """
    plaintext_as_bits_list = [bit for bit in plaintext_as_bits]
    plaintext_as_blocks = []
    for x in range(0, int(len(plaintext_as_bits_list)/64)):
        plaintext_as_blocks.append([])
        plaintext_as_blocks[x] = plaintext_as_bits_list[x*64:x*64+64]

    return plaintext_as_blocks


def create_initialization_vector() -> list:
    """
    Generates 8 random bytes using os.urandom
    """
    iv = os.urandom(8)

    iv_as_bits = list("".join([format(x, "08b") for x in iv]))

    return iv_as_bits


def pc1_permutation(bits_list_64: list) -> list:
    """
    Applies the PC-1 permutation to a 64-bit list of key bits.
    Returns a 56-bit permuted list.
    """
    return [bits_list_64[pc1[y] - 1] for y in range(56)]


def generate_subkeys(pci1_56bit_input: list) -> list:
    """
    Generates 16 48-bit subkeys (K1-K16) from the 56-bit PC1 input.
    """
    sub_key_half_length = len(pci1_56bit_input) // 2
    c = pci1_56bit_input[:sub_key_half_length]
    d = pci1_56bit_input[sub_key_half_length:]
    ki = []

    for shift_amount in shifts:
        c = c[shift_amount:] + c[:shift_amount]
        d = d[shift_amount:] + d[:shift_amount]
        combined = c + d
        ki.append([combined[pc2[x] - 1] for x in range(len(pc2))])

    return ki


def xor_round_substitution(plaintext_blocks: list, kn: list, iv: list) -> str:
    """
    Block formula for first block = C_1=E_K (P_1⊕IV)
    Block formula for blocks after first = C_n=E_K (P_n⊕C_(n-1))
    DES round function applied 16 times per block:
    IP, applies XOR with subkeys, S-box substitution & permutation (SP),
    LN = previous RN, RN = previous LN XOR with SP
    Final output = IV|C1|C2|...
    """
    current_cn = []
    cn_list = []
    for block in range(0, len(plaintext_blocks)):
        # First block XOR with IV
        # Next blocks XOR with their previos block's DES Cn output
        plaintext_block_with_xor = []
        if block == 0:
            plaintext_block_with_xor = [
                str(
                    int(a) ^ int(b)
                ) for a, b in zip(plaintext_blocks[block], iv)
                ]
        else:
            plaintext_block_with_xor = [
                str(int(a) ^ int(b))
                for a, b in zip(plaintext_blocks[block], current_cn)
            ]

        # Initial permitation is applied
        ip_applied = [plaintext_block_with_xor[ip[y] - 1] for y in range(64)]
        ln = ip_applied[:32]
        rn = ip_applied[32:]

        for round_number in range(16):
            # Expand RN from 32 to 48 bits
            expanded_rn = [rn[e[y] - 1] for y in range(48)]

            # XOR with round subkey
            xored = [
                int(a) ^ int(b) for a, b in zip(expanded_rn, kn[round_number])
            ]

            # Divide into eight 6-bit blocks
            xored_into_sixths = [xored[i:i + 6] for i in range(0, 48, 6)]

            # S-box substitution
            substitution_n = []
            for x in range(0, 8):
                # Bits are shifted to combine column and row information
                # grouped 1 << 6, 2 << 3 << 4 << 5,
                # example 011001 is 01 and 1100
                row_value = (
                    xored_into_sixths[x][0] << 1
                ) | xored_into_sixths[x][5]
                column_value = 0
                for bit in [xored_into_sixths[x][1], xored_into_sixths[x][2],
                            xored_into_sixths[x][3], xored_into_sixths[x][4]]:
                    column_value = (column_value << 1) | bit
                substitution_n.append(sbox[x][row_value][column_value])

            # Convert int to 4-bit binary and combine
            sub_full_as_32bits = list(
                "".join([format(x, "04b") for x in substitution_n])
            )

            # Permutation P
            permutated_substituted_32 = [
                sub_full_as_32bits[p[y] - 1] for y in range(32)
            ]

            # LN and RN swap/update
            ln_old = ln
            ln = rn
            rn = [
                str(int(a) ^ int(b)) for a, b in zip(
                    ln_old, permutated_substituted_32
                )
            ]

        # Final permutation after 16 rounds (swap halves)
        rn_ln = rn + ln
        current_cn = [rn_ln[fp[y] - 1] for y in range(64)]
        cn_list.append(current_cn)
    # Final output is IV concatenated with all ciphertext blocks
    final_output = "".join(iv)
    for cn in cn_list:
        final_output += "".join(cn)
    hex_length = len(final_output) // 4
    return hex(int(final_output, 2))[2:].zfill(hex_length)


def des_encrypt(plaintext: list, key: list) -> str:
    """
    Performs DES encryption for 64-bit block/blocks of plaintext.
    """
    key_bits = ascii_to_bits_in_list(key)
    plaintext_bits = ascii_to_bits_in_list(plaintext)
    subkeys = generate_subkeys(pc1_permutation(key_bits))
    plaintext_blocks = bits_to_blocks(plaintext_bits)
    iv = create_initialization_vector()
    return xor_round_substitution(plaintext_blocks, subkeys, iv)


def main():
    key = list("")
    plaintext_input = list("")
    ciphertext = des_encrypt(plaintext_input, key)
    print("Ciphertext:", ciphertext)


if __name__ == "__main__":
    main()
