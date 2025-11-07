# DES Encryption Python Library

Python implementation of the Data Encryption Standard (DES) algorithm, with padding support for key and plaintext, and automated testing using pytest.

## Features
- DES encryption of 64-bit plaintext and 64-bit key  
- ASCII input used  
- Maximum one 64-bit block (eight characters) for input & key  
- Minimum one character input & key  
- 16 subkeys generated  
- Matrix according to [FIPS 46-3](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf)  
- Hexadecimal output  
- pytest included