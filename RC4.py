import binascii

def RC4(plaintext, key):
    # Initialize
    S = []
    T = []
    # Convert plaintext and key to bytes if they are strings
    if isinstance(key, str):
        plaintext = plaintext.encode()  # Encode plaintext to bytes
        key = key.encode()  # Encode key to bytes

    # Create the arrays S and T with their corresponding values
    for i in range(256):  # 256 not included
        S.append(i)
        T.append(key[i % len(key)])  # Use modulo to wrap around the key

    # Change the permutation of S
    j = 0
    for i in range(256):
        j = (j + S[i] + T[i]) % 256
        swap(S, i, j)

    # Generate as many keystream bytes as needed
    i = 0
    j = 0
    ciphertext = bytearray()  # Store result in a bytearray

    # Loop for as many bytes as plaintext has + 1000 (we will skip the first 1000 bytes)
    for k in range(len(plaintext) + 1000):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        swap(S, i, j)

        if k >= 1000:  # Skip the first 1000 keystream bytes
            t = (S[i] + S[j]) % 256
            # XOR the byte with the keystream, then append the result to ciphertext
            ciphertext.append(plaintext[k - 1000] ^ S[t])

    return bytes(ciphertext)  # Return the ciphertext as bytes


def swap(arr, i, j):
    arr[i], arr[j] = arr[j], arr[i]  # Simplified swap


# Test with example text
cipher_text = RC4("hello, this is a long string", "hello, this is a key")
print(cipher_text)
# Print ciphertext as hexadecimal
print(binascii.hexlify(cipher_text))