import numpy as np


#a function used for me to test out some things and see if the program is working correctly :)
def print_state(matrix):
    mat = np.array([])

    for n in matrix:
        mat = np.append(mat, hex(int(n, 2)))
    
    print(mat.reshape(4, 4))

def print_key_hex(expanded_key):
    i = 0
    for key in expanded_key:
        print(str(i) + ": " + hex(int(key, 2)))
        i +=1

#converts a given text (in string format or hexadecimal format) to a string representing the binary sequence of the input
def convert_to_binary(text, bit_size_requirement = 4, required_bits = 0):
    #turn a string into bits
    if type(text) is str:
        #converts the string input into bits, got this from stack overflow
        #basically it goes through each character, converts it into a byte (8 bits) and adds it to the string
        key_bit_string = ''.join(format(ord(char), '08b') for char in text) 
        key_n_bits = len(key_bit_string)
    
    #turn a number into bits (so we can input hexadecimal values like 0xabcdf10....)
    else:
        #transfer the number into bits instead of decimal (0b1 will be 1, 0b10 will be 2, etc..) 
        key_bit_string = str(bin(text)) 

        #get rid of the beggining "0b", since we don't need it
        key_bit_string = key_bit_string[key_bit_string.find("0b") + 2:]

        key_n_bits = len(key_bit_string)
        #python loves removing the leading 0's so the byte value always starts with 1
        #(instead of having 0010, python will give 10, which is a problem).
        #so, we need to fix this, the easiest way is checking if the bit size is divisible by 4 (or 8 depending on our situation)
        #if not, update the "bit_input" and "n_bits" so they count the missing 0's as well

        if key_n_bits % bit_size_requirement != 0:
            #calculate the number of missing bits (0's)
            missing_bits = bit_size_requirement - (key_n_bits % bit_size_requirement)

            #in python you can multiply a string with a number (so "0" * 3 = "000", or "0" * 2 = "00")
            key_bit_string = "0" * missing_bits + key_bit_string
            key_n_bits += missing_bits
        
        #this will guarantee our keey is in the size that we want, as leading 0's cause problems (thank you python!)
        if required_bits != 0:
            key_bit_string = "0" * (required_bits - key_n_bits) + key_bit_string
            key_n_bits += required_bits - key_n_bits
    
    
    return key_bit_string, key_n_bits

#substitutes the bytes using the S_box
def sub_bytes(bytes, inverse = False):
    subbed_bytes = np.array([])
    #prepare the s_box variable and assign it the matrix according to whether we are encrypting or decrypting
    s_box = []
    
    if not inverse:
        s_box = [
        [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
        [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
        [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
        [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
        [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
        [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
        [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
        [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
        [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
        [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
        [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
        [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
        [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
        [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
        [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
        [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
        ]

    else:
        s_box = [
        [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
        [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
        [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
        [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
        [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
        [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
        [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
        [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
        [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
        [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
        [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
        [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
        [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
        [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
        [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
        [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
        ]

    #for every byte in our array of bytes, calculate the int of first 4 bits and last 4 bits and replace the array's value with the corresponding s_box value
    #also, convert that number back into a sequence of bits before adding into the matrix
    for byte_string in bytes:
        num = s_box[int(byte_string[: 4], 2)][int(byte_string[4:], 2)]
        num = convert_to_binary(num, 8)[0] #I put [0] as this function returns 2 numbers, we don't need n_bits
        subbed_bytes = np.append(subbed_bytes, num)
            

    return subbed_bytes

#Shifts the rows of the matrix accordingly
def shift_rows(bytes, inverse = False):
    #prepare the matrix that will be the shifted version of our bytes matrix
    shifted_rows = np.array([])

    #this variable will define if we should be shifting the current row and in which direction
    offset = 0

    for i in range(len(bytes)):
        #this means that we are moving onto the next row, as there are 4 columns per row
        if i!= 0 and  i % 4 == 0:
            if not inverse:
                offset += 1
            else:
                offset -= 1

        shifted_rows = np.append(shifted_rows, bytes[((i + offset) % 4) + 4 * abs(offset)])

    return shifted_rows

#multiplies by a matrix in polynoamial form and ensures that the results are 8 bits
def mix_columns(bytes, inverse = False):
    
    #a function that multiplies 2 numbers in the language of polynomials, by converting bits into a GF(2) polynomial
    #"a" is the first number
    #"b" is a string bit representation of the second number
    def multiply(a, b):
        result = 0

        for i in range(len(b)):
            if b[-i - 1] == "1":
                result ^= a << i #XOR the current result with the shifted version of the polynomial "a" (so if we have x, "a" will be shifted by 1 to the left)

        if result >= 256:
            result = modulo(result)
        return result
    
    #called when our result from multiplication is more than 8 bits (bigger or equal to 256)
    #modulatess the result by {x^8 + x^4 + x^3 + x + 1}, which happens to be equal to 283
    def modulo(result):
        AES_polynomial = 283 #a 9 bit sequence {100011011}

        #get the number of bits that the result uses, it should be more than 8!
        result_n_bits = convert_to_binary(result, 1)[1]


        while(result_n_bits > 8):
            #XOR the result with the AES polynomial shifted by a relative amount
            result ^= AES_polynomial << (result_n_bits - 9)

            #update the number of bits used by the result, if it's still more than 8 bits, continue
            result_n_bits = convert_to_binary(result, 1)[1]
        
        return result

    #turn the array of bytes into a 4x4 matrix (for simplicity and my own sanity)
    matrix = bytes.reshape(4, 4)

    #prepare the matrix that we will be multiplying with
    m_box = []

    if not inverse:
        m_box = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]
        ]

    else:
        m_box = [
            [0x0e, 0x0b, 0x0d, 0x09],
            [0x09, 0x0e, 0x0b, 0x0d],
            [0x0d, 0x09, 0x0e, 0x0b],
            [0x0b, 0x0d, 0x09, 0x0e]
        ]

    #this will be our resulting matrix after mix_columns()
    result_matrix = np.array([], dtype=int)

    #this is the multiplication process, we multiply the "m_box" elements on the same row with the "bytes" matrix on the same column
    for row in range(4):
        for column in range(4):
            
            result = 0
            for i in range(4):
                #executes a polynomial multiplication given 2 numbers (1 in int format, the other in string bit format)
                #Conveniently we have 1 number in int format and the other in string bit format!
                result ^= multiply(m_box[row][i], matrix[i][column])
            
            result_matrix = np.append(result_matrix, convert_to_binary(int(result), 8)[0])
    return result_matrix

def XOR_operation(bytes, key):
    result_bytes = np.array([])

    for i in range(len(bytes)):
        result_bytes = np.append(result_bytes, convert_to_binary(int(bytes[i], 2) ^ int(key[i], 2), 8)[0])

    return result_bytes

#KEY EXPANSION FUCNTIONS:

#takes 1 word (8 hexadecimal w value) and converts it.
def sub_word(Wi):
    result = ""

    s_box = [
        [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
        [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
        [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
        [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
        [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
        [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
        [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
        [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
        [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
        [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
        [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
        [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
        [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
        [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
        [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
        [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
    ]



    for i in range(4):
        a = int(Wi[8*i: 8*i + 4], 2)
        b = int(Wi[8*i + 4: 8*i + 8], 2)

        num = s_box[a][b]
        num = convert_to_binary(num, 8)[0]

        result += num

    return result
        
#rotate circularly to the left by 2 hexadecimal values, which is 8 bits
def rot_word(Wi):
    Wi_copy = Wi[8:]
    Wi_copy += Wi[:8]

    return Wi_copy

def key_expansion(key_bit_string):
    #ChatGPT did a nice job with this one!
    Rcon = [
    0x00000000,  # Rcon[0] is not used
    0x01000000,  # Rcon[1]
    0x02000000,  # Rcon[2]
    0x04000000,  # Rcon[3]
    0x08000000,  # Rcon[4]
    0x10000000,  # Rcon[5]
    0x20000000,  # Rcon[6]
    0x40000000,  # Rcon[7]
    0x80000000,  # Rcon[8]
    0x1B000000,  # Rcon[9]
    0x36000000,  # Rcon[10]
    ]
    W = []
    #number of words (iterations) before using subword, rotword and Rcon
    Nk = int(len(key_bit_string) / 32)
    #number of rounds in the AES
    Nr = 10
    Nr += Nk - 4
    

    #we go by 32 bits, as each w consists of 8 hexadecimal values which is 32 bits
    for i in range(Nk):
        W.append(key_bit_string[32*i : 32*i + 32])
    
    
    i = Nk
    #we will iterate (rounds + 1) * 4 times, as we need (rounds + 1) number of key blocks, each consisting of 4 words
    while i < 4 * (Nr + 1):
        temp = W[i - 1]
        if i % Nk == 0:
            temp = int(sub_word(rot_word(temp)), 2) ^ Rcon[int(i / Nk)]
        
        elif Nk > 6 and i % Nk == 4:
            temp = sub_word(temp)

        if type(temp) == str:
            temp = int(temp, 2)
        W.append(convert_to_binary(int(W[i - Nk], 2) ^ temp, bit_size_requirement=8)[0])
        i += 1
    return W

#runs the AES algorithm
def AES(plaintext, key, decrypt = False, key_size = 0, text_size = 0):

    #convert the key and plaintext into a binary text
    #"x_bit_string" is the sequence of bits that correspond to the key
    #"x_n_bits" is the number of bits the key uses
    key_bit_string, key_n_bits = convert_to_binary(key, required_bits=key_size)
    plaintext_bit_string, plaintext_n_bits = convert_to_binary(plaintext, required_bits=text_size)
    
    #check if the given key is valid (size 128, 192 or 256 bits).
    
    allowed_key_sizes = [128, 192, 256]

    if not (key_n_bits in allowed_key_sizes):
        print(key_bit_string)
        print(f"Your key size is {key_n_bits}, please input either a 128, 192 or 256 bit key.")
        return
    #our plaintext has to be a sequence of 128 bits (128, 256, ..., 128 * n bits).
    #this means that the plaintext must have a number of characters divisible by 128/8 = 16 (as each character is 8 bits)
    #if that's not the case, we can add padding by adding 0's in the BIT REPRESENTATION of the plaintext (so plaintext_bit_string)

    if len(plaintext_bit_string) % 128 != 0:
        plaintext_bit_string += "0" * (128 - (len(plaintext_bit_string) % 128))

    #if the size of the text is bigger than 128 bits, split it into 128 bit blocks
    plaintext_blocks = np.array([])

    for i in range(int(len(plaintext_bit_string) / 128)):
        plaintext_blocks = np.append(plaintext_blocks, plaintext_bit_string[128 * i: 128 * i + 128])


    #this will have all the keys in 1 array, each element being a word (Wi), which is 8 hexadecimal characters (32 bits).
    #we will take 4 elements per round 
    expanded_key_array = key_expansion(key_bit_string)

    #prepare the key block matrix (4x4), which will be an array of length 16
    key_block = [[], [], [], []]


    #the input seems to be going down each iteration, instead of going right, so I'm using i % 4

    if not decrypt:
        for i in range(16):
            key_block[i % 4].append(key_bit_string[8 * i : 8 + 8 * i])
    else:
        last_4_expanded_keys = ""

        for i in range(4):
            last_4_expanded_keys += expanded_key_array[-4 + i]

        for i in range(16):
            key_block[i % 4].append(last_4_expanded_keys[8 * i : 8 + 8 * i])

    key_block = np.array(key_block)
    key_block = key_block.reshape(16)

    ciphertext = ""

    #run AES per block
    for block in plaintext_blocks:

        #split the plaintext into 16 blocks (it's not actually a matrix, it's an array of length 16)
        matrix = [[], [], [], []]
        for i in range(16):
            matrix[i % 4].append(block[8 * i: 8* i + 8])

        matrix = np.array(matrix)
        matrix = matrix.reshape(16)
        
        matrix = XOR_operation(matrix, key_block)
        #print_state(matrix)

        #some repetitions here, I'm too tired to take care of it :)
        Nk = int(len(key_bit_string) / 32)
        #number of rounds in the AES
        Nr = 10
        Nr += Nk - 4

        for round in range(Nr):

            if not decrypt:
                #print_state(matrix)
                matrix = sub_bytes(matrix, decrypt)
                #print_state(matrix)
                matrix = shift_rows(matrix, decrypt)
                #print_state(matrix)

                #we don't use mix_columns on the last iteration
                if round != Nr - 1:
                    matrix = mix_columns(matrix, decrypt)
                    #print_state(matrix)

                key_block = [[], [], [], []]
                for i in range(4):
                    key = expanded_key_array[((round + 1)  * 4) + i] 

                    for f in range(4):
                        key_block[f].append(key[f*8 : f*8 + 8])

                key_block = np.array(key_block)
                key_block = key_block.reshape(16)


                matrix = XOR_operation(matrix, key_block)
                #print_state(matrix)

            #inverse cipher
            else:
                matrix = shift_rows(matrix, decrypt)
                #print_state(matrix)
                
                matrix = sub_bytes(matrix, decrypt)
                #print_state(matrix)


                key_block = [[], [], [], []]
                for i in range(4):
                    key = expanded_key_array[((Nr - round - 1)  * 4) + i] 

                    for f in range(4):
                        key_block[f].append(key[f*8 : f*8 + 8])

                key_block = np.array(key_block)
                key_block = key_block.reshape(16)

                matrix = XOR_operation(matrix, key_block)
                #print_state(matrix)

                #we don't use mix_columns on the last iteration
                if round != Nr - 1:
                    matrix = mix_columns(matrix, decrypt)

            
        offset = 0
        for i in range(len(matrix)):
            if i != 0 and i * 4 % 16 == 0:
                offset += 1
            #because python (again) loves not adding unnecessary 0's when not needed, we need to manually add a 0 at the beginning if it's missing
            hex_to_add = str(hex(int(matrix[((i * 4) % 16) + offset], 2)))[2:]
            while len(hex_to_add) < 2:
                hex_to_add = "0" + hex_to_add
            ciphertext += hex_to_add

    return ciphertext


print(AES(0x3243f6a8885a308d313198a2e0370734, 0x2b7e151628aed2a6abf7158809cf4f3c))

print(AES(0x3925841d02dc09fbdc118597196a0b32, 0x2b7e151628aed2a6abf7158809cf4f3c, decrypt=True))


#If any input starts with 0's you need to define the sizes of inputs when you are trying to encrypt (or decrypt), 
#which is really annoying, couldn't figure out another solution
print(AES(0x00112233445566778899aabbccddeeff, 0x000102030405060708090a0b0c0d0e0f, key_size=128, text_size = 128))

print(AES(0x69c4e0d86a7b0430d8cdb78070b4c55a, 0x000102030405060708090a0b0c0d0e0f, decrypt=True, key_size= 128, text_size=128))


print(AES(0x00112233445566778899aabbccddeeff, 0x000102030405060708090a0b0c0d0e0f1011121314151617, key_size=192, text_size=128))
print(AES(0xdda97ca4864cdfe06eaf70a0ec0d7191, 0x000102030405060708090a0b0c0d0e0f1011121314151617, decrypt= True, key_size=192, text_size=128))


#my soul left my body trying to get rid of stupid bugs caused by python ignoring bits that start with 0.
#I am finally done :)

