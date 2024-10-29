import binascii
import sys
import re
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

"""
    Implementation of AES-256 with CBC cipher mode
    Cipher = plaintext + hmac + padding
"""

IV = Random.new().read(AES.block_size)
KEY = Random.new().read(AES.block_size)

def randkey():
    global IV
    IV = Random.new().read(AES.block_size)
    global KEY
    KEY = Random.new().read(AES.block_size)


def pad(s):
    """ The pad function applies padding to a string s to ensure that its length is a multiple of the block size (16 bytes for AES).

    Args:
        s (string): the string to be padded.

    Returns:
        string: input string with padded characters.

    Steps:
        1. Calculate the number of padding characters needed by moduloing and then subtracting by 16.
        2. The padding character is calculated based on the number of padding characters used. 
        3. Repeat this padding character for the number of paddind characters needed.
    """

    return (16 - len(s) % 16) * chr((16 - len(s) - 1) % 16)


def unpad_verifier(s):
    """ Removes padding from a decrypted message and verifies its integrity by comparing HMACs.

    Args:
        s (bytes): The decrypted message which includes the original message, HMAC, and padding.

    Returns:
        tuple: A tuple containing the following:
            - msg (bytes): The original message without padding or HMAC.
            - hash_d (bytes): The computed HMAC of the extracted message.
            - hash_c (bytes): The HMAC extracted from the decrypted data for comparison.

    Steps:
        1. Access the last character of s and convert it to an integer to find the exact length of the padding. Extract the message.
        2. Locate the position of the HMAC and remove the padding to capture it.
        3. Generate a HMAC for msg using the same secret key and SHA-256 hash function
        - Ths computed HMAC is intended to be compared with the hash_c to verify the integrity of the data
    """

    msg = s[0:len(s) - 32 - ord(s[len(s)-1:]) - 1]
    hash_c = s[len(msg):-ord(s[len(s)-1:]) - 1]
    hash_d = hmac.new(KEY, msg, hashlib.sha256).digest()
    return msg, hash_d, hash_c


def encrypt(msg):
    """ Ciphers message using AEC in CBC mode.

    Args:
        msg (str): The plaintext message to encrypt.

    Returns:
        bytes: The encrypted message with appended integrity HMAC.

    Steps:
        - This is necessary because the encryption algorithm AES works on byte data rather than plain strings
        1. Converts the plain text message into bytes, encoding it as a UTF-8 btye string. 
        2. Creates a HMAC (Hashed-based Message Authentication Code) based on the provided KEY and DATA(the encoded message), using SHA-256 as the hashing algorithm. 
        - The hash is the resulting HMAC digest, which serves to verify the integrity of the message for decryption later
        3. Calls the pad function to generate padding for the data. Padding is done to ensure that the data length matches the AES block size requirements. 
        - The padding here is based on the combined length of data and hash, and is required to have the entire input (including the HMAC) to align with its 16-byte block size
        4. Combines the message data, the HMAC hash and the padded bytes to form the raw message that is to be encrypted.
        5. Initialises the AES Cipher in CBC mode and using the KEY and initialisation vector IV.
        6. Raw is encrpted using AES Cipher in CBC mode. The ciphertext is returned.
    """

    data = msg.encode()
    hash = hmac.new(KEY, data, hashlib.sha256).digest()
    padding = pad(data + hash)
    raw = data + hash + padding.encode()
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(raw)


def decrypt(enc):
    """ Decrypts an encrypted message using AES in CBC mode and verifies its integrity.

    Args:
        enc (bytes): The encrypted message to be decrypted.

    Returns:
        str: The decrypted plaintext message if integrity check passes.
        int: Returns 0 if the integrity check fails (HMAC mismatch).

    Steps:
        1. Initializes an AES cipher in CBC mode using the global KEY and IV.
        2. Decrypts the provided encrypted data to obtain the raw decrypted output.
        3. Calls the `unpad_verifier` function to unpad the decrypted output and verify the HMAC. Extracts the plaintext message, the extracted HMAC (`signature_2`), and the computed HMAC (`sig_c`).
        4. Compares the extracted HMAC with the computed HMAC:
           - If they do not match, returns 0 to indicate a failure in the integrity check.
        5. If the HMACs match, returns the decrypted plaintext message.
    """

    decipher = AES.new(KEY, AES.MODE_CBC, IV)
    plaintext, signature_2, sig_c = unpad_verifier(decipher.decrypt(enc))

    if signature_2 != sig_c:
        return 0
    return plaintext


def split_len(seq, length):
    """ Splits a sequence into smaller chunks of a specified length.

    Parameters:
        seq (str or list): The sequence to be split, such as a string or list.
        length (int): The length of each chunk.

    Returns:
        list: A list where each element is a chunk of the original sequence with the specified length.

    Steps:
        1. Iterates over seq with a step size of length, slicing seq from index i to i + length.
    """

    return [seq[i:i+length] for i in range(0, len(seq), length)]


def run(SECRET):
    
    """
    Initiates the POODLE attack to decipher the SECRET message without knowing
    the AES key. Implements padding-based decryption using crafted ciphertexts
    to analyze padding errors and reveal bytes of the plaintext.
    """
    # Initialises an empty list to store the discovered bytes of the plaintext
    secret = [] 

    # Define the block size for AES (16 Bytes for AES128)
    length_block = 16

    # Encrypt the secret message
    a = encrypt(SECRET)
    # Print the result of decrypting it
    print(decrypt(a))

    # Encrypt the SECRET message to obtain the hex-encoded ciphertext, which is used to determine the original ciphertext length
    t = binascii.hexlify(encrypt(SECRET))
    # Store the length of this ciphertext
    original_length = len(t)
    # Initialise the padding increment counter
    t = 1
    
    # Incrementally increase the padding by adding 'a' characters to find where the ciphertext length changes
    while (True):
        # Encrypt the modified message (padding 'a' * t + SECRET) and get its hex-encoded length
        length = len(binascii.hexlify(encrypt("a"*t + SECRET)))
        # If the length of the ciphertext exceeds the original, we know padding started a new block
        if (length > original_length):
            # Exit loop when the padded length exceeds original ciphertext length
            break
        # Increase padding counter by 1 for the next iteration
        t += 1
    # Save the padding length at which the ciphertext length increased
    save = t
    # Initialise a list to store the results of each diciphered block attempt
    v = []

    print("[+] Start Deciphering using POA...")
    
    # Loop to decipher each block from second last to the first block in reverse order
    for block in range(original_length//32-2, 0, -1):
        # Loop to decipher each byte in the current block, from the end of the block to the beginning
        for char in range(length_block):
            # Initialise a counter for the attempts
            count = 0
            while True:
                # Reset the encryption key to avoid detection through repeated ciphertexts
                randkey()
                # Encrypt a crafted string to exploit padding validation by the oracle
                request = split_len(binascii.hexlify(
                    encrypt("$"*16 + "#"*t + SECRET + "%"*(block*length_block - char))), 32)
                # Replace the last block of the crafted request with the targeted block, which is the one we're analysing
                request[-1] = request[block]
                # Convert the hex-encoded request back to bytes for decryption
                cipher = binascii.unhexlify(b''.join(request).decode())
                # Attempt to decrypt using the oracle
                plain = decrypt(cipher)
                count += 1

                # Checks if the oracle returned a valid decrypted result. A value of 0 indicates a padding error or an invalid guess
                if plain != 0:
                    # the variable t is incremented to move on to the next byte in the target block. This ensures that in subsequent iterations, the guessed byte of the secret is aligned correctly for guessing the next byte.
                    t += 1
                    # the second last block is assigned. It influences the decryption of the last block and will be XORed with the attacked block during AES decryption
                    pbn = request[-2]
                    # The block immediately before the block to decipher is also important as it is also involved in the XOR operation.
                    pbi = request[block - 1]
                    
                    # Key step where the byte is recovered
                    # - pbn[-2:]: The last two characters (i.e., one byte) of the second-to-last block (pbn). This is the byte that was XORed with the last block in the decryption.
                    # - pbi[-2:]: The last byte of the previous block (pbi) that was involved in the XOR during decryption.
                    # - int(... ^ ...) ^ ...: This XOR operation works as follows:
                    # - First, it XORs the padding byte (0f) with the last byte of pbn (influencing the block being attacked).
                    # - Then, it XORs the result with the last byte of pbi (from the previous block) to isolate and recover the corresponding byte of the secret.
                    decipher_byte = chr(int("0f", 16) ^ int(
                        pbn[-2:], 16) ^ int(pbi[-2:], 16))
                    # Add the newly deciphered byte to the secret list
                    secret.append(decipher_byte)
                    # A temporary list is created by reversing the secret list
                    tmp = secret[::-1]
                    # Prints the byte found in real time
                    sys.stdout.write(
                        "\r[+] Found byte \033[36m%s\033[0m - Block %d : [%16s]" % (decipher_byte, block, ''.join(tmp)))
                    sys.stdout.flush()
                    break
        print('')
        # Print out the secret in reverse order as decryption was done in reverse order
        secret = secret[::-1]
        v.append(('').join(secret))
        secret = []
        t = save

    v = v[::-1]
    plaintext = re.sub('^#+', '', ('').join(v))
    print("\n\033[32m{-} Deciphered plaintext\033[0m :", plaintext)
    return v


if __name__ == '__main__':

    print("{-} Poodle Proof of Concept for SC3010\n")

    SECRET = "This is a PoC of the Poodle Attack against SSL/TLS"
    print("[+] Secret plaintext :", SECRET)
    print("[+] Encrypted with \033[33mAES-256 MODE_CBC\033[0m")
    print("")
    run(SECRET)
    print("")

    SECRET = "I can decipher the plaintext without knowing the private key used for the encryption"
    print("[+] Secret plaintext :", SECRET)
    print("[+] Encrypted with \033[33mAES-256 MODE_CBC\033[0m")
    print("")
    run(SECRET)

    print("\nThank you for watching this poc Prof!")
