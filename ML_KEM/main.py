import ML_KEM
from GeneralAlgr import *
from GLOBAL import *
import time
from Crypto.Cipher import AES
import os

def parse_kat_file(filepath):
    """
    Parses a key-value file and stores values with the same key into lists.
    Values are converted from hex strings to bytes.

    Args:
        filepath (str): The path to the file to be parsed.

    Returns:
        dict: A dictionary where keys are the variable names (e.g., 'd', 'z')
              and values are lists of the corresponding bytes values found in the file.
              Returns an empty dictionary if the file cannot be read.
    """
    data = {}
    try:
        with open(filepath, 'r') as f:
            for line in f:
                # Ensure the line contains an equals sign before splitting
                if '=' in line:
                    # Split only on the first equals sign
                    key, value = line.split('=', 1)
                    
                    # Clean up whitespace from the key
                    key = key.strip()
                    
                    # Strip whitespace and convert the hex string value to bytes
                    try:
                        value_bytes = bytes.fromhex(value.strip())
                    except ValueError:
                        print(f"Warning: Could not decode hex value for key '{key}'. Skipping.")
                        continue

                    # Append the value to the list for this key.
                    # If the key doesn't exist yet, create an empty list first.
                    if key not in data:
                        data[key] = []
                    data[key].append(value_bytes)
    except FileNotFoundError:
        print(f"Error: The file '{filepath}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        
    return data

elapsed_time_list = []


def TC_KeyGen(parsed_data: dict):
    for i in range(100):
        d = parsed_data.get('d')[i]
        z = parsed_data.get('z')[i]
        pk = parsed_data.get('pk')[i]
        sk = parsed_data.get('sk')[i]



        public_key, private_key = ML_KEM.KeyGen(d, z)

        assert public_key == pk
        assert private_key == sk

    print("✅KeyGen() passed all 100 Testcases!")

def TC_Encaps(parsed_data: dict):
    for i in range(100):
        pk = parsed_data.get('pk')[i]
        m = parsed_data.get('m')[i]
        ss = parsed_data.get('ss')[i]
        ct = parsed_data.get('ct')[i]
        

        sender_shared_secret, ciphertext = ML_KEM.Encaps(pk, m)

        assert sender_shared_secret == ss
        assert ciphertext == ct

    print("✅Encaps() passed all 100 Testcases!")

def TC_Decaps(parsed_data: dict):
    for i in range(100):
        sk = parsed_data.get('sk')[i]
        ss = parsed_data.get('ss')[i]
        ct = parsed_data.get('ct')[i]

        recipient_shared_secret = ML_KEM.Decaps(sk, ct)

        assert recipient_shared_secret == ss

    print("✅Decaps() passed all 100 Testcases!")


def TC_FullSequence(parsed_data: dict):
    for i in range(100):
        d = parsed_data.get('d')[i]
        z = parsed_data.get('z')[i]
        pk = parsed_data.get('pk')[i]
        sk = parsed_data.get('sk')[i]
        m = parsed_data.get('m')[i]
        ct = parsed_data.get('ct')[i]
        ss = parsed_data.get('ss')[i]
        
        public_key, private_key = ML_KEM.KeyGen(d, z)
        sender_shared_secret, ciphertext = ML_KEM.Encaps(pk, m)
        recipient_shared_secret = ML_KEM.Decaps(sk, ct)


        assert public_key == pk
        assert private_key == sk
        assert ciphertext == ct
        assert sender_shared_secret == recipient_shared_secret
        assert sender_shared_secret == ss
        assert recipient_shared_secret == ss

    print("✅Full Sequence Test passed all 100 Testcases!")

def TC_EncryptwAES_randomData():
    for i in range(100):
        # 1. Alice
        public_key, private_key = ML_KEM.KeyGen()

        # 2. Bob recieved public key from Alice
        # 3. Bob encapsulate the public key to generate shared secret key and ciphertext
        sender_shared_secret, ciphertext = ML_KEM.Encaps(public_key)

        # 4. Bob encrypt a plaintext using AES with shared secret key
        plaintext = os.urandom(32)
        # print(f"Original Plaintext: {plaintext.hex()}")

        cipher = AES.new(sender_shared_secret, AES.MODE_GCM)
        ciphertext_AES, tag = cipher.encrypt_and_digest(plaintext)
        nonce = cipher.nonce
        

        # 5. Alice recieved ciphertext from Bob
        # 6. Alice Decapsulate the ciphertext with private key to gain shared secret key
        recipient_shared_secret = ML_KEM.Decaps(private_key, ciphertext)

        # 7. Alice received ciphertext_AES, tag and nonce from Bob
        # 8. Alice decrypt the ciphertext_AES
        decipher = AES.new(recipient_shared_secret, AES.MODE_GCM, nonce=nonce)
        decrypted_plaintext = decipher.decrypt_and_verify(ciphertext_AES, tag)

        # print(f"Decrypted Plaintext: {decrypted_plaintext.hex()}")
        assert plaintext == decrypted_plaintext
    print("✅Test with AES passed all 100 Testcases!")

def run_TC(n: int):
    # The name of the file you uploaded
    filename = TEST_FILENAME
    
    # Parse the file
    parsed_data = parse_kat_file(filename)
    start_time = time.perf_counter()
    
    for i in range(n):
        print("          ----- ROUND", i, " -----          ")
        TC_KeyGen(parsed_data)
        # TC_Encaps(parsed_data)
        # TC_Decaps(parsed_data)
        # TC_FullSequence(parsed_data)


        # TC_EncryptwAES_randomData()
        
        # Skip the first time run since numba cost time to compile for the first time.
        if (i == 0):
            first_run_end = time.perf_counter()
            first_run_elapsed = first_run_end - start_time
            print(f"The code took {first_run_elapsed:.4f} seconds to execute for the first time.")
            start_time = time.perf_counter()
        print('\n')

    end_time = time.perf_counter()
    if (n-1 != 0):
        elapsed_time = (end_time - start_time) / (n-1)
        print(f"The code took averagely {elapsed_time:.4f} seconds to execute.")

KEYGEN = 0
ENCAPS = 1
DECAPS = 2
FULL = 3
def run_Benchmark(n: int, module: int):
    # Skip first time run to avoid numba compilation time
    public_key, private_key = ML_KEM.KeyGen()
    sender_shared_secret, ciphertext = ML_KEM.Encaps(public_key)
    recipient_shared_secret = ML_KEM.Decaps(private_key, ciphertext)

    start_time = time.perf_counter()

    keygen_total_elapsed = 0.0
    encaps_total_elapsed = 0.0
    decaps_total_elapsed = 0.0
    
    for i in range(n):
        keygen_start = time.perf_counter()
        public_key, private_key = ML_KEM.KeyGen()
        keygen_end = time.perf_counter()
        keygen_total_elapsed += keygen_end - keygen_start

        encaps_start = time.perf_counter()
        sender_shared_secret, ciphertext = ML_KEM.Encaps(public_key)
        encaps_end = time.perf_counter()
        encaps_total_elapsed += encaps_end - encaps_start

        decaps_start = time.perf_counter()
        recipient_shared_secret = ML_KEM.Decaps(private_key, ciphertext)
        decaps_end = time.perf_counter()
        decaps_total_elapsed += decaps_end - decaps_start

        assert sender_shared_secret == recipient_shared_secret

        if module == KEYGEN:
            print(f"Round {i+1}: KeyGen() took {(keygen_end - keygen_start)*1000:.6f} ms to execute.")
        elif module == ENCAPS:
            print(f"Round {i+1}: Encaps() took {(encaps_end - encaps_start)*1000:.6f} ms to execute.")
        elif module == DECAPS:
            print(f"Round {i+1}: Decaps() took {(decaps_end - decaps_start)*1000:.6f} ms to execute.")
        elif module == FULL:
            round_total = (keygen_end - keygen_start) + (encaps_end - encaps_start) + (decaps_end - decaps_start)
            print(f"Round {i+1}: Full sequence took {round_total*1000:.6f} ms to execute.")
        

    keygen_average = keygen_total_elapsed / n * 1000
    encaps_average = encaps_total_elapsed / n * 1000
    decaps_average = decaps_total_elapsed / n * 1000

    if module == KEYGEN:
        print(f"KeyGen() took averagely {keygen_average:.6f} ms to execute.")
    elif module == ENCAPS:
        print(f"Encaps() took averagely {encaps_average:.6f} ms to execute.")
    elif module == DECAPS:
        print(f"Decaps() took averagely {decaps_average:.6f} ms to execute.")
    elif module == FULL:
        total_average = keygen_average + encaps_average + decaps_average
        print(f"Full sequence took averagely {total_average:.6f} ms to execute.")

if __name__ == "__main__":
    # run_TC(n=5)
    run_Benchmark(n=10, module=DECAPS) # KEYGEN, ENCAPS, DECAPS, FULL


