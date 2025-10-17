import ML_KEM
from GeneralAlgr import *
from GLOBAL import *
import time
from Crypto.Cipher import AES

# print("## ML-KEM-512 Full Cycle Test ##\n")

# 1. GENERATE RECIPIENT'S KEYS
# A potential recipient generates a key pair.
start_time = time.perf_counter()
public_key, private_key = ML_KEM.KeyGen()
# print("1. Recipient generated a public/private key pair.")
# print("Check:")
# print("   -> Public Key Length:", len(public_key))
# print("   -> Private Key Length:", len(private_key))
# print("Modulus check:")
# test = ByteEncode(12, ByteDecode(12, public_key[:384*k]))
# if test == public_key[:384*k]:
#     print("   -> Public Key encoding/decoding is consistent.")

# 2. SENDER ENCAPSULATES
# A sender uses the recipient's public key to create a shared secret
# and a ciphertext to send.
sender_shared_secret, ciphertext = ML_KEM.Encaps(public_key)
print("2. Sender encapsulated a secret, generating a shared secret and a ciphertext.")
# print("Check:")
# print("   -> Ciphertext Length:", len(ciphertext))
print(f"   -> Sender's Secret: {sender_shared_secret.hex()}")

plaintext = b"Messi mai dinh"

aes_key = sender_shared_secret

cipher = AES.new(aes_key, AES.MODE_GCM)
nonce = cipher.nonce
aes_ciphertext, tag = cipher.encrypt_and_digest(plaintext)

print(f"Plaintext: '{plaintext.decode()}'")
print(f"AES Ciphertext (first 16 bytes): {aes_ciphertext[:16].hex()}...")
print(f"Nonce: {nonce.hex()}")
print(f"Authentication Tag: {tag.hex()}")
print("-" * 40)

# 3. RECIPIENT DECAPSULATES
# The recipient uses their private key and the received ciphertext
# to derive their version of the shared secret.
recipient_shared_secret = ML_KEM.Decaps(private_key, ciphertext)
print("\n3. Recipient decapsulated the ciphertext using their private key.")
print(f"   -> Recipient's Secret: {recipient_shared_secret.hex()}")

# 4. VERIFY
# Both parties should now have the exact same 32-byte secret key.
assert sender_shared_secret == recipient_shared_secret
print("\n✅ Success! The sender's and recipient's shared secrets match perfectly.")

recipient_aes_key = recipient_shared_secret
try:
    # The recipient creates an AES object with the same key and nonce
    decipher = AES.new(recipient_aes_key, AES.MODE_GCM, nonce=nonce)

    # Decrypt and verify the authentication tag
    # If the tag is invalid, this will raise a ValueError
    decrypted_plaintext = decipher.decrypt_and_verify(aes_ciphertext, tag)

    print(f"✅ Decryption successful!")
    print(f"Decrypted Message: '{decrypted_plaintext.decode()}'")

    # Final check
    assert plaintext == decrypted_plaintext

except (ValueError, KeyError) as e:
    print(f"❌ Decryption failed! The message may have been tampered with.")





end_time = time.perf_counter()
elapsed_time = end_time - start_time
print(f"The code took {elapsed_time:.4f} seconds to execute.")




