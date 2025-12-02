import ML_KEM
from GeneralAlgr import *
from GLOBAL import *



# try:
#     print("## ML-KEM-512 Full Cycle Test ##\n")

#     # 1. GENERATE RECIPIENT'S KEYS
#     # A potential recipient generates a key pair.
#     public_key, private_key = ML_KEM.KeyGen()
#     print("1. Recipient generated a public/private key pair.")

#     # 2. SENDER ENCAPSULATES
#     # A sender uses the recipient's public key to create a shared secret
#     # and a ciphertext to send.
#     sender_shared_secret, ciphertext = ML_KEM.Encaps(public_key)
#     print("2. Sender encapsulated a secret, generating a shared secret and a ciphertext.")
#     print(f"   -> Sender's Secret: {sender_shared_secret.hex()}")

#     # 3. RECIPIENT DECAPSULATES
#     # The recipient uses their private key and the received ciphertext
#     # to derive their version of the shared secret.
#     recipient_shared_secret = ML_KEM.Decaps(private_key, ciphertext)
#     print("\n3. Recipient decapsulated the ciphertext using their private key.")
#     print(f"   -> Recipient's Secret: {recipient_shared_secret.hex()}")

#     # 4. VERIFY
#     # Both parties should now have the exact same 32-byte secret key.
#     assert sender_shared_secret == recipient_shared_secret
#     print("\n✅ Success! The sender's and recipient's shared secrets match perfectly.")

# except NameError:
#     print("Error: One of the required Kyber functions (e.g., 'ML_KEM_Decaps_internal') is not defined.")
#     print("Please ensure all previously implemented Kyber functions are available in your script.")
# except Exception as e:
#     print(f"An error occurred: {e}")

print("## ML-KEM-512 Full Cycle Test ##\n")

# 1. GENERATE RECIPIENT'S KEYS
# A potential recipient generates a key pair.
public_key, private_key = ML_KEM.KeyGen()
print("1. Recipient generated a public/private key pair.")
print("Type check:")
print("   -> Public Key Length:", len(public_key))
print("   -> Private Key Length:", len(private_key))
# print("Modulus check:")
# test = ByteEncode(12, ByteDecode(12, public_key[:384*k]))
# if test == public_key[:384*k]:
#     print("   -> Public Key encoding/decoding is consistent.")

# 2. SENDER ENCAPSULATES
# A sender uses the recipient's public key to create a shared secret
# and a ciphertext to send.
sender_shared_secret, ciphertext = ML_KEM.Encaps(public_key)
print("2. Sender encapsulated a secret, generating a shared secret and a ciphertext.")
print(f"   -> Sender's Secret: {sender_shared_secret.hex()}")

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