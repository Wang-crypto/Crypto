from Crypto.PublicKey import RSA
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import datetime
import random
import string
import time

i = False

def Exit():
    print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
    print("█             Thank you for using this program! It will automatically exit in 10 seconds.            █")
    print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
    time.sleep(10)
    exit(0)

def RSA_ENCRYPT(data):
    data = data.encode("utf-8")
    file_out = open("encrypted_data.bin", "wb")

    recipient_key = RSA.import_key(open("public.pem").read())
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    [file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
    file_out.close()

def RSA_GENERATION():
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("public.pem", "wb")
    file_out.write(public_key)
    file_out.close()


def TIMED_CIPHER():
    ga = datetime.datetime.now().hour

    def insertChar(mystring, position, chartoinsert):
        mystring = mystring[:position] + chartoinsert + mystring[position:]
        return mystring

    while True:
        hey = 0
        dt = datetime.datetime.today()
        mon = dt.month
        hmm = dt.day

        if hmm > 26:
            hmm = hmm - 26

        # we need 2 helper mappings, from letters to ints and the inverse
        L2I = dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ", range(26)))
        I2L = dict(zip(range(26), "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))

        key = hmm
        plaintext = input("Put message: \n\n")

        # encipher
        ciphertext = ""
        for c in plaintext.upper():
            if c.isalpha():
                ciphertext += I2L[(L2I[c] + key) % 26]
            else:
                ciphertext += c
        longi = len(ciphertext)
        ahh = 0

        while hey < longi:
            lol = 0
            while lol < mon * ga:
                ciphertext = insertChar(ciphertext, ahh, random.choice(string.ascii_letters))
                lol += 1
            while lol < mon * ga:
                ciphertext = insertChar(ciphertext, ahh, random.choice(string.ascii_letters))
                lol += 1
            ahh += mon + 1
            hey += 1

        ciphertext.replace(" ", "fwc")
        for c in ciphertext.upper():
            if c.isalpha():
                ciphertext += I2L[(L2I[c] + key) % 26]
            else:
                ciphertext += c
        print("copy this and send: \n\n" + ciphertext.upper() + "\n\n")


print("\nThis is made by Wang Zerui.")
print("\nCryptoAlgo Beta\n")

print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
action = input("█                                 What would you like to do, User?                                   █"
               "\n█ 1: RSA keypair generation                                                                          █"
               "\n█ 2: AES keyset generation                                                                           █"
               "\n█ 3: Decrypt With RSA                                                                                █"
               "\n█ 4: Encrypt With RSA                                                                                █"
               "\n█ 5: Encrypt                                                                                         █"
               "\n█ 6: Decrypt                                                                                         █"
               "\n█ 7: Encrypt Using Timed Cipher (beta)                                                               █"
               "\n█ Pressing any other key will cause the program to exit.                                             █"
               "\n██████████████████████████████████████████████████████████████████████████████████████████████████████\n")
try:
    action = int(action)
except ValueError:
    Exit()

if action == 1:
    print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
    print("█ Welcome to the RSA key generator! Tha key will be generated in the same folder this program is in. █")
    print("█        This may take some time and seem unresponsive. Please do not shut down this program.        █")
    print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
    RSA_GENERATION()
    Exit()

elif action == 4:
    data = input("Encrypted data")
    RSA_ENCRYPT(data)

elif action == 7:
    print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
    i = input("█ Do you want to proceed? This function is unstable and no decrypter is developed yet! [y]es or [n]o █\n██████████████████████████████████████████████████████████████████████████████████████████████████████\n")
    if i.lower() == "y":
        TIMED_CIPHER()
    else:
        Exit()
