from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from pathlib import Path
import datetime
import random
import string
import time
import getpass
from colorama import Fore
import colorama
import os
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# -*- coding: utf-8 -*-
# ===================================================================
#
# Copyright (c) 2020
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ===================================================================


def PASSWORD_CREATE_KEY():
    password_provided = getpass.getpass("Input your password: ")  # This is input in the form of a string
    password = password_provided.encode()  # Convert to type bytes
    salt = b'salt_'  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
    return key


def PRIVATE_ENCRYPT(key):
    input_file = 'private.pem'
    output_file = 'encrypted_private.pem'

    with open(input_file, 'rb') as f:
        data = f.read()

    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)

    with open(output_file, 'wb') as f:
        f.write(encrypted)


def PRIVATE_DECRYPT(key):
    from cryptography.fernet import Fernet
    input_file = 'encrypted_private.pem'
    output_file = 'private.pem'

    with open(input_file, 'rb') as f:
        data = f.read()

    fernet = Fernet(key)
    encrypted = fernet.decrypt(data)

    with open(output_file, 'wb') as f:
        f.write(encrypted)

    # You can delete input_file if you want


def PUBLIC_ENCRYPT(key):
    input_file = 'public.pem'
    output_file = 'encrypted_public.pem'

    with open(input_file, 'rb') as f:
        data = f.read()

    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)

    with open(output_file, 'wb') as f:
        f.write(encrypted)


def PUBLIC_DECRYPT(key):
    from cryptography.fernet import Fernet
    input_file = 'encrypted_public.pem'
    output_file = 'pulbic.pem'

    with open(input_file, 'rb') as f:
        data = f.read()

    fernet = Fernet(key)
    encrypted = fernet.decrypt(data)

    with open(output_file, 'wb') as f:
        f.write(encrypted)

    # You can delete input_file if you want

colorama.init()

clear = lambda: os.system('cls')

i = False

print(Fore.RED)

print('''
________________________________________________________________________________
|                                  #/(#(////(#/#%                              |
|                              #((///////////////////*                         |
|                          #(((((((//            /(/(                          |
|                       *((((((   *((((((((((((((((                            |
|                     #((((/  ((((((((((     ((((((((((                        |
|                   #((((#  ((((((                 /((((((                     |
|                  ((((( ((((((    ((,                #((                      |
|                 #(((( (((((  ,((((((                                         |
|                #(((( (((((  /((((                                            |
|                ((((/#(((((  ((((                                             |
|                *//(( ((((( ((((                                              |
|                *///( ((((# ((((                                              |
|                ((/// ((((# (/(((                                             |
|                 (///( ((((  ,//((                                            |
|                  (///# (((((  ////((#       .(((((/                          |
|                   (///# ((((/#  .(///(/((((((((((                            |
|                    #////# #((//(/    .#(//(                                  |
|                      #////# /(////(                      (((                 |
|                        (/////#,                       #(////(                |
|                           (//////((#            .#(//////(,                  |
|                               (//////////////////////(#                      |
|                                      #/(#(((#/#%                             |
|                                                                              |
________________________________________________________________________________
''')

print(Fore.RESET)

print(Fore.BLUE)

print('''
░█████╗░██████╗░██╗░░░██╗██████╗░████████╗░█████╗░  ░█████╗░██╗░░░░░░██████╗░█████╗░   ██╗░░░██╗░░███╗░░░░░░█████╗░
██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚══██╔══╝██╔══██╗  ██╔══██╗██║░░░░░██╔════╝░██╔══██╗  ██║░░░██║░████║░░░░░██╔══██╗
██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝░░░██║░░░██║░░██║  ███████║██║░░░░░██║░░██╗░██║░░██║  ╚██╗░██╔╝██╔██║░░░░░╚█████╔╝
██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██║░░░██║░░██║  ██╔══██║██║░░░░░██║░░╚██╗██║░░██║  ░╚████╔╝░╚═╝██║░░░░░██╔══██╗
╚█████╔╝██║░░██║░░░██║░░░██║░░░░░░░░██║░░░╚█████╔╝  ██║░░██║███████╗╚██████╔╝╚█████╔╝  ░░╚██╔╝░░███████╗██╗╚█████╔╝
░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░░╚════╝░  ╚═╝░░╚═╝╚══════╝░╚═════╝░░╚════╝░  ░░░╚═╝░░░╚══════╝╚═╝░╚════╝░ 


''')

print(Fore.RESET)


def GET_FILE_EXTENSION(filename):
    file_extension = os.path.splitext(filename)
    file_extension = file_extension[1]
    return file_extension


def Read_File(filename):
    filehandle = ''
    try:
        filehandle = open(filename, "rb")
    except:
        print("Could not open file " + filename)
        Exit()

    text = filehandle.read()
    filehandle.close()
    return text


def Print_Dir():
    x = Path('./')
    items = list(filter(lambda y: y.is_file(), x.iterdir()))
    n = 1

    for item in items:
        print(str(n) + ". " + str(item))
        n += 1
    file = input()
    file_name = items[int(file) - 1]
    return file_name


def Exit():
    time.sleep(5)
    clear()
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


def RSA_FILE_ENCRYPT(data):
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
    file_extension = GET_FILE_EXTENSION(data)
    file_out.write(file_extension + bytes("\n"))
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


def RSA_DECRYPT():
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import AES, PKCS1_OAEP

    file_in = open("encrypted_data.bin", "rb")

    private_key = RSA.import_key(open("private.pem").read())

    enc_session_key, nonce, tag, ciphertext = \
        [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print(data.decode("utf-8"))


def RSA_FILE_DECRYPT(name):
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import AES, PKCS1_OAEP
    with open(name, "r") as f:
        fst_l = f.readline()
        lines = f.readlines()

    with open(name, "w") as f:
        for line in lines:

            if line.strip("\n") != "\n":
                f.write(line)
    file_in = open(name, "rb")

    private_key = RSA.import_key(open("private.pem").read())

    enc_session_key, nonce, tag, ciphertext = \
        [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    file = open("decrypted_data" + fst_l, "w+")
    file.write(data.decode("utf-8"))
    file.close()


print("\nThis is made by Wang Zerui.")
print("\nCryptoAlgo Official Release 1.0\n")

print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
action = input("█                                 What would you like to do, User?                                   █"
               "\n█ 1:  RSA keypair generation                                                                         █"
               "\n█ 2:  Decrypt With combined AES and RSA Encryption                                                   █"
               "\n█ 3:  Encrypt With combined AES and RSA Encryption                                                   █"
               "\n█ 4:  Encrypt Using Timed Cipher (beta)                                                              █"
               "\n█ 5:  Encrypt a file                                                                                 █"
               "\n█ 6:  Decrypt a file                                                                                 █"
               "\n█ 7:  Encrypt private key                                                                            █"
               "\n█ 8:  Decrypt private key                                                                            █"
               "\n█ 9:  Encrypt public key                                                                             █"
               "\n█ 10: Decrypt public key                                                                             █"
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

elif action == 2:
    print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
    print("█                                          Decrypted message:                                        █")
    print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
    RSA_DECRYPT()
    Exit()

elif action == 3:
    print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
    dmata = input("█                                       Data to be encrypted:                                        █\n██████████████████████████████████████████████████████████████████████████████████████████████████████\n")
    RSA_ENCRYPT(dmata)
    print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
    print("█                              SUCCESS! Data is stored in encrypted_data.bin                         █")
    print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
    Exit()

elif action == 4:
    print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
    i = input("█ Do you want to proceed? This function is unstable and no decrypter is developed yet! [y]es or [n]o █\n██████████████████████████████████████████████████████████████████████████████████████████████████████\n")
    if i.lower() == "y":
        password = getpass.getpass("Developer Password")
        TIMED_CIPHER()
    else:
        Exit()

elif action == 5:
    to_be_encrypted = Print_Dir()
    print("This is the file: " + str(to_be_encrypted) + ".")
    Content = Read_File(to_be_encrypted)
    try:
        RSA_ENCRYPT(str(Content))
        print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
        print("█                              SUCCESS! Data is stored in encrypted_data.bin                         █")
        print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
        Exit()
    except:
       print("Please generate the keyfile!")

elif action == 6:
    to_be_decrypted = Print_Dir()
    print("This is the file: " + str(to_be_decrypted) + ".")
    to_be_decrypted = str(to_be_decrypted)
    try:
        RSA_FILE_DECRYPT(to_be_decrypted)
        print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
        print("█                              SUCCESS! Data is stored in decrypted_data.extension                   █")
        print("██████████████████████████████████████████████████████████████████████████████████████████████████████")
        Exit()
    except:
       print("Please put the private key in the same folder!")

elif action == 7:
    PRIVATE_ENCRYPT(PASSWORD_CREATE_KEY())

elif action == 8:
    PRIVATE_DECRYPT(PASSWORD_CREATE_KEY())

elif action == 9:
    PUBLIC_ENCRYPT(PASSWORD_CREATE_KEY())

elif action == 10:
    PUBLIC_DECRYPT(PASSWORD_CREATE_KEY())

else:
    Exit()