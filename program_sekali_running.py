import math
import sys

from Crypto.Cipher import Blowfish
from Crypto import Random
from struct import pack

from ast import literal_eval
import wave

""" === KEPERLUAN HELPERS RC6 === """

#rotate right input x, by n bits
def ROR(x, n, bits = 32):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))

#rotate left input x, by n bits
def ROL(x, n, bits = 32):
    return ROR(x, bits - n,bits)

#convert input sentence into blocks of binary
#creates 4 blocks of binary each of 32 bits.
def blockConverter(sentence):
    encoded = []
    res = ""
    for i in range(0,len(sentence)):
        if i%4==0 and i!=0 :
            encoded.append(res)
            res = ""
        temp = bin(ord(sentence[i]))[2:]
        if len(temp) <8:
            temp = "0"*(8-len(temp)) + temp
        res = res + temp
    encoded.append(res)
    return encoded

#converts 4 blocks array of long int into string
def deBlocker(blocks):
    s = ""
    for ele in blocks:
        temp =bin(ele)[2:]
        if len(temp) <32:
            temp = "0"*(32-len(temp)) + temp
        for i in range(0,4):
            s=s+chr(int(temp[i*8:(i+1)*8],2))
    return s

#generate key s[0... 2r+3] from given input string userkey
def generateKey(userkey):
    r=12
    w=32
    b=len(userkey)
    modulo = 2**32
    s=(2*r+4)*[0]
    s[0]=0xB7E15163
    for i in range(1,2*r+4):
        s[i]=(s[i-1]+0x9E3779B9)%(2**w)
    encoded = blockConverter(userkey)
    #print encoded
    enlength = len(encoded)
    l = enlength*[0]
    for i in range(1,enlength+1):
        l[enlength-i]=int(encoded[i-1],2)
    
    v = 3*max(enlength,2*r+4)
    A=B=i=j=0
    
    for index in range(0,v):
        A = s[i] = ROL((s[i] + A + B)%modulo,3,32)
        B = l[j] = ROL((l[j] + A + B)%modulo,(A+B)%32,32) 
        i = (i + 1) % (2*r + 4)
        j = (j + 1) % enlength
    return s


""" === KEPERLUAN ENCRYPT RC6 """

def encrypt_rc6(sentence,s):
    encoded = blockConverter(sentence)
    enlength = len(encoded)
    A = int(encoded[0],2)
    B = int(encoded[1],2)
    C = int(encoded[2],2)
    D = int(encoded[3],2)
    orgi = []
    orgi.append(A)
    orgi.append(B)
    orgi.append(C)
    orgi.append(D)
    r=12
    w=32
    modulo = 2**32
    lgw = 5
    B = (B + s[0])%modulo
    D = (D + s[1])%modulo 
    for i in range(1,r+1):
        t_temp = (B*(2*B + 1))%modulo 
        t = ROL(t_temp,lgw,32)
        u_temp = (D*(2*D + 1))%modulo
        u = ROL(u_temp,lgw,32)
        tmod=t%32
        umod=u%32
        A = (ROL(A^t,umod,32) + s[2*i])%modulo 
        C = (ROL(C^u,tmod,32) + s[2*i+ 1])%modulo
        (A, B, C, D)  =  (B, C, D, A)
    A = (A + s[2*r + 2])%modulo 
    C = (C + s[2*r + 3])%modulo
    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    return orgi,cipher


def proses_rc6_encrypt(key):
    s = generateKey(key)

    # add data yang akan di enkripsi
    f = open('plaintext.txt', 'r')
    sentence = f.readline()[:16]

    orgi, cipher = encrypt_rc6(sentence, s)
    esentence = deBlocker(cipher)

    print("nilai plaintext : ", sentence)
    #print("\n\nEncrypted string : ", esentence)

    # create file hasil enkripsi RC6
    f = open('ciphertextRC6.txt', 'w')
    f.write(esentence)
    f.close()

    return "ciphertextRC6.txt"


""" === KEPERLUAN DECRYPT RC6 """ 

def decrypt_rc6(esentence, s):
    encoded = blockConverter(esentence)
    enlength = len(encoded)
    A = int(encoded[0],2)
    B = int(encoded[1],2)
    C = int(encoded[2],2)
    D = int(encoded[3],2)
    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    r=12
    w=32
    modulo = 2**32
    lgw = 5
    C = (C - s[2*r+3])%modulo
    A = (A - s[2*r+2])%modulo
    for j in range(1,r+1):
        i = r+1-j
        (A, B, C, D) = (D, A, B, C)
        u_temp = (D*(2*D + 1))%modulo
        u = ROL(u_temp,lgw,32)
        t_temp = (B*(2*B + 1))%modulo 
        t = ROL(t_temp,lgw,32)
        tmod=t%32
        umod=u%32
        C = (ROR((C-s[2*i+1])%modulo,tmod,32)  ^u)  
        A = (ROR((A-s[2*i])%modulo,umod,32)   ^t) 
    D = (D - s[1])%modulo 
    B = (B - s[0])%modulo
    orgi = []
    orgi.append(A)
    orgi.append(B)
    orgi.append(C)
    orgi.append(D)
    return cipher,orgi


def proses_rc6_decrypt(key, filename, add_digit):
    s = generateKey(key)

    #print("nilai filename : ", filename)

    # add data yang akan di dekripsi
    f = open(filename, "r")
    if not f:
        print("Encrypted input not found in textBlowfish.txt")
        sys.exit(0)
    else:
        esentence = f.readline()
        esentence = esentence[:-add_digit]

    #print("\n\n")
    #print("nilai esentence : ", esentence)
    #print("\n\n")

    cipher, orgi = decrypt_rc6(esentence, s)
    sentence = deBlocker(orgi)

    print("nilai sentence : ", sentence)

    # create file hasil dekripsi
    f = open("textRC6.txt", "w")
    f.write(sentence)
    f.close()

    return "textRC6.txt"


""" === KEPERLUAN ENCRYPT BLOWFISH === """

def encrypt_blowfish(key, filename):
    bs = Blowfish.block_size
    iv = Random.new().read(bs)

    #print("\n\nnilai iv - encrypt : ", iv)
    #print("len iv : ", len(iv))
    key = literal_eval("b'{}'".format(key))
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    
    # read file ciphertextRC6
    f = open(filename, "r")
    plaintext = f.readline()

    add_digit = 0
    if len(plaintext.encode()) % 8 != 0:
        add_digit = 8 - len(plaintext.encode()) % 8
        plaintext = plaintext + " " * add_digit

    encrypt_msg = iv + cipher.encrypt(plaintext)

    # create file ciphertext Blowfish
    f = open("ciphertextBlowfish.txt", "w")
    f.write(str(encrypt_msg)[2:-1])
    f.close()

    return "ciphertextBlowfish.txt", add_digit


""" === KEPERLUAN DECRYPT BLOWFISH === """

def decrypt_blowfish(key, filename):
    bs = Blowfish.block_size
    
    #key = literal_eval("b'{}'".format(key))
    #print("nilai key : ", key)
    # read file hasil ekstraksi dari file audio
    f = open(filename, "r")
    encrypt_msg = f.read()

    #print("\n\nnilai encrypt_msg : ", encrypt_msg)

    # convert to propery bytes format
    encrypt_msg = literal_eval("b'{}'".format(encrypt_msg))

    iv = encrypt_msg[:bs]
    decrypt_msg = encrypt_msg[bs:]

    #print("\n\nnilai iv : ", iv)
    #print("\n\nniai decrypt_msg : ", decrypt_msg)
    #print("\n\nnilai type(decrypt_msg) : ", type(decrypt_msg))

    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    msg = cipher.decrypt(decrypt_msg)
    #print("\n\nhasil decrypt Blowfish : ", type(msg))
    #print("\n\nhasil decrypt : ", msg)

    f = open("textBlowfish.txt", "w")
    f.write(str(msg.decode()))
    f.close()

    return "textBlowfish.txt"


""" === KEPERLUAN INPUT TEXT TO AUDIO === """

def input_text_audio(filename_text, filename_audio):
    # read file audio yang akan disisipi text
    song = wave.open(filename_audio, mode="rb")
    frame_bytes = bytearray(list(song.readframes(song.getnframes())))

    # read file text yang akan disisipkan
    f = open(filename_text, "r")
    string = f.readline()
    string = string + int((len(frame_bytes) - (len(string)*8*8)) / 8) * '#'

    bits = list(map(int, ''.join([bin(ord(i)).lstrip('0b').rjust(8,'0') for i in string])))

    for i, bit in enumerate(bits):
        frame_bytes[i] = (frame_bytes[i] & 254) | bit

    frame_modified = bytes(frame_bytes)

    # create file audio
    with wave.open("mgdrown_nrremix_result.wav", "wb") as fd:
        fd.setparams(song.getparams())
        fd.writeframes(frame_modified)
    song.close()

    return "mgdrown_nrremix_result.wav"


""" === KEPERLUAN OUTPUT TEXT FROM AUDIO === """

def output_text_audio(filename_audio):
    # read file audio
    song = wave.open(filename_audio, mode="rb")

    # convert audio to byte array
    frame_bytes = bytearray(list(song.readframes(song.getnframes())))

    # Extract the LSB of each byte
    extracted = [frame_bytes[i] & 1 for i in range(len(frame_bytes))]

    # convert byte array back to string
    string = "".join(chr(int("".join(map(str,extracted[i: i+8 ])), 2)) for i in range(0, len(extracted), 8))
    # cut off at the filler characters
    decode = string.split("###")[0]

    # create text result
    f = open("textExtraction.txt", "w")
    f.write(decode)
    f.close()

    song.close()

    return "textExtraction.txt"


""" === MAIN PROSES === """

def main():
    # key pemrosesan
    key = "ini key proseses"
    #print("len(key) : ", len(key))

    # enkripsi proses
    result_enkripsi_rc6 = proses_rc6_encrypt(key=key)
    result_enkripsi_blowfish, add_digit = encrypt_blowfish(key=key, filename=result_enkripsi_rc6)
    #print("add_digit : ", add_digit)

    # audio proses
    result_input_text_audio = input_text_audio(filename_text=result_enkripsi_blowfish,
                                               filename_audio="mgdrown_nrremix.wav")

    result_output_text_audio = output_text_audio(filename_audio=result_input_text_audio)

    # dekripsi proses
    result_dekripsi_blowfish = decrypt_blowfish(key=key, filename=result_output_text_audio)
    result_dekripsi_rc6 = proses_rc6_decrypt(key=key, filename=result_dekripsi_blowfish, add_digit=add_digit)
    

if __name__ == "__main__":
    main()