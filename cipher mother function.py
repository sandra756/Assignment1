import sys


# A Caesar Cipher Technique
def ceaser_enc(text,s): 
    result = "" 
  
    # traverse text 
    for i in range(len(text)): 
        char = text[i] 
  
        # Encrypt uppercase characters 
        if (char.isupper()): 
            result += chr((ord(char) + s-65) % 26 + 65) 
  
        # Encrypt lowercase characters 
        elif (char.islower()):
            char = char.upper() 
            res = chr((ord(char) + s-65) % 26 + 65) 
            result+= res.lower()
    return result 

def ceaser_dec(text,s): 
    result = "" 
  
    # traverse text 
    for i in range(len(text)): 
        char = text[i] 
  
        # Encrypt uppercase characters 
        if (char.isupper()): 
            result += chr((ord(char) + 65-s) % 26 + 65) 
  
        # Encrypt lowercase characters 
        elif (char.islower()): 
            char = char.upper()
            res = chr((ord(char) + 65-s) % 26 + 65) 
            result +=res.lower()
    return result

# A Affine Cipher Technique

# Extended Euclidean Algorithm for finding modular inverse 
# eg: modinv(7, 26) = 15 
def egcd(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    return gcd, x, y


def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

    # affine cipher encrytion function

# affine cipher encrytion function 
# returns the cipher text 
def affine_encrypt(text, key): 
	''' 
	C = (a*P + b) % 26 
	'''
	result = ""
	for i in range(len(text)):
		char = text[i]
		if (char.isupper()):
			result += chr((( key[0]*(ord(char) - 65) + key[1] ) % 26) + 65)
		elif(char.islower()):
			char = char.upper()
			res= chr((( key[0]*(ord(char) - 65) + key[1] ) % 26) + 65)
			result+= res.lower()

	return result 


# affine cipher decryption function 
# returns original text 
def affine_decrypt(cipher, key): 
	''' 
	P = (a^-1 * (C - b)) % 26 
	'''
	result = ""
	for i in range(len(cipher)):
		char = cipher[i]
		if(char.isupper()):
			result += chr((( modinv(key[0], 26)*(ord(char) - 65 - key[1])) % 26) + 65)
		elif(char.islower()):
			char = char.upper()
			res = chr((( modinv(key[0], 26)*(ord(char) - 65 - key[1])) % 26) + 65)
			result+=res.lower()

	return result

# A Vigenere Cipher Technique

# This function generates the 
# key in a cyclic manner until 
# it's length isn't equal to 
# the length of original text 
def generateKey(string, key):
    
    key = list(key)
    if len(string) == len(key):
        return (key)
    else:
        for i in range(len(string) -
                       len(key)):
            key.append(key[i % len(key)])
    return ("".join(key))


# This function returns the 
# encrypted text generated 
# with the help of the key 
def cipherText(text, key): 
	result = ''
	for i in range(len(text)):
		char = text[i]
		if (char.isupper()):
			result += chr(((ord(char) +ord(key[i])) % 26) + ord('A'))
		elif(char.islower()):
			char = char.upper()
			res = chr(((ord(char) +ord(key[i])) % 26) + ord('A'))
			result+= res.lower()
	return result 
	
# This function decrypts the 
# encrypted text and returns 
# the original text 
def originalText(cipher_text, key): 
	result = ''  
	for i in range(len(cipher_text)):
		char = cipher_text[i]
		if(char.isupper()):
			result += chr(((ord(char) - ord(key[i]) + 26) % 26)+ord('A'))
		elif(char.islower()):
			char = char.upper()
			res = chr(((ord(char) - ord(key[i]) + 26) % 26)+ord('A'))
			result+= res.lower()

	return result 

# def main():

# choose which chiper do you want
file1 = open(sys.argv[3] + ".txt", "r+")
print ("Output of Read function is ")
textfile = file1.read()
print(textfile)
file1.close()

file1 = open(sys.argv[4] + ".txt", "w")

cipher = sys.argv[1]
kind = sys.argv[2]


if cipher == "shift" and kind == "enc":
    text = textfile
    s = int(sys.argv[5])
    print ("Text  : " + text)
    print ("Shift : " + str(s))
    print ('Cipher: ' + ceaser_enc(text, s))
    print("this is enc")
    # \n is placed to indicate EOL (End of Line)
    file1.writelines(ceaser_enc(text, s))
    file1.close()

if cipher == "shift" and kind == "dec":
    text = textfile
    s = int(sys.argv[5])
    print ("Text  : " + text)
    print ("Shift : " + str(s))
    print ("Cipher: " + ceaser_dec(text, s))
    print("this is dec")
    file1.writelines(ceaser_dec(text, s))
    file1.close()


if cipher == "affine" and kind == "enc":
    # declaring text and key
    text = textfile
    #17,20
    key = [int(sys.argv[5]),int(sys.argv[6])]
    affine_encrypted_text = affine_encrypt(text, key)
    print('Encrypted Text: {}'.format(affine_encrypted_text))
    file1.writelines(affine_encrypted_text)
    file1.close()

if cipher == "affine" and kind == "dec":
    text = textfile
    key = [int(sys.argv[5]),int(sys.argv[6])]
    affine_decrypted_text = affine_decrypt(text, key)
    print('Decrypted Text: {}'.format(affine_decrypted_text))
    file1.writelines(affine_decrypted_text)
    file1.close()

if cipher == "vigenere" and kind == "enc":
    string = textfile
    keyword = sys.argv[5]
    key = generateKey(string, keyword)
    cipher_text = cipherText(string,key)
    print("ciphertext :",cipher_text)
    file1.writelines(cipher_text)
    file1.close()

if cipher == "vigenere" and kind == "dec":
    string = textfile
    keyword = sys.argv[5]
    key = generateKey(string, keyword)
    original_text = originalText(string,key)
    print("original/dec text :",original_text)
    file1.writelines(original_text)
    file1.close()

# if __name__ == "__main__":
#	main()
