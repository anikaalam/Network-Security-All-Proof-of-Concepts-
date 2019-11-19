#import math 
#import string
#ciphertext = "14 17 3 28 27 24 16 4 14 9 13 24 1 19 23 1 28 26 5 27 24 16 4 14 26 31 23 3 14 17 14 17 26 24 28 1 4 24 3 19 3 14 3 22 26"
print('Enter filename:')
x = raw_input()
ciphertext = open(x, "r")
chars = ciphertext.read().split(" ")

plaintext = "" 
charArray = [];
numArray = []

for char in chars:
	newchar = int(char.strip() or 0)
	if (newchar !=0): 
		decrypt = (newchar**7)%33
		charArray.append(decrypt)
print charArray

string = []
for chars in charArray:   # Loop through each element
        chars = chr(int(chars) + 64) # Convert number to letter
        string.append(str(chars))
print "Decoded string: "
print string     # Return cipher string

#sentence = ['this','is','a','sentence']
con = ""
for i in string:
    con += str(i) + ""
con = con[:-1]
print con





