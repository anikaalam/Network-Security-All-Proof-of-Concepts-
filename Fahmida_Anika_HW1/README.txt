HW-1 : RSA and CTR 

[P1]

a)privacy; 
b)privacy; confidentiality;
c)data/source integrity; availability; confidentiality; authentication
d)data integrity; system integrity; authenticity; availability 



[P2]
people = 20, establish pairwise secure communications 

(a) Total number of keys created for symmetric distribution:

n users = n(n-1)/2 keys 
20 users = 20(20-1)/2 = 190 
=> 190 total keys for sym distribution 

(b) Asym key distribution like RSA, each user had 2 keys, private and public keys + there will be 1 key that will be shared between each 2 users 

Total priv + pub key for 20 people = 20*2 = 40 
Total shared key = 40/2 = 20 

Total asym key distributed = 40 + 20 = 60

[P3] D-H protocol 

(a) given p =29 g = 2 ,a = 5 b = 3

Alice will send to Bob ->R1 = 2^a mod 29
Bob will send to Alice ->R2 = 2^b mod 29

Shared key, k = g^ab mod p
	    k = 2^(5*3) mod 29
	    k = 29 (key) 

(b) given p = 7 g = 3  R1 = 6(A->B) 

i. 
R1 = g^a mod p
=> 6 = 3^a mod 7
=> a = 9,15, 21

Attacker was able to obtain 3 possible values of a from given info 

ii. R2 = 5

Bob, R2 = g^b mod p
=> 5 = 3^b mod 7
=> b = 11, 17, 23

using, a = 9 and b = 11 

Shared key, k = g^ab mod p

k = 3^(11*9) mod 7
k = 6

Yes, attacker can obtain shared key, he had to obtain Bob's b first using Bob's R1
[P4] RSA

(a)

public key : (N,e) -> (33,33) - given 
Private key: (N, d) -> find d

To decrypt: 
m = c^d mod N = (m^ed)mod N
when c = 20 (from given ciphertext)

=> 20^3 mod 33 = m^3d mod 33
=> d = 7 

RSA private key: (33, 7)


[P5] CTR|XOR 
CTR decrption: Pi = Ci XOR Ek(nonce||i)
Given, C1 and P1, XOR output of C1 and P1 using www.XOR.pw:
		
C1 XOR P1 = Ek(nonce||i)
 
Ek(nonce||i)= 30516a576e3d4991b52777d7ebbe5b0445bf0b128e2ec0d5cd3eed5f91d83ab1a

Therefore: 
P2 = C2 XOR Ek(nonce||i)

P2 in hex: 54686973206973206120736563726574202020436f6e666964656e7469616c21
P2 in Ascii: This is a secret   Confidential!
