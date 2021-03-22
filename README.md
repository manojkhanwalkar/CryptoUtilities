# **Crypto Utilities**

A set of functions that I have found useful in dealing with X509 certificates , private keys in DER and PEM formats etc. for application level encryption.
The code has been put together from various snippets found on the internet. 
The utilities cover RSA/EC asymmetric keys as well as AES symmetric key. 

* **JSONUtil** - Wrapper over the Jackson library to convert a java object to json string and vice versa. 
* **IdGenerator** - Wrapper over secure random and uuid to generate int and string id's. 
* **HMACUtil** - Creates a HMAC string. HMAC is used to both authenticate (both sides have access to the secret key) as well as for message integrity. (The HMAC is calculated over the message).
* **CertificateCreatorUtil** - creates a X509 certificate programatically. Takes in a KeyPair and uses that to self sign the certificate. 
* **CertUtil** - Additional utilities to convert certificate to base64 string and vice versa. This is useful when the cert needs to be sent to another service. 
* **CertChainValidator** - utility function to validate a cert using a certificate chain. The cert presented should have been signed by the intermediate cert , which has been signed by the root CA. 
* **CryptUtil** - utilities that deal with creating keys from file as well as encryption and decryption.
* **DHUtil** - Functionality that supports exchange of keys using Diffie Hellman. 
* **SignUtil** - Functionality to sign and verify a message. 
* **HPKEUtil** - Utilities that perform the three steps in a Hybrid Public Key EncryptionScheme. 
    1. KEM - Key Encapsulation Mechanism 
    2. KDF - Key Derivation Function
    3. AEAD - authenticated Encryption with additional data. 
    4. An example in the test package shows how these steps can be used. 
        1. Alice generates a key pair (a,A) and sends A to Bob
        2. Bob generates a key pair (b,B) and chooses a secret S.  He encrypts the secret using A and creates ES. He then sends B and ES to Alice. 
        3. Alice generates a shared secret using a,B and S. (S is obtained by decrypting ES using a) 
        4. Bob generates the same shared secret using b,A and S. 
        5. Both Alice and Bob then feed the shared secret to a KDF to generate a symmetric key. 
        6. This key will be used in the AEAD algorithm along with a Nonce for encrypting the actual messages between them. 
        7. The nonce will be appended at the end of the ciphertext and both sent together to the other party. 
        8. This enables the other party to extract the nonce and use it as input along with the symmetric key to decrypt the message. 

# Useful links and commands 

* https://jamielinux.com/docs/openssl-certificate-authority/sign-server-and-client-certificates.html  (tutorial to generate root , intermediate and leaf certificates.)
* openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem -out private.der -nocrypt (openssl command to convert from pem to der format)
