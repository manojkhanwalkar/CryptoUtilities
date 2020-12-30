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
# Useful links and commands 

* https://jamielinux.com/docs/openssl-certificate-authority/sign-server-and-client-certificates.html  (tutorial to generate root , intermediate and leaf certificates.)
* openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem -out private.der -nocrypt (openssl command to convert from pem to der format)
