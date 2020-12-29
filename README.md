# **Crypto Utilities**

A set of functions that I have found useful in dealing with X509 certificates , private keys in DER and PEM formats etc. for application level encryption.
The utilities cover RSA/EC asymmetric keys as well as AES symmetric key. 

* JSONUtil - Wrapper over the Jackson library to convert a java object to json string and vice versa. 
* IdGenerator - Wrapper over secure random and uuid to generate int and string id's. 
* HMACUtil - Creates a HMAC string. HMAC is used to both authenticate (both sides have access to the secret key) as well as for message integrity. (The HMAC is calculated over the message).
* CertificateCreatorUtil - creates a X509 certificate programatically. Takes in a KeyPair and uses that to self sign the certificate. 
* CertUtil - Additional utilities to convert certificate to base64 string and vice versa. This is useful when the cert needs to be sent to another service. 

# Useful links and commands 

* https://jamielinux.com/docs/openssl-certificate-authority/sign-server-and-client-certificates.html  (tutorial to generate root , intermediate and leaf certificates.)
* openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem -out private.der -nocrypt (openssl command to convert from pem to der format)

Work in Progress 