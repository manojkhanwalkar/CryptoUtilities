# **Crypto Utilities**

A set of functions that I have found useful in dealing with X509 certificates , private keys in DER and PEM formats etc. for application level encryption.
The utilities cover RSA/EC asymmetric keys as well as AES symmetric key. 

* JSONUtil - Wrapper over the Jackson library to convert a java object to json string and vice versa. 
* IdGenerator - Wrapper over secure random and uuid to generate int and string id's. 
* HMACUtil - Creates a HMAC string. HMAC is used to both authenticate (both sides have access to the secret key) as well as for message integrity. (The HMAC is calculated over the message).

Work in Progress 