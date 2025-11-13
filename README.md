# tlschecker
## golang SSL/TLS network server certificate checker

A library to connect to, and parse, the certificate and chain of a TLS server (ostensibly webservers).
It will take the leaf certificate and any other certificates provided in the TLS handshake and parse some pertinent information from them.

Some features:
* Supports checking the provided certificate and chain against multiple trust-stores
* Attempts to mimic a browser (using uTLS: https://github.com/refraction-networking/utls) to avoid TLS clienthello fingerprinting
* Performs some simple checks on the leaf certificate
  * Name-mismatch (checks the provided FQDN is in or represented in the SAN dnsNames)
  * Validity - is the certificate expired or not
  * Is an OCSP staple provided
  * Is a self-signed root provided in the TLS handshake (which is a pointless waste of bytes on the wire)
* Attempt to extract some HTTP headers
* Fetching of reverse DNS, nameserver, MX and CAA DNS records

Library is also in-use with a simple webserver wrapper at: https://ismycert.com/    
