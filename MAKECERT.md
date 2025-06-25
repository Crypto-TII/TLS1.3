# Create test certificate chain

Example script for creating TLS-friendly 3-link certificate chain plus private keys, using Dilithium (ML-DSA) digital signature algorithm. Requires openssl version 3.5+

## first create file myopenssl.cnf :

    [ req ]
    distinguished_name       = distinguished_name
    extensions               = int_ca
    req_extensions           = int_ca

    [ int_ca ]
    basicConstraints         = CA:TRUE

    [ distinguished_name ]

## then create Root CA

    openssl req -new -x509 -days 365 -newkey mldsa65 -keyout mldsa65_CA.key -out mldsa65_CA.crt -nodes -subj "/CN=TiigerTLS root CA"

## create Intermediate CA

    openssl req -new -newkey mldsa65 -keyout mldsa65_intCA.key -out mldsa65_intCA.csr -nodes -subj "/CN=TiigerTLS intermediate CA"
    openssl x509 -req -CAcreateserial -days 365 -extfile myopenssl.cnf -extensions int_ca -in mldsa65_intCA.csr -CA mldsa65_CA.crt -CAkey mldsa65_CA.key -out mldsa65_intCA.crt

## create Server certificate

    openssl req -new -newkey mldsa65 -keyout mldsa65_server.key -out mldsa65_server.csr -nodes -subj "/CN=TiigerTLS server"
    openssl x509 -req -in mldsa65_server.csr -CA mldsa65_intCA.crt -CAkey mldsa65_intCA.key -set_serial 01 -days 365 -out mldsa65_server.crt

## verify and create certificate  chain

    openssl verify -CAfile mldsa65_CA.crt -untrusted mldsa65_intCA.crt mldsa65_server.crt

    cat mldsa65_server.crt mldsa65_intCA.crt > mldsa65_certchain.pem


## Install certs

After running these instructions, provision the TLS server (*servercert.rs*) from files *mldsa65_server.key* (private key) and
*mldsa65_certchain.pem*. Provision the TLS clients (*cacerts.rs* and *tls_cacerts.cpp*) from *mldsa65_CA.crt*, to be inserted 
into the root CA store.

## ECC chains

To create a certificate chain using elliptic curves, change the *-newkey* parameter to for example *-newkey ec:<(openssl ecparam -name prime256v1)* 
