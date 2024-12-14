# Create test certificate chain

Example script for creating TLS-friendly 3-link certificate chain plus private keys, using Dilithium (ML-DSA) digital signature algorithm. Requires installation of OQS provider.

## create Root CA

    openssl req -provider=oqsprovider -provider=default -new -x509 -days 365 -newkey mldsa65 -keyout mldsa65_CA.key -out mldsa65_CA.crt -nodes -subj "/CN=TiigerTLS root CA"

## create Intermediate CA

    openssl req -provider=oqsprovider -provider=default -new -newkey mldsa65 -keyout mldsa65_intCA.key -out mldsa65_intCA.csr -nodes -subj "/CN=TiigerTLS intermediate CA"
    openssl x509 -provider=oqsprovider -provider=default -req -CAcreateserial -days 365 -extfile myopenssl.cnf -extensions int_ca -in mldsa65_intCA.csr -CA mldsa65_CA.crt -CAkey mldsa65_CA.key -out mldsa65_intCA.crt

## create Server certificate

    openssl req -provider=oqsprovider -provider=default -new -newkey mldsa65 -keyout mldsa65_server.key -out mldsa65_server.csr -nodes -subj "/CN=TiigerTLS server"
    openssl x509 -provider=oqsprovider -provider=default -req -in mldsa65_server.csr -CA mldsa65_intCA.crt -CAkey mldsa65_intCA.key -set_serial 01 -days 365 -out mldsa65_server.crt

## verify and create certificate  chain

    openssl verify -provider=oqsprovider -provider=default -CAfile mldsa65_CA.crt -untrusted mldsa65_intCA.crt mldsa65_server.crt

    cat mldsa65_server.crt mldsa65_intCA.crt > mldsa65_certchain.pem


## create file myopenssl.cnf :

[ req ]

distinguished_name       = distinguished_name

extensions               = int_ca

req_extensions           = int_ca


[ int_ca ]

basicConstraints         = CA:TRUE

[ distinguished_name ]


## Install certs

After running these instructions, provision the TLS server with files *mldsa65_server.key* (private key) and
*mldsa65_certchain.pem*. Provision the TLS clients with *mldsa65_CA.crt*, to be inserted into the root CA store.
