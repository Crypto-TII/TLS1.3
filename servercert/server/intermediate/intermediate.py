# script to generate intermediate certificate inter.crt and its private key inter.key
# more elliptic curves, MLDSA options could be added
# intermediate certificates have a lifetime of 1 year
# more certificate details could be provided
# requires openssl 3.50+
# 
# 
# Once created the full certificate chain is verified
# The server's certificate chain is formed from concatenation of the server certificate with the intermediate certificate
#
# OpenSSL by default uses sha256 hashing of certificates before they are signed. By supplying a second parameter this can be changed
# This may impact the signature attached to this certificate, for example changing it from ecdsa_with_sha256 to ecdsa_with_sha384

import sys
import subprocess

if len(sys.argv)!=2 and len(sys.argv)!=3 :
    print("Syntax error")
    print("Valid syntax - python3 intermediate.py <intermediate_method>")
    print("For example - python3 intermediate.py NIST384 sha384")
    exit(2)

method=sys.argv[1]
hash="sha256"
if len(sys.argv)==3 :
    hash=sys.argv[2]
   
hash= "\"-"+hash+"\""
subject="\"/CN=TiigerTLS server intermediate CA\""

if method=="NIST256" :
    subprocess.call("openssl ecparam -name prime256v1 -out ecparam.pem",shell=True)
    subprocess.call("openssl req -new -newkey ec:ecparam.pem -keyout inter.key -out inter.csr -nodes -subj " + subject,shell=True)
    subprocess.call("openssl x509 -req -CAcreateserial -days 365 -extfile tiiger.cnf -extensions int_ca -in inter.csr "+hash+"  -CA root/root.crt -CAkey root/root.key -out inter.crt",shell=True)

if method=="NIST384" :
    subprocess.call("openssl ecparam -name secp384r1 -out ecparam.pem",shell=True)
    subprocess.call("openssl req -new -newkey ec:ecparam.pem  -keyout inter.key -out inter.csr -nodes -subj " + subject,shell=True)
    subprocess.call("openssl x509 -req -CAcreateserial  -days 365 -extfile tiiger.cnf -extensions int_ca -in inter.csr "+hash+"  -CA root/root.crt -CAkey root/root.key -out inter.crt",shell=True)

if method=="RSA1024" :
    subprocess.call("openssl req -new -newkey rsa:1024 -keyout inter.key -out inter.csr -nodes -subj " + subject,shell=True)
    subprocess.call("openssl x509 -req -CAcreateserial -days 365 -extfile tiiger.cnf -extensions int_ca -in inter.csr "+hash+"  -CA root/root.crt -CAkey root/root.key -out inter.crt",shell=True)

if method=="RSA2048" :
    subprocess.call("openssl req -new -newkey rsa:2048 -keyout inter.key -out inter.csr -nodes -subj " + subject,shell=True)
    subprocess.call("openssl x509 -req -CAcreateserial -days 365 -extfile tiiger.cnf -extensions int_ca -in inter.csr "+hash+"  -CA root/root.crt -CAkey root/root.key -out inter.crt",shell=True)

if method=="RSA4096" :
    subprocess.call("openssl req -new -newkey rsa:4096 -keyout inter.key -out inter.csr -nodes -subj " + subject,shell=True)
    subprocess.call("openssl x509 -req -CAcreateserial -days 365 -extfile tiiger.cnf -extensions int_ca -in inter.csr "+hash+"  -CA root/root.crt -CAkey root/root.key -out inter.crt",shell=True)

if method=="ED25519" :
    subprocess.call("openssl genpkey -algorithm ED25519 -out eddsa.key",shell=True)
    subprocess.call("openssl req -new -key eddsa.key -keyout inter.key -out inter.csr -nodes -subj " + subject,shell=True)
    subprocess.call("openssl x509 -req -CAcreateserial -days 365 -extfile tiiger.cnf -extensions int_ca -in inter.csr -CA root/root.crt -CAkey root/root.key -out inter.crt",shell=True)

if method=="ED448" :
    subprocess.call("openssl genpkey -algorithm ED448 -out eddsa.key",shell=True)
    subprocess.call("openssl req -new -key eddsa.key -keyout inter.key -out inter.csr -nodes -subj " + subject,shell=True)
    subprocess.call("openssl x509 -req -CAcreateserial -days 365 -extfile tiiger.cnf -extensions int_ca -in inter.csr -CA root/root.crt -CAkey root/root.key -out inter.crt",shell=True)

if method=="MLDSA65" :
    subprocess.call("openssl req -new -newkey mldsa65 -keyout inter.key -out inter.csr -nodes -subj " + subject,shell=True)
    subprocess.call("openssl x509 -req -CAcreateserial -days 365 -extfile tiiger.cnf -extensions int_ca -in inter.csr -CA root/root.crt -CAkey root/root.key -out inter.crt",shell=True)

subprocess.call("openssl x509 -in inter.crt -text -noout",shell=True)

