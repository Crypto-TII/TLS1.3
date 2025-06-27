# script to generate root certificate root.crt and its private key root.key
# more elliptic curves, MLDSA options could be added
# root certificates have a lifetime of 10 years
# more certificate details could be provided
# requires openssl 3.50+
# 
# Note that root.crt must be in root store of clients if this root of trust is to be accepted

import sys
import subprocess

if len(sys.argv)!=2 :
    print("Syntax error")
    print("Valid syntax - python3 root.py <root_method>")
    print("For example - python3 root.py RSA2048")
    exit(2)

method=sys.argv[1]

if method=="NIST256" :
    subprocess.call("openssl ecparam -name prime256v1 -out ecparam.pem",shell=True)
    subprocess.call("openssl req -new -x509 -days 3650 -newkey ec:ecparam.pem -keyout root.key -out root.crt -nodes -subj \"/CN=TiigerTLS root CA\"",shell=True)

if method=="NIST384" :
    subprocess.call("openssl ecparam -name secp384r1 -out ecparam.pem",shell=True)
    subprocess.call("openssl req -new -x509 -days 3650 -newkey ec:ecparam.pem -keyout root.key -out root.crt -nodes -subj \"/CN=TiigerTLS root CA\"",shell=True)

if method=="RSA1024" :
    subprocess.call("openssl req -new -x509 -days 3650 -newkey rsa:1024 -keyout root.key -out root.crt -nodes -subj \"/CN=TiigerTLS root CA\"",shell=True)

if method=="RSA2048" :
    subprocess.call("openssl req -new -x509 -days 3650 -newkey rsa:2048 -keyout root.key -out root.crt -nodes -subj \"/CN=TiigerTLS root CA\"",shell=True)

if method=="RSA4096" :
    subprocess.call("openssl req -new -x509 -days 3650 -newkey rsa:4096 -keyout root.key -out root.crt -nodes -subj \"/CN=TiigerTLS root CA\"",shell=True)

if method=="ED25519" :
    subprocess.call("openssl genpkey -algorithm ED25519 -out eddsa.key",shell=True)
    subprocess.call("openssl req -new -x509 -days 3650 -key eddsa.key -keyout root.key -out root.crt -nodes -subj \"/CN=TiigerTLS root CA\"",shell=True)
if method=="ED448" :
    subprocess.call("openssl genpkey -algorithm ED448 -out eddsa.key",shell=True)
    subprocess.call("openssl req -new -x509 -days 3650 -key eddsa.key -keyout root.key -out root.crt -nodes -subj \"/CN=TiigerTLS root CA\"",shell=True)

if method=="MLDSA65" :
    subprocess.call("openssl req -new -x509 -days 3650 -newkey mldsa65 -keyout root.key -out root.crt -nodes -subj \"/CN=TiigerTLS root CA\"",shell=True)


subprocess.call("openssl x509 -in root.crt -text -noout",shell=True)
