# script to generate enduser certificate enduser.crt and its private key enduser.key
# more elliptic curves, MLDSA options could be added
# enduser certificates have a lifetime of 6 days
# more certificate details could be provided
# requires openssl 3.50+
# 
# Once created the full certificate chain is verified
# The enduser's certificate chain is formed from concatenation of the enduser certificate with the intermediate certificate

import sys
import subprocess

if len(sys.argv)!=2 :
    print("Syntax error")
    print("Valid syntax - python3 enduser.py <enduser_method>")
    print("For example - python3 enduser.py NIST256")
    exit(2)

method=sys.argv[1]

if method=="NIST256" :
    subprocess.call("openssl ecparam -name prime256v1 -out ecparam.pem",shell=True)
    subprocess.call("openssl req -new -newkey ec:ecparam.pem -keyout enduser.key -out enduser.csr -nodes -subj \"/CN=TiigerTLS intermediate CA\"",shell=True)
    subprocess.call("openssl x509 -req -set_serial 01 -days 6 -in enduser.csr -CA intermediate/inter.crt -CAkey intermediate/inter.key -out enduser.crt",shell=True)

if method=="NIST384" :
    subprocess.call("openssl ecparam -name secp384r1 -out ecparam.pem",shell=True)
    subprocess.call("openssl req -new -newkey ec:ecparam.pem -keyout enduser.key -out enduser.csr -nodes -subj \"/CN=TiigerTLS intermediate CA\"",shell=True)
    subprocess.call("openssl x509 -req -set_serial 01 -days 6 -in enduser.csr -CA intermediate/inter.crt -CAkey intermediate/inter.key -out enduser.crt",shell=True)

if method=="RSA1024" :
    subprocess.call("openssl req -new -newkey rsa:1024 -keyout enduser.key -out enduser.csr -nodes -subj \"/CN=TiigerTLS enduser\"",shell=True)
    subprocess.call("openssl x509 -req -in enduser.csr -CA intermediate/inter.crt -CAkey intermediate/inter.key -set_serial 01 -days 6 -out enduser.crt",shell=True)

if method=="RSA2048" :
    subprocess.call("openssl req -new -newkey rsa:2048 -keyout enduser.key -out enduser.csr -nodes -subj \"/CN=TiigerTLS enduser\"",shell=True)
    subprocess.call("openssl x509 -req -in enduser.csr -CA intermediate/inter.crt -CAkey intermediate/inter.key -set_serial 01 -days 6 -out enduser.crt",shell=True)

if method=="RSA4096" :
    subprocess.call("openssl req -new -newkey rsa:4096 -keyout enduser.key -out enduser.csr -nodes -subj \"/CN=TiigerTLS enduser\"",shell=True)
    subprocess.call("openssl x509 -req -in enduser.csr -CA intermediate/inter.crt -CAkey intermediate/inter.key -set_serial 01 -days 6 -out enduser.crt",shell=True)

if method=="ED25519" :
    subprocess.call("openssl genpkey -algorithm ED25519 -out eddsa.key",shell=True)
    subprocess.call("openssl req -new -key eddsa.key -keyout enduser.key -out enduser.csr -nodes -subj \"/CN=TiigerTLS intermediate CA\"",shell=True)
    subprocess.call("openssl x509 -req -set_serial 01 -days 6 -in enduser.csr -CA intermediate/inter.crt -CAkey intermediate/inter.key -out enduser.crt",shell=True)

if method=="ED448" :
    subprocess.call("openssl genpkey -algorithm ED448 -out eddsa.key",shell=True)
    subprocess.call("openssl req -new -key eddsa.key -keyout enduser.key -out enduser.csr -nodes -subj \"/CN=TiigerTLS intermediate CA\"",shell=True)
    subprocess.call("openssl x509 -req -set_serial 01 -days 6 -in enduser.csr -CA intermediate/inter.crt -CAkey intermediate/inter.key -out enduser.crt",shell=True)

if method=="MLDSA65" :
    subprocess.call("openssl req -new -newkey mldsa65 -keyout enduser.key -out enduser.csr -nodes -subj \"/CN=TiigerTLS intermediate CA\"",shell=True)
    subprocess.call("openssl x509 -req -set_serial 01 -days 6 -in enduser.csr -CA intermediate/inter.crt -CAkey intermediate/inter.key -out enduser.crt",shell=True)

subprocess.call("openssl x509 -in enduser.crt -text -noout",shell=True)

subprocess.call("openssl verify -CAfile intermediate/root/root.crt -untrusted intermediate/inter.crt enduser.crt",shell=True)
subprocess.call("cat enduser.crt intermediate/inter.crt > ../certchain.pem",shell=True)
subprocess.call("cp enduser.key ../enduser.key",shell=True)
subprocess.call("cp intermediate/root/root.crt ../root.crt",shell=True)

