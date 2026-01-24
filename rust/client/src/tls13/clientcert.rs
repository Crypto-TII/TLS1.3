
//! Client Certificate and private key stored here

use crate::config::*;
use crate::tls13::utils;
use crate::tls13::x509;
use crate::tls13::x509::*;
use crate::sal_m::sal;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

// ECC-SS self-signed keys 256 bit. Certificate expires Jan 2026

pub const MY_PRIVATE: &str = 
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwmEaEau6Dybv+N5d\
1v+BkVWYQZhNsNu/X8JPZzZgTd6hRANCAAQvn/UmTjXDk41r0ow6+LfsA3qdKV2K\
1eRIv6axrsfEKds9poshRyvEgy4M8WYZlyOOchiVcO2jTyxvH1Xun/WH";

pub const MY_CERTCHAIN: [&str;2] = [ 
"MIICdDCCAhmgAwIBAgIUPDaj+Hv0/zO5MmUpKn2EvnrRJrEwCgYIKoZIzj0EAwIw\
gY4xCzAJBgNVBAYTAklFMRAwDgYDVQQIDAdJcmVsYW5kMQ8wDQYDVQQHDAZEdWJs\
aW4xDzANBgNVBAoMBlNoYW11czERMA8GA1UECwwIUmVzZWFyY2gxEzARBgNVBAMM\
Ck1pa2UgU2NvdHQxIzAhBgkqhkiG9w0BCQEWFG1pY2hhZWwuc2NvdHRAdGlpLmFl\
MB4XDTIzMDQyNjE4MDMwNloXDTI2MDEyMDE4MDMwNlowgY4xCzAJBgNVBAYTAklF\
MRAwDgYDVQQIDAdJcmVsYW5kMQ8wDQYDVQQHDAZEdWJsaW4xDzANBgNVBAoMBlNo\
YW11czERMA8GA1UECwwIUmVzZWFyY2gxEzARBgNVBAMMCk1pa2UgU2NvdHQxIzAh\
BgkqhkiG9w0BCQEWFG1pY2hhZWwuc2NvdHRAdGlpLmFlMFkwEwYHKoZIzj0CAQYI\
KoZIzj0DAQcDQgAEL5/1Jk41w5ONa9KMOvi37AN6nSlditXkSL+msa7HxCnbPaaL\
IUcrxIMuDPFmGZcjjnIYlXDto08sbx9V7p/1h6NTMFEwHQYDVR0OBBYEFDOMT9fP\
R8x88EC9TzUeTZ8Af4o7MB8GA1UdIwQYMBaAFDOMT9fPR8x88EC9TzUeTZ8Af4o7\
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAMjslzs/qSlwxY5q\
PIj1zkn3Z7bknRV3ICsVzl9hhGJBAiEAkhUnhBuPHgTuGJ3c1xGIIEjNDKvW7Fhc\
94BzAlOIACk=",""];

fn get_sigalg(pk: &x509::PKTYPE) -> u16 {
    if pk.kind==x509::ECC {
        if pk.curve==x509::USE_NIST256 {
            return ECDSA_SECP256R1_SHA256; // as long as this is a client capability
        }
        if pk.curve==x509::USE_NIST384 {
            return ECDSA_SECP384R1_SHA384;  // as long as this is a client capability
        }
    }
    if pk.kind==x509::RSA {
       return RSA_PSS_RSAE_SHA256;
    }
    if pk.kind==x509::DLM {
        return MLDSA65;
    }
    if pk.kind==x509::HY1 {
        return MLDSA44_P256;
    }
    if pk.kind==x509::ECD {
        if pk.curve==x509::USE_ED25519 {
            return ED25519;
        }
        if pk.curve==x509::USE_ED448 {
            return ED448;
        }
    }            
    return 0;    
}

// add X509 signature type to TLS signature capability requirements list
fn add_cert_sig_type(pk: &x509::PKTYPE,reqlen: usize,requirements: &mut [u16]) -> usize {
    let mut len=reqlen;
    if pk.kind==x509::ECC {
        if pk.curve==x509::USE_NIST256 {
            requirements[len]=ECDSA_SECP256R1_SHA256; // as long as this is a client capability
            len+=1;
        }
        if pk.curve==x509::USE_NIST384 {
            requirements[len]=ECDSA_SECP384R1_SHA384;  // as long as this is a client capability
            len+=1;
        }
        return len;
    }
    if pk.kind==x509::RSA {
        if pk.hash==x509::H256 {
            requirements[len]=RSA_PKCS1_SHA256;
            len+=1;
        }
        if pk.hash==x509::H384 {
            requirements[len]=RSA_PKCS1_SHA384;
            len+=1;
        }
        if pk.hash==x509::H512 {
            requirements[len]=RSA_PKCS1_SHA512;
            len+=1;
        }
        return len;
    }

    if pk.kind==x509::DLM {
        requirements[len]=MLDSA65;
        len+=1;
        return len;
    }
    if pk.kind==x509::HY1 {
        requirements[len]=MLDSA44_P256;
        len+=1;
        requirements[len]=MLDSA44;
        len+=1;
        requirements[len]=ECDSA_SECP256R1_SHA384;
        len+=1;
        return len;  // *** also need to check that secp256r1 is supported - kind indicates that both signature keys are in privkey
    }
    if pk.kind==x509::ECD {
        if pk.curve==x509::USE_ED25519 {
            requirements[len]=ED25519;
            len+=1;
            return len;
        }
        if pk.curve==x509::USE_ED448 {
            requirements[len]=ED448;
            len+=1;
            return len;
        }
    }
    return len;
}

// client credential, its certificate chain, its secret key
#[derive(Copy,Clone)]
pub struct CREDENTIAL {
    pub certchain: [u8;MAX_CLIENT_CHAIN_SIZE],
    pub certchain_len: usize,
    pub publickey: [u8;MAX_SIG_PUBLIC_KEY],
    pub publickey_len: usize,
    pub secretkey: [u8;MAX_SIG_SECRET_KEY],
    pub secretkey_len: usize,
    pub requirements: [u16;16],    // signature algorithms that will be needed by the server
    pub nreqs: usize,
    pub nreqsraw: usize,
    pub sigalg: u16,
}

impl CREDENTIAL {
    pub fn new() -> CREDENTIAL  { 
        let this=CREDENTIAL {
            certchain:[0;MAX_CLIENT_CHAIN_SIZE], // certificate chain to be sent to server
            certchain_len: 0,
            publickey: [0;MAX_SIG_PUBLIC_KEY],  // server public key
            publickey_len: 0,
            secretkey: [0;MAX_SIG_SECRET_KEY],  // server secret key
            secretkey_len: 0,
            requirements: [0;16],  // server requirements if they are to process my cert
            nreqs: 0,
            nreqsraw: 0, // fewer signature requirements for raw public key
            sigalg: 0, // my signature algorithm
        };
        return this;
    }

// create credential structure from base64 inputs of the private key and the certificate chain
    pub fn set(&mut self) -> bool  {
        let mut sc:[u8;MAX_CERT_SIZE]=[0;MAX_CERT_SIZE]; // workspace
        let mut sig:[u8;MAX_SIGNATURE_SIZE]=[0;MAX_SIGNATURE_SIZE];
       
       	let privkey:&str; let stored_chain:[&str;2];
        let mut secret=String::from("");  
        let mut certchain:[String;2]=[String::from(""),String::from("")];   
        
        if CLIENT_CERT==NO_CERT {
            return false;
        }
        if CLIENT_CERT==FROM_ROM {       
            privkey=MY_PRIVATE; stored_chain=MY_CERTCHAIN;       
        } else {

            let mut path = Path::new("../../../clientcert/client.key");
            let mut display = path.display();

            let mut file = match File::open(path) {
                Err(why) => panic!("Must run from project src directory, couldn't find {}: {}", display, why),
                Ok(file) => file,
            };
            let mut reader = BufReader::new(file);
            for line in reader.lines() {
                let next=line.unwrap();
                let nextstr=next.as_str();
                if nextstr.chars().nth(0).unwrap()=='-' {
                    continue;
                }
                secret+=nextstr;
            }   
            privkey=secret.as_str();
            path=Path::new("../../../clientcert/certchain.pem" );
            display=path.display();
            file = match File::open(path) {
                Err(why) => panic!("Must run from project src directory, couldn't find {}: {}", display, why),
                Ok(file) => file,
            };
            reader = BufReader::new(file);
            let mut i=0;
            for line in reader.lines().skip(1) {
                let next=line.unwrap();
                let nextstr=next.as_str();
                if nextstr.chars().nth(0).unwrap()=='-' {
                    i=1;
                    continue;
                }
                certchain[i]+=nextstr;
            }            
            stored_chain=[certchain[0].as_str(),certchain[1].as_str()];
        }         
        let mut sclen=utils::decode_b64(&privkey.as_bytes(),&mut sc);  // get secret key structure
        let mut pk=x509::extract_private_key(&sc[0..sclen],&mut self.secretkey);    // extract secret key
        self.secretkey_len=pk.len;
	let kind=get_sigalg(&pk); // Client must implement algorithm to do signature - make sure its in the SAL!
	self.sigalg=kind;
        
//println!("kind= {:x}",kind);
        let mut sig_algs:[u16;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS];
        let nsa=sal::sigs(&mut sig_algs);
        let mut offered=false;
        for i in 0..nsa {
//println!("sigalgs= {:x}",sig_algs[i]);
            if kind==sig_algs[i] {
               offered=true;
            }
        } 
        if !offered { return false; } 

 // chain length is 1 (self-signed) or 2 (server+intermediate - root is not transmitted)
       
        let mut b=stored_chain[0].as_bytes();
        sclen=utils::decode_b64(&b,&mut sc);

// start building certificate chain
        self.certchain_len=utils::append_int(&mut self.certchain,self.certchain_len,sclen,3);
        self.certchain_len=utils::append_bytes(&mut self.certchain,self.certchain_len,&sc[0..sclen]);
        self.certchain_len=utils::append_int(&mut self.certchain,self.certchain_len,0,2);
        pk=extract_cert_sig(&sc[0..sclen],&mut sig);  // not interested in signature, only its type
        self.nreqs=add_cert_sig_type(&pk,self.nreqs,&mut self.requirements);
        self.nreqsraw=self.nreqs;

        let mut start=0;
        let mut len=x509::find_cert(&sc,&mut start); // find start and length of first signed certificate
        let cert=&sc[start..start+len]; // extract certificate
        len=x509::find_public_key(cert,&mut start);
        let pubk=&cert[start..start+len]; // extract public key
        self.publickey_len=utils::append_int(&mut self.publickey,self.publickey_len,len,3);
        self.publickey_len=utils::append_bytes(&mut self.publickey,self.publickey_len,&pubk[0..len]);
   
    	if stored_chain[1].len()>0 {
            b=stored_chain[1].as_bytes();
            sclen=utils::decode_b64(&b,&mut sc);
            self.certchain_len=utils::append_int(&mut self.certchain,self.certchain_len,sclen,3);
            self.certchain_len=utils::append_bytes(&mut self.certchain,self.certchain_len,&sc[0..sclen]);
            self.certchain_len=utils::append_int(&mut self.certchain,self.certchain_len,0,2);
            pk=extract_cert_sig(&sc[0..sclen],&mut sig); // not interested in signature, only its type
            self.nreqs=add_cert_sig_type(&pk,self.nreqs,&mut self.requirements);
        }
        return true;
    }
}

