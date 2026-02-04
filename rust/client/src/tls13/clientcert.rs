
//! Client Certificate and private key stored here

use crate::config::*;
use crate::tls13::utils;
use crate::tls13::x509;
use crate::tls13::x509::*;
use crate::sal_m::sal;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

// ECC-SS self-signed keys 256 bit. Certificate expires Jan 2027

pub const MY_PRIVATE: &str = 

"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3DkvaA4S0pWnwu6t\
I6bczti3Qkh3T0qwzpdL2nmzdNmhRANCAAQ42drg0b22Z7G/J9cbGgVUpS+g01qh\
zrfdbaWVI6wnJ8eHRkk4vWjj46IqBBTMMDTu3J0X30STHnCsSl4nhELV";

pub const MY_CERTCHAIN: [&str;2] = [ 
"MIICdDCCAhugAwIBAgIUW9i3XshoTf1kbkaYGXgdu62/je8wCgYIKoZIzj0EAwIw\
gY8xCzAJBgNVBAYTAkFFMRIwEAYDVQQIDAlBYnUgRGhhYmkxEzARBgNVBAcMCllh\
cyBpc2xhbmQxDDAKBgNVBAoMA1RJSTEMMAoGA1UECwwDQ1JDMRYwFAYDVQQDDA1N\
aWNoYWVsIFNjb3R0MSMwIQYJKoZIhvcNAQkBFhRtaWNoYWVsLnNjb3R0QHRpaS5h\
ZTAeFw0yNjAyMDMxMjQ2NDFaFw0yNzAyMDMxMjQ2NDFaMIGPMQswCQYDVQQGEwJB\
RTESMBAGA1UECAwJQWJ1IERoYWJpMRMwEQYDVQQHDApZYXMgaXNsYW5kMQwwCgYD\
VQQKDANUSUkxDDAKBgNVBAsMA0NSQzEWMBQGA1UEAwwNTWljaGFlbCBTY290dDEj\
MCEGCSqGSIb3DQEJARYUbWljaGFlbC5zY290dEB0aWkuYWUwWTATBgcqhkjOPQIB\
BggqhkjOPQMBBwNCAAQ42drg0b22Z7G/J9cbGgVUpS+g01qhzrfdbaWVI6wnJ8eH\
Rkk4vWjj46IqBBTMMDTu3J0X30STHnCsSl4nhELVo1MwUTAdBgNVHQ4EFgQUHwGZ\
X/Oz4wmMST6ZVYRa3N3cKyIwHwYDVR0jBBgwFoAUHwGZX/Oz4wmMST6ZVYRa3N3c\
KyIwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiB2QNlCag9lWmSN\
W1aw2gORSfiPjBTLTR7fOw75AvCDpAIgPUaTdkFFmmHAVnuUox1CfIfJ/acrosUE\
5HfclrEdr8k=",""];


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
        return MLDSA44_ED25519;
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
        requirements[len]=MLDSA44_ED25519;
        len+=1;
        requirements[len]=MLDSA44;
        len+=1;
        requirements[len]=ED25519;
        len+=1;
        return len;  // *** also need to check that ed25519 is supported - kind indicates that both signature keys are in privkey
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
            let mut path = Path::new(&CLIENT_KEY_PATH);
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
            path=Path::new(&CLIENT_CERT_PATH);
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

