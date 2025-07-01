
//! Client Certificate and private key stored here

use crate::config::*;
use crate::tls13::utils;
use crate::tls13::x509;
use crate::tls13::x509::*;
use crate::sal_m::sal;

// ECC-SS self-signed keys 256 bit. Certificate expires Jan 2026

pub const MY_PRIVATE: &str = 
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwmEaEau6Dybv+N5d\
1v+BkVWYQZhNsNu/X8JPZzZgTd6hRANCAAQvn/UmTjXDk41r0ow6+LfsA3qdKV2K\
1eRIv6axrsfEKds9poshRyvEgy4M8WYZlyOOchiVcO2jTyxvH1Xun/WH";

pub const CHAINLEN:usize = 1;

pub const MY_CERTCHAIN: [&str;CHAINLEN] = [ 
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
94BzAlOIACk="];

// add X509 signature type to TLS signature capability requirements list
fn add_sig_type(pk: &x509::PKTYPE,reqlen: usize,requirements: &mut [u16]) -> usize {
    let mut len=reqlen;
    if pk.kind==x509::ECC {
        if pk.curve==x509::USE_NIST256 {
            requirements[len]=ECDSA_SECP256R1_SHA256; // as long as this is a client capability
            len+=1;
            return len;
        }
        if pk.curve==x509::USE_NIST384 {
            requirements[len]=ECDSA_SECP384R1_SHA384;  // as long as this is a client capability
            len+=1;
            return len;
        }
    }
    if pk.kind==x509::RSA {
       requirements[len]=RSA_PSS_RSAE_SHA256;
       len+=1;
       return len;
    }

    if pk.kind==x509::PQ {
        requirements[len]=DILITHIUM3;
        len+=1;
        return len;
    }
    if pk.kind==x509::HY {
        requirements[len]=DILITHIUM2_P256;
        len+=1;
        requirements[len]=DILITHIUM2;
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
            requirements: [0;16],  // first element is secret key type, followed by types of signatures on certificates
            nreqs: 0,
            nreqsraw: 0, // only one signature requirement for raw public key
        };
        return this;
    }

// create credential structure from base64 inputs of the private key and the certificate chain
    pub fn set(&mut self,privkey: &str,stored_chain: &[&str]) -> bool  {
        let mut sc:[u8;MAX_CERT_SIZE]=[0;MAX_CERT_SIZE]; // workspace
        let mut sig:[u8;MAX_SIGNATURE_SIZE]=[0;MAX_SIGNATURE_SIZE];
       
        let mut sclen=utils::decode_b64(&privkey.as_bytes(),&mut sc);  // get secret key structure
        let mut pk=x509::extract_private_key(&sc[0..sclen],&mut self.secretkey);    // extract secret key
        self.secretkey_len=pk.len;

        self.nreqs=add_sig_type(&pk,self.nreqs,&mut self.requirements); // at least one signature scheme must be supported

        let kind=self.requirements[0]; // Client must implement algorithm to do signature - make sure its in the SAL!
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
        let chlen=stored_chain.len();
       
        let mut b=stored_chain[0].as_bytes();
        sclen=utils::decode_b64(&b,&mut sc);

// start building certificate chain
        self.certchain_len=utils::append_int(&mut self.certchain,self.certchain_len,sclen,3);
        self.certchain_len=utils::append_bytes(&mut self.certchain,self.certchain_len,&sc[0..sclen]);
        self.certchain_len=utils::append_int(&mut self.certchain,self.certchain_len,0,2);
        pk=extract_cert_sig(&sc[0..sclen],&mut sig);  // not interested in signature, only its type
        self.nreqs=add_sig_type(&pk,self.nreqs,&mut self.requirements);
        self.nreqsraw=self.nreqs;

        let mut start=0;
        let mut len=x509::find_cert(&sc,&mut start); // find start and length of first signed certificate
        let cert=&sc[start..start+len]; // extract certificate
        len=x509::find_public_key(cert,&mut start);
        let pubk=&cert[start..start+len]; // extract public key
        self.publickey_len=utils::append_int(&mut self.publickey,self.publickey_len,len,3);
        self.publickey_len=utils::append_bytes(&mut self.publickey,self.publickey_len,&pubk[0..len]);
   
        for i in 1..chlen {
            b=stored_chain[i].as_bytes();
            sclen=utils::decode_b64(&b,&mut sc);
            self.certchain_len=utils::append_int(&mut self.certchain,self.certchain_len,sclen,3);
            self.certchain_len=utils::append_bytes(&mut self.certchain,self.certchain_len,&sc[0..sclen]);
            self.certchain_len=utils::append_int(&mut self.certchain,self.certchain_len,0,2);
            pk=extract_cert_sig(&sc[0..sclen],&mut sig); // not interested in signature, only its type
            self.nreqs=add_sig_type(&pk,self.nreqs,&mut self.requirements);
        }
        return true;
    }
}



/*
// Report signature requirements for our certificate chain
pub fn get_sig_requirements(sig_reqs:&mut [u16]) -> usize {
    sig_reqs[0]=ECDSA_SECP256R1_SHA256;
    return 1;
}

// extract certificate chain from stored base64 version. If a raw public key is being used, just extract the public key from the first certificate in the chain.
// sc is workspace
fn extract_chain(stored_chain: &[&str],cert_type: u8,sc: &mut [u8],certchain: &mut [u8]) -> usize {
    let chlen=stored_chain.len();
    let mut ptr=0;
    if cert_type==RAW_PUBLIC_KEY { // RAW public key only is asked for
        let b=stored_chain[0].as_bytes();
        utils::decode_b64(&b,sc);
        let mut start=0;
        let mut len=x509::find_cert(sc,&mut start); // find start and length of first signed certificate
        let cert=&sc[start..start+len]; // extract certificate
        len=x509::find_public_key(cert,&mut start);
        let pk=&cert[start..start+len]; // extract public key
        ptr=utils::append_int(certchain,ptr,len,3);
        ptr=utils::append_bytes(certchain,ptr,&pk[0..len]);

    } else {
        for i in 0..chlen {
            let b=stored_chain[i].as_bytes();
            let sclen=utils::decode_b64(&b,sc);
            ptr=utils::append_int(certchain,ptr,sclen,3);
            ptr=utils::append_bytes(certchain,ptr,&sc[0..sclen]);
            ptr=utils::append_int(certchain,ptr,0,2); // add no certificate extensions
        }
    }
    return ptr;
}

/// Get client credentials (cert+signing key) from clientcert.rs
// Here we get the signature key type from the X.509 private key 
pub fn get_client_credentials(privkey: &mut [u8],sklen: &mut usize,cert_type: u8,certchain: &mut [u8],cclen: &mut usize) -> u16 {
    let mut sc:[u8;MAX_CLIENT_CHAIN_SIZE]=[0;MAX_CLIENT_CHAIN_SIZE];
// first get certificate chain
    let ptr=extract_chain(&MY_CERTCHAIN,cert_type,&mut sc,certchain);
    *cclen=ptr;
// next get secret key
    let b=MY_PRIVATE.as_bytes();
    let sclen=utils::decode_b64(&b,&mut sc);
    let pk=x509::extract_private_key(&sc[0..sclen],privkey);
    *sklen=pk.len;
    let mut kind:u16=0;
    if pk.kind==x509::ECC {
        if pk.curve==x509::USE_NIST256 {
            kind=ECDSA_SECP256R1_SHA256;  // as long as this is a client capability
        }
        if pk.curve==x509::USE_NIST384 {
            kind=ECDSA_SECP384R1_SHA384;  // as long as this is a client capability
        }
    }
    if pk.kind==x509::RSA {
        kind=RSA_PSS_RSAE_SHA256;
    }

    if pk.kind==x509::PQ {
        kind=DILITHIUM3;
    }
    if pk.kind==x509::HY {
        kind=DILITHIUM2_P256;   
    }
    if pk.kind==x509::ECD {
        if pk.curve==x509::USE_ED25519 {
            kind=ED25519;
        }
        if pk.curve==x509::USE_ED448 {
            kind=ED448;
        }
    }
    return kind;
}
*/