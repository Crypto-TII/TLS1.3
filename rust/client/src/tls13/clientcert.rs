
//! Client Certificate and private key stored here

use crate::config::*;
use crate::tls13::utils;
use crate::tls13::x509;

// ECC-SS self-signed keys 256 bit. Certificate expires May 2023/Jan 2026

pub const MY_PRIVATE: &str = 
//"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkYO7LpVcia9BoJSQ\
//Ls2rOGluxjkah3LzRChLGt8oyXShRANCAAQpVUJz1HzNuFR9QfLaQz5eO9BMSrHT\
//OblikZXqx3xbwQaAZgGJLfYgiPc+cSVBtJeWYUruLdTRnNEWPVULstnI";
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwmEaEau6Dybv+N5d\
1v+BkVWYQZhNsNu/X8JPZzZgTd6hRANCAAQvn/UmTjXDk41r0ow6+LfsA3qdKV2K\
1eRIv6axrsfEKds9poshRyvEgy4M8WYZlyOOchiVcO2jTyxvH1Xun/WH";

pub const CHAINLEN:usize = 1;

pub const MY_CERTCHAIN: [&str;CHAINLEN] = [ 
//"MIICczCCAhmgAwIBAgIUO4ZDnPLFU4TKBeKzGAQ/8jsumt8wCgYIKoZIzj0EAwIw\
//gY4xCzAJBgNVBAYTAklFMREwDwYDVQQIDAhMZWluc3RlcjENMAsGA1UEBwwEVHJp\
//bTEPMA0GA1UECgwGU2hhbXVzMREwDwYDVQQLDAhSZXNlYXJjaDETMBEGA1UEAwwK\
//TWlrZSBTY290dDEkMCIGCSqGSIb3DQEJARYVbWlrZS5zY290dEBtaXJhY2wuY29t\
//MB4XDTIyMDUwMjA4MzgzOFoXDTIzMDUwMjA4MzgzOFowgY4xCzAJBgNVBAYTAklF\
//MREwDwYDVQQIDAhMZWluc3RlcjENMAsGA1UEBwwEVHJpbTEPMA0GA1UECgwGU2hh\
//bXVzMREwDwYDVQQLDAhSZXNlYXJjaDETMBEGA1UEAwwKTWlrZSBTY290dDEkMCIG\
//CSqGSIb3DQEJARYVbWlrZS5zY290dEBtaXJhY2wuY29tMFkwEwYHKoZIzj0CAQYI\
//KoZIzj0DAQcDQgAEKVVCc9R8zbhUfUHy2kM+XjvQTEqx0zm5YpGV6sd8W8EGgGYB\
//iS32IIj3PnElQbSXlmFK7i3U0ZzRFj1VC7LZyKNTMFEwHQYDVR0OBBYEFLqCgrLR\
//ZgirGFexJSa18p7YgpehMB8GA1UdIwQYMBaAFLqCgrLRZgirGFexJSa18p7Ygpeh\
//MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgI1dd2DBjgRls92H0\
//SpxxnguAEeVw/jxqF1xw+xoECV0CIQDmex6iyHQEzDP7cyzKo4WHuEG6UkjlaRUA\
//XhcQYkLKHg=="];

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
    return kind;
}
