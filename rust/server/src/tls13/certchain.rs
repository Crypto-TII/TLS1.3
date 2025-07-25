//! TLS1.3 X.509 Certificate Processing Code

use crate::config::*;
use crate::tls13::utils;
use crate::tls13::x509;
use crate::tls13::x509::PKTYPE;
use crate::sal_m::sal;
use crate::tls13::logger;
use crate::tls13::logger::log;
use crate::tls13::cacerts;

use std::time::{SystemTime, UNIX_EPOCH};
use std::str;
use chrono::NaiveDateTime;

/// Get system time as milliseconds since epoch
pub fn seconds() -> usize {
    return SystemTime::now().duration_since(UNIX_EPOCH).expect("").as_secs() as usize;    
}

pub fn epoch_seconds(certtime: &str) -> usize {
    let dt = NaiveDateTime::parse_from_str(certtime,"%y%m%d%H%M%S").unwrap(); //               "250526131315","%y%m%d%H%M%S").unwrap();
    return dt.and_utc().timestamp() as usize;
}

/// Certificate components
pub struct CERT {
    pub sig:[u8;MAX_SIGNATURE_SIZE],
    pub sgt: PKTYPE,
    pub pk:[u8;MAX_SIG_PUBLIC_KEY],
    pub pkt: PKTYPE,
    pub issuer: [u8;MAX_X509_FIELD],
    pub islen: usize,
    pub subject: [u8;MAX_X509_FIELD],
    pub sblen: usize,
    pub status: isize
}

impl CERT {
    pub fn new() -> CERT  {
        let this=CERT {
            sig:[0;MAX_SIGNATURE_SIZE],
            sgt: {PKTYPE{kind:0,hash:0,curve:0,len:0}},
            pk: [0;MAX_SIG_PUBLIC_KEY],
            pkt: {PKTYPE{kind:0,hash:0,curve:0,len:0}},
            issuer: [0;MAX_X509_FIELD],
            islen: 0,
            subject: [0;MAX_X509_FIELD],
            sblen: 0,
            status: 0
        }; 
        return this;
    }
}

/// Combine Common Name, Organisation Name and Unit Name to make unique determination
fn create_full_name(fullname: &mut [u8],cert: &[u8],ic: usize,len: usize) -> usize {
    let mut ptr=0;
    ptr=utils::append_bytes(fullname,ptr,&cert[ic..ic+len]);
    return ptr;
}

/// Just check year of issue
fn check_cert_not_expired(cert:&[u8]) -> bool {
    let ic=x509::find_validity(cert);
    let cs=x509::find_start_date(cert,ic);
    let begin=epoch_seconds(&str::from_utf8(&cert[cs..cs+12]).unwrap());
    let ce=x509::find_expiry_date(cert,ic);
    let end=epoch_seconds(&str::from_utf8(&cert[ce..ce+12]).unwrap());
    let now=seconds();
//println!("cert time= {} {} {}",begin,end,now);
    if now>begin && now<end {
        return true;
    }
    return false;
}

/// Find root CA (if it exists) from database
fn find_root_ca(issuer: &[u8],st: &PKTYPE,pk: &mut [u8],pklen: &mut usize) -> bool {
    let mut owner:[u8;MAX_X509_FIELD]=[0;MAX_X509_FIELD];
    let mut sc:[u8;MAX_CERT_SIZE]=[0;MAX_CERT_SIZE];
    for i in 0..cacerts::CERT_STORE_SIZE {
        let b=cacerts::CACERTS[i].as_bytes();
        let sclen=utils::decode_b64(&b,&mut sc);
        let mut start=0;
        let len=x509::find_cert(&sc[0..sclen],&mut start);
        let cert=&sc[start..start+len];
        let ret=x509::find_issuer(&cert);
        //let ic=ret.index;
        let wlen=create_full_name(&mut owner,cert,ret.index,ret.length);
        if !check_cert_not_expired(&cert) {
            continue;
        }
        if &owner[0..wlen]==issuer {
            let pkt=x509::extract_public_key(cert, pk);
            if st.kind==pkt.kind {
                if st.kind==x509::PQ || st.kind==x509::HY || st.curve==pkt.curve {  // In PQ world signature sizes and public key sizes are not the same
                    *pklen=pkt.len;
                    return true;
                }
            }
        }
    }
    return false;
}

/// Check signature on Certificate given signature type and public key
fn check_cert_sig(st: &PKTYPE,cert: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    if st.kind==x509::ECC && st.hash==x509::H256 && st.curve==x509::USE_NIST256 {
        return sal::tls_signature_verify(ECDSA_SECP256R1_SHA256,cert,sig,pubkey);
    }
    if st.kind==x509::ECC && st.hash==x509::H384 && st.curve==x509::USE_NIST384 {
        return sal::tls_signature_verify(ECDSA_SECP384R1_SHA384,cert,sig,pubkey);
    }
    if st.kind==x509::ECD && st.curve==x509::USE_ED25519{
        return sal::tls_signature_verify(ED25519,cert,sig,pubkey);
    }
    if st.kind==x509::ECD && st.curve==x509::USE_ED448{
        return sal::tls_signature_verify(ED448,cert,sig,pubkey);
    }
    if st.kind==x509::RSA && st.hash==x509::H256 {
        return sal::tls_signature_verify(RSA_PKCS1_SHA256,cert,sig,pubkey);
    }
    if st.kind==x509::RSA && st.hash==x509::H384 {
        return sal::tls_signature_verify(RSA_PKCS1_SHA384,cert,sig,pubkey);
    }
    if st.kind==x509::RSA && st.hash==x509::H512 {
        return sal::tls_signature_verify(RSA_PKCS1_SHA512,cert,sig,pubkey);
    }
    if st.kind==x509::PQ {
        return sal::tls_signature_verify(MLDSA65,cert,sig,pubkey);
    }
    if st.kind==x509::HY {
        let sig1=&sig[0..64];
        let sig2=&sig[64..]; 
        let pub1=&pubkey[0..65];
        let pub2=&pubkey[65..];
        if sal::tls_signature_verify(ECDSA_SECP256R1_SHA384,cert,sig1,pub1) && sal::tls_signature_verify(MLDSA44,cert,sig2,pub2) {
            return true;
        }
        return false;
    }
    return false;
}

/// parse out certificate details, check that previous issuer is subject of this cert, update previous issuer
fn parse_cert(scert: &[u8],start: &mut usize,len: &mut usize,prev_issuer: &mut[u8],pislen: &mut usize) -> CERT {
    let mut ct=CERT::new();
    ct.sgt=x509::extract_cert_sig(scert,&mut ct.sig);
    *start=0;
    *len=x509::find_cert(scert,start);      // find start and length of certificate
    let cert=&scert[*start..*start+*len];   // slice it out

    let mut ret=x509::find_issuer(cert);
    //let mut ic=ret.index;
    ct.islen=create_full_name(&mut ct.issuer,cert,ret.index,ret.length);
    ret=x509::find_subject(cert);
    //ic=ret.index;
    ct.sblen=create_full_name(&mut ct.subject,cert,ret.index,ret.length);

    if !check_cert_not_expired(cert) {
        log(IO_DEBUG,"Certificate has expired\n",-1,None);
        ct.status=CERT_OUTOFDATE;
        return ct;
    }
    if ct.sgt.kind==0 {
        log(IO_DEBUG,"Unrecognised Signature Type",-1,None);
        ct.status=BAD_CERT_CHAIN;
        return ct;
    }
    ct.pkt=x509::extract_public_key(cert, &mut ct.pk);

    logger::log_cert_details(&ct);

    if ct.pkt.kind==0 {
        log(IO_DEBUG,"Unrecognised Public key Type",-1,None);
        ct.status=BAD_CERT_CHAIN;
        return ct;
    }

    if &ct.issuer[0..ct.islen]==&ct.subject[0..ct.sblen] {
        log(IO_DEBUG,"Self signed Cert\n",-1,None);
        ct.status=SELF_SIGNED_CERT;
        return ct;
    }
    if *pislen!=0 { // there was one
        if prev_issuer[0..*pislen] != ct.subject[0..ct.sblen] {
            log(IO_DEBUG,"Subject of this certificate is not issuer of prior certificate\n",-1,None);       
        }
        ct.status=BAD_CERT_CHAIN;
        return ct;
    }
    *pislen=ct.islen;
    for i in 0..ct.islen {
        prev_issuer[i]=ct.issuer[i]; // update issuer
    }
    return ct;
}


/// Extract public key, and check validity of certificate chain. Ensure that the hostname is same as that in Cert.
/// Assumes simple chain Cert->Intermediate Cert->CA cert.
/// CA cert not read from chain (if its even there) instead search for issuer of Intermediate Cert in cert store 
pub fn check_certchain(chain: &[u8],hostname: Option<&[u8]>,cert_type: u8,pubkey:&mut [u8],pklen: &mut usize,identity: &mut[u8],idlen: &mut usize) -> isize {
    let mut ptr=0;
    let mut capk:[u8;MAX_SIG_PUBLIC_KEY]=[0;MAX_SIG_PUBLIC_KEY];
    let mut issuer:[u8;MAX_X509_FIELD]=[0;MAX_X509_FIELD];

// Extract and process Cert
    let mut r=utils::parse_int(chain,3,&mut ptr); if r.err!=0 {return r.err;}
    let mut len=r.val;
    if len==0 {
        return EMPTY_CERT_CHAIN;
    }
    if ptr+len>chain.len() {
        return BAD_CERT_CHAIN;
    }

    if cert_type==RAW_PUBLIC_KEY { // its actually not a certificate chain, its a raw public key
        let pkt=x509::get_public_key(&chain[ptr..],pubkey);
        let id="Assumed to be known".as_bytes();
        for i in 0..id.len() {
            identity[i]=id[i];
        }
        *pklen=pkt.len;
        *idlen=id.len();
        return 0;
    }

// slice signed cert from chain
    let signed_cert=&chain[ptr..ptr+len];
    ptr+=len;
    r=utils::parse_int(chain,2,&mut ptr); if r.err!=0 {return r.err;}
    len=r.val;
    ptr+=len;    // skip certificate extensions

// parse first certificate
    let mut start=0;
    let mut len=0;
    let mut islen=0;
    let ct=parse_cert(&signed_cert,&mut start,&mut len,&mut issuer,&mut islen);
    
    //println!("xxct.sgt.len= {}",ct.sgt.len);
    //println!("xxct.sgt.curve= {}",ct.sgt.curve);
    
    let cert=&signed_cert[start..start+len];  // slice certificate from signed certificate
    if ct.status!=0 {
        if ct.status==SELF_SIGNED_CERT {
            if !check_cert_sig(&ct.sgt,&cert,&ct.sig[0..ct.sgt.len],&ct.pk[0..ct.pkt.len]) {
                return ct.status;
            }
        } else {
            return ct.status;
        }
    }
    
// Get good stuff from this certificate. First check hostname is correct
    let ic=x509::find_extensions(cert);
    let c=x509::find_extension(cert,&x509::AN,ic);
    if  let Some(host) = hostname {
        let found=x509::find_alt_name(cert,c.index,host);
        if !found && host!="localhost".as_bytes() {
            log(IO_DEBUG,"Hostname not found in certificate\n",-1,None);
            return BAD_CERT_CHAIN;
        }
    }

// get public key
    *pklen=ct.pkt.len; // make public key available externally
    for i in 0..*pklen {
        pubkey[i]=ct.pk[i];
    }
// get identity
    *idlen=ct.sblen;
    for i in 0..*idlen {
        identity[i]=ct.subject[i];
    }
    
// if self-signed, thats the end of the chain. And for development it may be acceptable
    if ct.status==SELF_SIGNED_CERT { 
        if ALLOW_SELF_SIGNED {
            log(IO_PROTOCOL,"Self-signed Certificate allowed\n",-1,None);
            return 0;
        } else {
            return ct.status;
        }
    }

    if ptr==chain.len() { // the chain ends here
        log(IO_DEBUG,"Non-self-signed Chain of length 1 ended unexpectedly\n",-1,None);
        return BAD_CERT_CHAIN;
    }

    r=utils::parse_int(chain,3,&mut ptr); len=r.val; if r.err!=0 {return r.err;}
    if len==0 {
        return EMPTY_CERT_CHAIN;
    }    
    if ptr+len>chain.len() {
        return BAD_CERT_CHAIN;
    }

// slice signed cert from chain
    let inter_signed_cert=&chain[ptr..ptr+len];
    ptr+=len;
    r=utils::parse_int(chain,2,&mut ptr); len=r.val; if r.err!=0 {return r.err;}
    ptr+=len;    // skip certificate extensions

    if ptr<chain.len() {
        log(IO_PROTOCOL,"Warning - there are unprocessed Certificates in the Chain\n",-1,None);
    }

// parse next certificate
    start=0;
    len=0;
    islen=0;
    let ctn=parse_cert(&inter_signed_cert,&mut start,&mut len,&mut issuer,&mut islen);
    let inter_cert=&inter_signed_cert[start..start+len];  // slice certificate from signed certificate

    if ctn.status!=0 {
        return BAD_CERT_CHAIN;
    }
    /*
    println!("ct.sgt.len={}",ct.sgt.len);
    println!("ctn.pkt.len={}",ctn.pkt.len);
    println!("cert.len={}",cert.len());
    println!("ct.sgt.kind= {:x}",ct.sgt.kind);
    println!("ct.sgt.hash= {:x}",ct.sgt.hash);
    println!("ct.sgt.curve= {:x}",ct.sgt.curve); 
    */   
    if !check_cert_sig(&ct.sgt,&cert,&ct.sig[0..ct.sgt.len],&ctn.pk[0..ctn.pkt.len]) {
        log(IO_DEBUG,"Certificate sig is NOT OK\n",-1,None);
        return BAD_CERT_CHAIN;
    }
    log(IO_DEBUG,"Certificate sig is OK\n",-1,None);
    
// parse root ca cert - extract its public key
    let mut capklen=0;
    if !find_root_ca(&issuer[0..islen],&ctn.sgt,&mut capk, &mut capklen) {
        log(IO_DEBUG,"Root Certificate not found\n",-1,None);
        return BAD_CERT_CHAIN;
    }
    log(IO_DEBUG,"\nPublic Key from root cert= ",0,Some(&capk[0..capklen]));
    
    if !check_cert_sig(&ctn.sgt,&inter_cert,&ctn.sig[0..ctn.sgt.len],&capk[0..capklen]) {
        log(IO_DEBUG,"Root Certificate signature is NOT OK\n",-1,None);
        return BAD_CERT_CHAIN;
    }
    log(IO_DEBUG,"Root Certificate signature is OK\n",-1,None);

    return 0;
}

