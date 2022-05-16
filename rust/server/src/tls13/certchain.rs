// TLS1.3 X.509 Certificate Processing Code
//
use crate::config::*;
use crate::tls13::utils;
use crate::tls13::x509;
use crate::tls13::x509::PKTYPE;
use crate::tls13::sal;
use crate::tls13::logger;
use crate::tls13::logger::log;
use crate::tls13::cacerts;
use crate::tls13::servercert;

pub struct CERT {
    pub sig:[u8;MAX_SIGNATURE_SIZE],
    pub sgt: PKTYPE,
    pub pk:[u8;MAX_PUBLIC_KEY],
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
            pk: [0;MAX_PUBLIC_KEY],
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

// combine Common Name, Organisation Name and Unit Name to make unique determination
fn create_full_name(fullname: &mut [u8],cert: &[u8],ic: usize) -> usize {
    let mut ptr=0;
    let mut ep=x509::find_entity_property(cert,&x509::MN,ic);
    ptr=utils::append_bytes(fullname,ptr,&cert[ep.index..ep.index+ep.length]);
    ptr=utils::append_byte(fullname,ptr,'/' as u8,1);
    ep=x509::find_entity_property(cert,&x509::ON,ic);
    ptr=utils::append_bytes(fullname,ptr,&cert[ep.index..ep.index+ep.length]);
    ptr=utils::append_byte(fullname,ptr,'/' as u8,1);
    ep=x509::find_entity_property(cert,&x509::UN,ic);
    ptr=utils::append_bytes(fullname,ptr,&cert[ep.index..ep.index+ep.length]);
    return ptr;
}

// just check year of issue
fn check_cert_not_expired(cert:&[u8]) -> bool {
    let ic=x509::find_validity(cert);
    let c=x509::find_expiry_date(cert,ic);
    let oh = '0' as u8;
    let year=2000+((cert[c]-oh)*10+cert[c+1]-oh) as usize;
    if year<THIS_YEAR {
        return false;
    }
    return true;
}

// base64 decoding
fn decode_b64(b: &[u8],w:&mut [u8]) -> usize { // decode from base64 in place
    let mut j=0;
    let mut k=0;
    let len=b.len();
    let mut ch:[u8;4]=[0;4];
    let mut ptr:[u8;3]=[0;3];
    while j<len {
        let mut pads=0;
        for i in 0..4 {
            let mut c=80+b[j]; j+=1;
            if c<=112 {continue;}
            if c>144 && c<171 {
                c-=145;
            }
            if c>176 && c<203 { 
                c-=151;
            }
            if c>127 && c<138 {
                c-=76;
            }
            if c==123 {c=62;}
            if c==127 {c=63;}
            if c==141 {
                pads+=1;
                continue;
            }
            ch[i]=c;
        }
        ptr[0] = (ch[0] << 2) | (ch[1] >> 4);
        ptr[1] = (ch[1] << 4) | (ch[2] >> 2);
        ptr[2] = (ch[2] << 6) | ch[3];
        for i in 0..3 - pads {
            /* don't put in leading zeros */
            w[k] = ptr[i]; k+=1;
        }
    }
    return k;
}

// find root CA (if it exists) from database
fn find_root_ca(issuer: &[u8],st: &PKTYPE,pk: &mut [u8],pklen: &mut usize) -> bool {
    let mut owner:[u8;MAX_X509_FIELD]=[0;MAX_X509_FIELD];
    let mut sc:[u8;MAX_ROOT_CERT_SIZE]=[0;MAX_ROOT_CERT_SIZE];
    for i in 0..cacerts::CERT_STORE_SIZE {
        let b=cacerts::CACERTS[i].as_bytes();
        let sclen=decode_b64(&b,&mut sc);
        let mut start=0;
        let len=x509::extract_cert_ptr(&sc[0..sclen],&mut start);
        let cert=&sc[start..start+len];
        let ic=x509::find_issuer(&cert);
        let wlen=create_full_name(&mut owner,cert,ic);
        if !check_cert_not_expired(&cert) {
            continue;
        }
        if &owner[0..wlen]==issuer {
            let pkt=x509::extract_public_key(cert, pk);
            if st.kind==pkt.kind && st.curve==pkt.curve {
            *pklen=pkt.len;
                return true;
            }
        }
    }
    return false;
}

// Check signature on Certificate given signature type and public key
fn check_cert_sig(st: &PKTYPE,cert: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    let mut sigalg:u16=0;
    if st.kind==x509::ECC && st.hash==x509::H256 && st.curve==x509::USE_NIST256 {
        sigalg=ECDSA_SECP256R1_SHA256;
    }
    if st.kind==x509::ECC && st.hash==x509::H384 && st.curve==x509::USE_NIST384 {
        sigalg=ECDSA_SECP384R1_SHA384;
    }
    if st.kind==x509::RSA && st.hash==x509::H256 {
        sigalg=RSA_PKCS1_SHA256;
    }
    if st.kind==x509::RSA && st.hash==x509::H384 {
        sigalg=RSA_PKCS1_SHA384;
    }
    if st.kind==x509::RSA && st.hash==x509::H512 {
        sigalg=RSA_PKCS1_SHA512;
    }
    if sigalg==0 {
//println!("Unsupported sig {} {} {}",st.kind,st.hash,st.curve);
        return false;
    }
    let res=sal::tls_signature_verify(sigalg,cert,sig,pubkey);
    return res;
}

// get server credentials
pub fn get_server_credentials(csigalgs: &[u16],privkey: &mut [u8],sklen: &mut usize,certchain: &mut [u8],cclen: &mut usize) -> u16 {
    let mut sc:[u8;MAX_CERT_SIZE]=[0;MAX_CERT_SIZE];
// first get certificate chain
// Should check against hostname to pick right certificate - we could have more than one

    let nccsalgs=csigalgs.len();
    let mut ptr=0;
    for i in 0..servercert::CHAINLEN {
        let b=servercert::MYCERTCHAIN[i].as_bytes();
        let sclen=decode_b64(&b,&mut sc);
        ptr=utils::append_int(certchain,ptr,sclen,3);
        ptr=utils::append_bytes(certchain,ptr,&sc[0..sclen]);
        ptr=utils::append_int(certchain,ptr,0,2); // add no certificate extensions
    }
    *cclen=ptr;
// next get secret key
    let b=servercert::MYPRIVATE.as_bytes();
    let sclen=decode_b64(&b,&mut sc);
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
    for i in 0..nccsalgs {
        if kind==csigalgs[i] {return kind;}
    }
    return 0;
}

// parse out certificate details
// check that previous issuer is subject of this cert
// update previous issuer
fn parse_cert(scert: &[u8],start: &mut usize,len: &mut usize,prev_issuer: &mut[u8],pislen: &mut usize) -> CERT {
    let mut ct=CERT::new();
    ct.sgt=x509::extract_cert_sig(scert,&mut ct.sig);
    *start=0;
    *len=x509::extract_cert_ptr(scert,start); // find start and length of certificate
    let cert=&scert[*start..*start+*len];     // slice it out

    let mut ic=x509::find_issuer(cert);
    ct.islen=create_full_name(&mut ct.issuer,cert,ic);
    ic=x509::find_subject(cert);
    ct.sblen=create_full_name(&mut ct.subject,cert,ic);

    if !check_cert_not_expired(cert) {
        log(IO_DEBUG,"Certificate has expired\n",0,None);
        ct.status=CERT_OUTOFDATE;
        return ct;
    }
    if ct.sgt.kind==0 {
        log(IO_DEBUG,"Unrecognised Signature Type\n",0,None);
        ct.status=BAD_CERT_CHAIN;
        return ct;
    }
    ct.pkt=x509::extract_public_key(cert, &mut ct.pk);

    logger::log_cert_details(&ct);

    if ct.pkt.kind==0 {
        log(IO_DEBUG,"Unrecognised Public key Type\n",0,None);
        ct.status=BAD_CERT_CHAIN;
        return ct;
    }

    if &ct.issuer[0..ct.islen]==&ct.subject[0..ct.sblen] {
        log(IO_DEBUG,"Self signed Cert\n",0,None);
        ct.status=SELF_SIGNED_CERT;
        return ct;
    }
    if *pislen!=0 { // there was one
        if prev_issuer[0..*pislen] != ct.subject[0..ct.sblen] {
            log(IO_DEBUG,"Subject of this certificate is not issuer of prior certificate\n",0,None);       
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

// extract public key, and check validity of certificate chain
// ensures that the hostname is same as that in Cert
// Assumes simple chain Cert->Intermediate Cert->CA cert
// CA cert not read from chain (if its even there). 
// Search for issuer of Intermediate Cert in cert store 
pub fn check_certchain(chain: &[u8],hostname: Option<&[u8]>,pubkey:&mut [u8],pklen: &mut usize,identity: &mut[u8],idlen: &mut usize) -> isize {
    let mut ptr=0;
    let mut capk:[u8;MAX_PUBLIC_KEY]=[0;MAX_PUBLIC_KEY];
    let mut issuer:[u8;MAX_X509_FIELD]=[0;MAX_X509_FIELD];

// Extract and process Cert
    let mut r=utils::parse_int(chain,3,&mut ptr); if r.err!=0 {return BAD_CERT_CHAIN;}
    let mut len=r.val;
    if ptr+len>chain.len() {
        return BAD_CERT_CHAIN;
    }

// slice signed cert from chain
    let signed_cert=&chain[ptr..ptr+len];
    ptr+=len;
    r=utils::parse_int(chain,2,&mut ptr); if r.err!=0 {return BAD_CERT_CHAIN;}
    len=r.val;
    ptr+=len;    // skip certificate extensions

// parse first certificate
    let mut start=0;
    let mut len=0;
    let mut islen=0;
    let ct=parse_cert(&signed_cert,&mut start,&mut len,&mut issuer,&mut islen);
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
            log(IO_DEBUG,"Hostname not found in certificate\n",0,None);
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
            log(IO_PROTOCOL,"Self-signed Certificate allowed\n",0,None);
            return 0;
        } else {
            return ct.status;
        }
    }

    if ptr==chain.len() { // the chain ends here
// parse root ca cert - extract its public key
/*        let mut capklen=0;
        if !find_root_ca(&issuer[0..islen],&ct.sgt,&mut capk, &mut capklen) {
            log(IO_DEBUG,"Root Certificate not found = ",0,Some(&issuer[0..islen]));
            return BAD_CERT_CHAIN;
        }
        log(IO_DEBUG,"\nPublic Key from root cert= ",0,Some(&capk[0..capklen]));
    
        if !check_cert_sig(&ct.sgt,&cert,&ct.sig[0..ct.sgt.len],&capk[0..capklen]) {
            log(IO_DEBUG,"Root Certificate signature is NOT OK\n",0,None);
            return BAD_CERT_CHAIN;
        }
        log(IO_DEBUG,"Root Certificate signature is OK\n",0,None);

        return 0;
*/
        log(IO_DEBUG,"Non-self-signed Chain of length 1 ended unexpectedly\n",0,None);
        return BAD_CERT_CHAIN;
    }

    r=utils::parse_int(chain,3,&mut ptr); len=r.val; if r.err!=0 {return BAD_CERT_CHAIN;}
    if ptr+len>chain.len() {
        return BAD_CERT_CHAIN;
    }

// slice signed cert from chain
    let inter_signed_cert=&chain[ptr..ptr+len];
    ptr+=len;
    r=utils::parse_int(chain,2,&mut ptr); len=r.val; if r.err!=0 {return BAD_CERT_CHAIN;}
    ptr+=len;    // skip certificate extensions

    if ptr<=chain.len() {
        log(IO_PROTOCOL,"Warning - there are unprocessed Certificates in the Chain\n",0,None);
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
    if !check_cert_sig(&ct.sgt,&cert,&ct.sig[0..ct.sgt.len],&ctn.pk[0..ctn.pkt.len]) {
        log(IO_DEBUG,"Certificate sig is NOT OK\n",0,None);
        return BAD_CERT_CHAIN
    }
    log(IO_DEBUG,"Certificate sig is OK\n",0,None);
    
// parse root ca cert - extract its public key
    let mut capklen=0;
    if !find_root_ca(&issuer[0..islen],&ctn.sgt,&mut capk, &mut capklen) {
        log(IO_DEBUG,"Root Certificate not found\n",0,None);
        return BAD_CERT_CHAIN;
    }
    log(IO_DEBUG,"\nPublic Key from root cert= ",0,Some(&capk[0..capklen]));
    
    if !check_cert_sig(&ctn.sgt,&inter_cert,&ctn.sig[0..ctn.sgt.len],&capk[0..capklen]) {
        log(IO_DEBUG,"Root Certificate signature is NOT OK\n",0,None);
        return BAD_CERT_CHAIN;
    }
    log(IO_DEBUG,"Root Certificate signature is OK\n",0,None);

    return 0;
}

