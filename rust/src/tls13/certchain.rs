// TLS1.3 Certificate Processing Code

use crate::config::*;
use crate::tls13::utils;
use crate::tls13::x509;
use crate::tls13::x509::PKTYPE;
use crate::tls13::sal;
use crate::tls13::logger;
use crate::tls13::cacerts;
use crate::tls13::clientcert;

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
        return false;
    }
    let res=sal::tls_signature_verify(sigalg,cert,sig,pubkey);
    return res;
}

pub fn get_client_credentials(csigalgs: &[u16],privkey: &mut [u8],sklen: &mut usize,certchain: &mut [u8],cclen: &mut usize) -> u16 {
    let mut sc:[u8;MAX_MYCERT_SIZE]=[0;MAX_MYCERT_SIZE];
// first get certificate chain
    let nccsalgs=csigalgs.len();
    let mut ptr=0;
    for i in 0..clientcert::CHAINLEN {
        let b=clientcert::MYCERTCHAIN[i].as_bytes();
        let sclen=decode_b64(&b,&mut sc);
        ptr=utils::append_int(certchain,ptr,sclen,3);
        ptr=utils::append_bytes(certchain,ptr,&sc[0..sclen]);
        ptr=utils::append_int(certchain,ptr,0,2); // add no certificate extensions
    }
    *cclen=ptr;
// next get secret key
    let b=clientcert::MYPRIVATE.as_bytes();
    let sclen=decode_b64(&b,&mut sc);
    let pk=x509::extract_private_key(&sc[0..sclen],privkey);
    *sklen=sclen;
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

// Check certificate has not expired
// Detach signature from certificate
// Check if self-signed
// Check signature and public keys are supported types
// Check subject of this certificate is issuer of previous certificate in the chain
// output signature and public key, and issuer of this certificate
fn parse_cert(scert: &[u8],start: &mut usize,len: &mut usize,sig: &mut[u8],csgt: &mut PKTYPE,pk: &mut[u8],cpkt: &mut PKTYPE,prev_issuer: &mut[u8],pislen: &mut usize) -> isize {
    let mut subject:[u8;MAX_X509_FIELD]=[0;MAX_X509_FIELD];  
    let mut issuer:[u8;MAX_X509_FIELD]=[0;MAX_X509_FIELD];      

    let sgt=x509::extract_cert_sig(scert,sig);

    *start=0;
    *len=x509::extract_cert_ptr(scert,start); // find start and length of certificate
    let cert=&scert[*start..*start+*len];     // slice it out

    let mut ic=x509::find_issuer(cert);
    let islen=create_full_name(&mut issuer,cert,ic);
    ic=x509::find_subject(cert);
    let sblen=create_full_name(&mut subject,cert,ic);

    if !check_cert_not_expired(cert) {
        logger::logger(IO_DEBUG,"Certificate has expired\n",0,None);
        return CERT_OUTOFDATE;
    }
    if sgt.kind==0 {
        logger::logger(IO_DEBUG,"Unrecognised Signature Type\n",0,None);
        return BAD_CERT_CHAIN;
    }
    let pkt=x509::extract_public_key(cert, pk);

    logger::log_cert_details(&pk[0..pkt.len],&sgt,&sig[0..pkt.len],&pkt,&subject[0..sblen],&issuer[0..islen]);

    if pkt.kind==0 {
        logger::logger(IO_DEBUG,"Unrecognised Public key Type\n",0,None);
        return BAD_CERT_CHAIN;
    }

    *csgt=sgt;
    *cpkt=pkt;

    if issuer[0..islen]==subject[0..sblen] {
        logger::logger(IO_DEBUG,"Self signed Cert\n",0,None);
        return SELF_SIGNED_CERT;
    }

    if *pislen!=0 { // there was one
        if prev_issuer[0..*pislen] != subject[0..sblen] {
            logger::logger(IO_DEBUG,"Subject of this certificate is not issuer of prior certificate\n",0,None);       
        }
        return BAD_CERT_CHAIN;
    }
    *pislen=islen;
    for i in 0..islen {
        prev_issuer[i]=issuer[i]; // update issuer
    }
    return 0;
}

// extract server public key, and check validity of certificate chain
// ensures that the hostname is valid.
// Assumes simple chain Server Cert->Intermediate Cert->CA cert
// CA cert not read from chain (if its even there). 
// Search for issuer of Intermediate Cert in cert store 
pub fn check_server_certchain(chain: &[u8],hostname: &[u8],pubkey:&mut [u8],pklen: &mut usize) -> isize {
    let mut ptr=0;
    let mut server_sig:[u8;MAX_SIGNATURE_SIZE]=[0;MAX_SIGNATURE_SIZE];
    let mut inter_sig:[u8;MAX_SIGNATURE_SIZE]=[0;MAX_SIGNATURE_SIZE];
    let mut pk:[u8;MAX_SERVER_PUB_KEY]=[0;MAX_SERVER_PUB_KEY];
    let mut issuer:[u8;MAX_X509_FIELD]=[0;MAX_X509_FIELD];

// Extract and process Server Cert
    let mut r=utils::parse_int(chain,3,&mut ptr); if r.err!=0 {return BAD_CERT_CHAIN;}
    let mut len=r.val;
    if ptr+len>chain.len() {
        return BAD_CERT_CHAIN;
    }

// slice signed server cert from chain
    let server_signed_cert=&chain[ptr..ptr+len];
    ptr+=len;

    r=utils::parse_int(chain,2,&mut ptr); if r.err!=0 {return BAD_CERT_CHAIN;}
    len=r.val;
    ptr+=len;    // skip certificate extensions

// extract signature
    let mut ssgt=PKTYPE::new();  // server sig type
    let mut spkt=PKTYPE::new();  // server public key type
    let mut start=0;
    let mut len=0;
    let mut islen=0;
    let mut rtn=parse_cert(&server_signed_cert,&mut start,&mut len,&mut server_sig,&mut ssgt,pubkey,&mut spkt,&mut issuer,&mut islen);
    let server_cert=&server_signed_cert[start..start+len];  // slice certificate from signed certificate
    if rtn!=0 {
        if rtn==SELF_SIGNED_CERT {
            if !check_cert_sig(&ssgt,&server_cert,&server_sig[0..ssgt.len],&pubkey[0..spkt.len]) {
                return BAD_CERT_CHAIN;
            }
        } else {
            return rtn;
        }
    }
    *pklen=spkt.len;

    let ic=x509::find_extensions(server_cert);
    let c=x509::find_extension(server_cert,&x509::AN,ic);
    let found=x509::find_alt_name(server_cert,c.index,hostname);
    if !found && hostname!="localhost".as_bytes() {
        logger::logger(IO_DEBUG,"Hostname not found in certificate\n",0,None);
        return BAD_CERT_CHAIN;
    }

    if rtn==SELF_SIGNED_CERT { // If self-signed, thats the end of the chain. And for development it may be acceptable
        if ALLOW_SELF_SIGNED {
            return 0;
        } else {
            return rtn;
        }
    }

    r=utils::parse_int(chain,3,&mut ptr); len=r.val; if r.err!=0 {return BAD_CERT_CHAIN;}
    if ptr+len>chain.len() {
        return BAD_CERT_CHAIN;
    }
    let inter_signed_cert=&chain[ptr..ptr+len];
    ptr+=len;

    r=utils::parse_int(chain,2,&mut ptr); len=r.val; if r.err!=0 {return BAD_CERT_CHAIN;}
    ptr+=len;    // skip certificate extensions

    if ptr<=chain.len() {
        logger::logger(IO_PROTOCOL,"Warning - there are unprocessed Certificates in the Chain\n",0,None);
    }

// extract signature
    let mut isgt=PKTYPE::new();
    let mut ipkt=PKTYPE::new();
    start=0;
    len=0;
    islen=0;
    rtn=parse_cert(&inter_signed_cert,&mut start,&mut len,&mut inter_sig,&mut isgt,&mut pk,&mut ipkt,&mut issuer,&mut islen);
    let inter_cert=&inter_signed_cert[start..start+len];  // slice certificate from signed certificate

    if rtn!=0 {
        return BAD_CERT_CHAIN;
    }

    if !check_cert_sig(&ssgt,&server_cert,&server_sig[0..ssgt.len],&pk[0..ipkt.len]) {
        logger::logger(IO_DEBUG,"Server Certificate sig is NOT OK\n",0,None);
        return BAD_CERT_CHAIN
    }
    logger::logger(IO_DEBUG,"Server Certificate sig is OK\n",0,None);
    
    let mut pklen=0;
    if !find_root_ca(&issuer[0..islen],&isgt,&mut pk, &mut pklen) {
        logger::logger(IO_DEBUG,"Root Certificate not found\n",0,None);
        return BAD_CERT_CHAIN;
    }
    logger::logger(IO_DEBUG,"\nPublic Key from root cert= ",0,Some(&pk[0..pklen]));
    
    if !check_cert_sig(&isgt,&inter_cert,&inter_sig[0..isgt.len],&pk[0..pklen]) {
        logger::logger(IO_DEBUG,"Root Certificate sig is NOT OK\n",0,None);
        return BAD_CERT_CHAIN;
    }
    logger::logger(IO_DEBUG,"Root Certificate sig is OK\n",0,None);
    
    return 0;
}

