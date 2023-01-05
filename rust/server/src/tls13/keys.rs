//! Create and manage cryptographic keys

use zeroize::Zeroize;

use crate::config::*;
use crate::tls13::utils;
use crate::sal_m::sal;
use crate::tls13::servercert;
use crate::tls13::x509;
//use crate::tls13::logger::log;

/// Create expanded HKDF label LB from label and context
fn hkdf_label(lb: &mut [u8],len: usize,label:&[u8],ctx: Option<&[u8]>) -> usize {
    let mut ptr=0;
    let tls="tls13 ";
    ptr=utils::append_int(lb,ptr,len,2);
    ptr=utils::append_byte(lb,ptr,(6+label.len()) as u8,1);
    ptr=utils::append_bytes(lb,ptr,tls.as_bytes());
    ptr=utils::append_bytes(lb,ptr,label);

    if let Some(sctx) = ctx {
        ptr=utils::append_byte(lb,ptr,sctx.len() as u8,1);
        ptr=utils::append_bytes(lb,ptr,sctx);
    } else {
        ptr=utils::append_byte(lb,ptr,0,1);
    }
    return ptr;
}

/// HKDF extension for TLS1.3
pub fn hkdf_expand_label(htype: usize,okm: &mut [u8],prk: &[u8],label: &[u8],ctx: Option<&[u8]>)
{
    let mut hl:[u8;MAX_HASH+24]=[0;MAX_HASH+24];
    let len=hkdf_label(&mut hl,okm.len(),label,ctx);
    sal::hkdf_expand(htype,okm,prk,&hl[0..len]);
}

/// Key Schedule code. Get Early Secret ES and optional Binder Key (either External or Resumption)
pub fn derive_early_secrets(htype: usize,psk: Option<&[u8]>,es: &mut [u8],bke: Option<&mut [u8]>,bkr: Option<&mut [u8]>)
{
    let mut emh:[u8;MAX_HASH]=[0;MAX_HASH];
    let zk:[u8;MAX_HASH]=[0;MAX_HASH];
    let eb="ext binder";
    let rb="res binder";
    let hlen=sal::hash_len(htype);
    let zk_s=&zk[0..hlen];

    let mut len=hlen;
    if let Some(spsk) = psk {
        len=spsk.len();
        emh[0..len].clone_from_slice(&spsk[0..len]);
    } else {
        emh[0..len].clone_from_slice(zk_s);
    }
    sal::hkdf_extract(htype,es,Some(zk_s),&emh[0..len]);

    sal::hash_null(htype,&mut emh);
    if let Some(sbke) = bke {
        hkdf_expand_label(htype,&mut sbke[0..hlen],es,eb.as_bytes(),Some(&emh[0..hlen]));
    }
    if let Some(sbkr) = bkr {
        hkdf_expand_label(htype,&mut sbkr[0..hlen],es,rb.as_bytes(),Some(&emh[0..hlen]));
    }
}

/// Get Later Secrets (Client Early Traffic Secret CETS and Early Exporter Master Secret EEMS) - requires partial transcript hash H
pub fn derive_later_secrets(htype: usize,es: &[u8],h: &[u8], cets: Option<&mut [u8]>, eems: Option<&mut [u8]>) 
{
    let ct="c e traffic";
    let em="e exp master";
    if let Some(scets) = cets {
        hkdf_expand_label(htype,scets,es,ct.as_bytes(),Some(h));
    }
    if let Some(seems) = eems {
        hkdf_expand_label(htype,seems,es,em.as_bytes(),Some(h));
    }
}

/// Structure for Key and IV for AEAD
pub struct CRYPTO {
    pub active: bool,
    pub k: [u8;MAX_KEY],        // AEAD cryptographic Key bytes     
    pub iv: [u8;MAX_IV_SIZE],   // AEAD cryptographic IV bytes 
    pub record: usize,          // current record number - to be incremented 
    pub suite: u16,             // Cipher Suite 
	pub taglen: usize		    //Tag Length 
}

impl CRYPTO {
    pub fn new() -> CRYPTO {
        CRYPTO {
            active: false,
            k: [0;MAX_KEY],
            iv: [0;MAX_IV_SIZE],
            record: 0,
            suite: 0,
            taglen: 0
        }
    }

/// Initialise for ticket encryption
    pub fn special_init(&mut self,iv: &[u8]) {
        self.active=true;
        self.suite=AES_128_GCM_SHA256;
        self.record=0;
        self.taglen=16;
        for i in 0..12 {
            self.iv[i]=iv[i];
        }
        for  i in 0..16 {
            self.k[i]=servercert::TEK[i];
        }
    }
/// Initialise cipher suite
    pub fn init(&mut self,cipher_suite: u16,ts: &[u8])
    {
        let htype=sal::hash_type(cipher_suite);
        let hlen=sal::hash_len(htype);
        let klen=sal::aead_key_len(cipher_suite);
        let kyt="key";
        let ivt="iv";
        hkdf_expand_label(htype,&mut self.k[0..klen],&ts[0..hlen],kyt.as_bytes(),None);
        hkdf_expand_label(htype,&mut self.iv[0..12],&ts[0..hlen],ivt.as_bytes(),None);

        self.active=true;
        self.suite=cipher_suite;
        self.record=0;
        self.taglen=sal::aead_tag_len(cipher_suite);
    }
/// Remove cipher suite
    pub fn clear(&mut self) {
        self.active=false;
        self.record=0;
        self.suite=0;
        self.taglen=0;
        self.k.zeroize();
        self.iv.zeroize();
    }

/// Check if cipher-suite is active
    pub fn is_active(&mut self) -> bool {
        return self.active;
    }

///  Increment record, and update IV
    pub fn increment_crypto_context(&mut self)
    { 
        let mut b:[u8;4]=[0;4];
        b[3]=(self.record%256) as u8;
        b[2]=((self.record>>8)%256) as u8;
        b[1]=((self.record>>16)%256) as u8;
        b[0]=((self.record>>24)%256) as u8;
   
        for i in 0..4 {
            self.iv[8+i]^=b[i];  // revert to original IV
        }
        self.record+=1;
        b[3]=(self.record%256) as u8;
        b[2]=((self.record>>8)%256) as u8;
        b[1]=((self.record>>16)%256) as u8;
        b[0]=((self.record>>24)%256) as u8;
        for i in 0..4 {
            self.iv[8+i]^=b[i];  // advance to new IV
        }
    }

/// Update Traffic secret and associated traffic key and IV
    pub fn update(&mut self,ts: &mut [u8]) {
        let mut nts:[u8;MAX_HASH]=[0;MAX_HASH];
        let htype=sal::hash_type(self.suite);
        let hlen=sal::hash_len(htype);
        let klen=sal::aead_key_len(self.suite);
        let tu="traffic upd";
        let ky="key";
        let iv="iv";

        hkdf_expand_label(htype,&mut nts[0..hlen],ts,tu.as_bytes(),None);
        for i in 0..hlen {
            ts[i]=nts[i];
        }
        hkdf_expand_label(htype,&mut self.k[0..klen],ts,ky.as_bytes(),None);
        hkdf_expand_label(htype,&mut self.iv[0..12],ts,iv.as_bytes(),None);
        self.record=0;
        self.active=true;
    }  
}

/// Create Server Certificate Verifier
pub fn create_server_cert_verifier(sigalg: u16,h: &[u8],key: &[u8],scvsig: &mut [u8]) -> usize {
    let mut ptr=0;
    let txt="TLS 1.3, server CertificateVerify";
    let mut scv:[u8;100+MAX_HASH]=[0;100+MAX_HASH];
    ptr=utils::append_byte(&mut scv,ptr,32,64);
    ptr=utils::append_bytes(&mut scv,ptr,txt.as_bytes());
    ptr=utils::append_byte(&mut scv,ptr,0,1); 
    ptr=utils::append_bytes(&mut scv,ptr,h);

// *** if sigalg==DILITHIUM2_P256, extract both signing keys, create two signatures, and concatenate them
    if sigalg==DILITHIUM2_P256 {
        // whats private key look like?
        let siglen=sal::tls_signature(ECDSA_SECP256R1_SHA384,&key[0..32],&scv[0..ptr],scvsig);
        let mut sclen=x509::ecdsa_sig_encode(siglen,scvsig);
        sclen+=sal::tls_signature(DILITHIUM2,&key[32..],&scv[0..ptr],&mut scvsig[sclen..]); // append PQ sig
        return sclen;
    }

    let mut sclen=sal::tls_signature(sigalg,key,&scv[0..ptr],scvsig);
    if sigalg==ECDSA_SECP256R1_SHA256 || sigalg==ECDSA_SECP384R1_SHA384 {
        sclen=x509::ecdsa_sig_encode(sclen,scvsig);
    }
    return sclen;
}

/// Check Client Certificate Verifier - verify signature
pub fn check_client_cert_verifier(sigalg: u16,ccvsig: &mut [u8],h: &[u8],certpk: &[u8]) -> bool {
    let mut ccv:[u8;100+MAX_HASH]=[0;100+MAX_HASH];
    let mut ptr=0;
    ptr=utils::append_byte(&mut ccv,ptr,32,64); // 64 spaces
    let txt="TLS 1.3, client CertificateVerify";
    ptr=utils::append_bytes(&mut ccv,ptr,txt.as_bytes()); // 33 characters
    ptr=utils::append_byte(&mut ccv,ptr,0,1);   // add 0
    ptr=utils::append_bytes(&mut ccv,ptr,h);    // add transcript hash

// *** if sigalg==DILITHIUM2_P256, extract two signatures, and verify them separately
    if sigalg==DILITHIUM2_P256 {
        let pub1=&certpk[0..65];
        let pub2=&certpk[65..];
        let ret=x509::ecdsa_sig_decode(ccvsig);
        let siglen=ret.length;
        if siglen == 0 {
            return false;
        }   
        let index=ret.index;
        return sal::tls_signature_verify(ECDSA_SECP256R1_SHA384,&ccv[0..ptr],&ccvsig[0..siglen],pub1) && sal::tls_signature_verify(DILITHIUM2,&ccv[0..ptr],&ccvsig[index..],pub2);
    }

    let mut siglen=ccvsig.len();
// Special case processing required here for ECDSA signatures -  scvsig is modified
    if sigalg==ECDSA_SECP256R1_SHA256 || sigalg==ECDSA_SECP384R1_SHA384 {
        let ret=x509::ecdsa_sig_decode(ccvsig);
        siglen=ret.length;
        if siglen == 0 {
            return false;
        }    
    }
    return sal::tls_signature_verify(sigalg,&ccv[0..ptr],&ccvsig[0..siglen],certpk);
}

/// Derive verifier
pub fn derive_verifier_data(htype:usize,cf: &mut [u8],chts: &[u8],h: &[u8]) {
    let mut fk:[u8;MAX_HASH]=[0;MAX_HASH];  
    let info="finished";
    let hlen=sal::hash_len(htype);
    hkdf_expand_label(htype,&mut fk[0..hlen],chts,&info.as_bytes(),None);
    sal::hmac(htype,cf,&fk[0..hlen],h);
}

/// Check verifier
pub fn check_verifier_data(htype: usize,sf: &[u8],shts: &[u8],h: &mut [u8]) -> bool {
    let mut vd:[u8;MAX_HASH]=[0;MAX_HASH];
    let hlen=sal::hash_len(htype);
    derive_verifier_data(htype,&mut vd[0..hlen],shts,h);

    if sf.len() != hlen {
        return false;
    }
    for i in 0..hlen {
        if sf[i] != vd[i] {
            return false;
        }
    }
    return true;
}

