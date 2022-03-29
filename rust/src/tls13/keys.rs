
use crate::config::*;
use crate::tls13::utils;
use crate::tls13::sal;
use crate::tls13::logger;

// create expanded HKDF label LB from label and context
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

// HKDF extension for TLS1.3
pub fn hkdf_expand_label(htype: usize,okm: &mut [u8],prk: &[u8],label: &[u8],ctx: Option<&[u8]>)
{
    let mut hl:[u8;MAX_HASH+24]=[0;MAX_HASH+24];
    let len=hkdf_label(&mut hl,okm.len(),label,ctx);
    sal::hkdf_expand(htype,okm,prk,&hl[0..len]);
}



// Key Schedule code
// Get Early Secret ES and optional Binder Key (either External or Resumption)
pub fn derive_early_secrets(htype: usize,psk: Option<&[u8]>,es: &mut [u8],bke: Option<&mut [u8]>,bkr: Option<&mut [u8]>)
{
    let mut emh:[u8;MAX_HASH]=[0;MAX_HASH];
    let zk:[u8;MAX_HASH]=[0;MAX_HASH];
    let eb="ext binder";
    let rb="res binder";
    let hlen=sal::hash_len(htype);
    if let Some(spsk) = psk {
        emh[0..hlen].clone_from_slice(&spsk[0..hlen]);
    } else {
        emh[0..hlen].clone_from_slice(&zk[0..hlen]);
    }
    sal::hkdf_extract(htype,es,Some(&zk[0..hlen]),&emh[0..hlen]);
    sal::hash_null(htype,&mut emh);

    if let Some(sbke) = bke {
        hkdf_expand_label(htype,&mut sbke[0..hlen],es,eb.as_bytes(),Some(&emh[0..hlen]));
    }
    if let Some(sbkr) = bkr {
        hkdf_expand_label(htype,&mut sbkr[0..hlen],es,rb.as_bytes(),Some(&emh[0..hlen]));
    }
}

pub struct CRYPTO {
    pub active: bool,
    pub k: [u8;MAX_KEY], // AEAD cryptographic Key bytes     
    pub iv: [u8;MAX_IV_SIZE],            // AEAD cryptographic IV bytes 
    pub record: usize,          // current record number - to be incremented 
    pub suite: usize,           // Cipher Suite 
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
    pub fn init(&mut self,cipher_suite: usize,ts: &[u8])
    {
        let htype=sal::hash_type(cipher_suite);
        let klen=sal::aead_key_len(cipher_suite);
        let kyt="key";
        let ivt="iv";
        hkdf_expand_label(htype,&mut self.k[0..klen],ts,kyt.as_bytes(),None);
        hkdf_expand_label(htype,&mut self.iv[0..12],ts,ivt.as_bytes(),None);

        self.active=true;
        self.suite=cipher_suite;
        self.record=0;
        self.taglen=sal::aead_tag_len(cipher_suite);
    }

    pub fn is_active(&mut self) -> bool {
        return self.active;
    }

//  increment record, and update IV
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

// update Traffic secret and associated traffic key and IV
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

fn parse_in_ecdsa_sig(htype: usize,ccvsig: &mut [u8]) -> usize {
    let mut c:[u8;MAX_ECC_FIELD]=[0;MAX_ECC_FIELD];
    let mut d:[u8;MAX_ECC_FIELD]=[0;MAX_ECC_FIELD];
    let hlen=sal::hash_len(htype);
    let mut ptr=0;   
    for i in 0..hlen {
        c[i]=ccvsig[i];
        d[i]=ccvsig[hlen+i];
    }
    let mut cinc=false;
    let mut dinc=false;
    if c[0]&0x80 !=0 {
        cinc=true;
    }
    if d[0]&0x80 !=0 {
        dinc=true;
    }
    let mut len=2*hlen+4;
    if cinc {len+=1;}
    if dinc {len+=1;}

    ptr=utils::append_byte(ccvsig,ptr,0x30,1);  // ASN.1 SEQ
    ptr=utils::append_byte(ccvsig,ptr,len as u8,1);
// c
    ptr=utils::append_byte(ccvsig,ptr,0x02,1);  // ASN.1 INT type
    if cinc {
        ptr=utils::append_byte(ccvsig,ptr,(hlen+1) as u8,1);
        ptr=utils::append_byte(ccvsig,ptr,0,1);
    } else {
        ptr=utils::append_byte(ccvsig,ptr,hlen as u8,1);
    }
    ptr=utils::append_bytes(ccvsig,ptr,&c[0..hlen]);
// d
    ptr=utils::append_byte(ccvsig,ptr,0x02,1);  // ASN.1 INT type
    if dinc {
        ptr=utils::append_byte(ccvsig,ptr,(hlen+1) as u8,1);
        ptr=utils::append_byte(ccvsig,ptr,0,1);
    } else {
        ptr=utils::append_byte(ccvsig,ptr,hlen as u8,1);
    }
    ptr=utils::append_bytes(ccvsig,ptr,&d[0..hlen]);
    return ptr;
}

pub fn create_client_cert_verifier(sigalg: usize,h: &[u8],key: &[u8],ccvsig: &mut [u8]) -> usize {
    let mut ptr=0;
    let txt="TLS 1.3, client CertificateVerify";
    let mut ccv:[u8;100+MAX_HASH]=[0;100+MAX_HASH];
    ptr=utils::append_byte(&mut ccv,ptr,32,64);
    ptr=utils::append_bytes(&mut ccv,ptr,txt.as_bytes());
    ptr=utils::append_byte(&mut ccv,ptr,0,1); 
    ptr=utils::append_bytes(&mut ccv,ptr,h);

    let mut cclen=sal::tls_signature(sigalg,key,&ccv[0..ptr],ccvsig);
    if sigalg==ECDSA_SECP256R1_SHA256 || sigalg==ECDSA_SECP384R1_SHA384 {
        cclen=parse_in_ecdsa_sig(sal::hash_type_sig(sigalg),ccvsig);
    }
    return cclen;
}

// Convert DER encoded signature to ECDSA signature
// parse out DER encoded (r,s) ECDSA signature into a single SIG 
fn parse_out_ecdsa_sig(htype: usize,scvsig: &mut [u8]) -> usize {
    let mut r:[u8;MAX_ECC_FIELD]=[0;MAX_ECC_FIELD];
    let mut s:[u8;MAX_ECC_FIELD]=[0;MAX_ECC_FIELD];
    let hlen=sal::hash_len(htype);
    let mut ptr=0;
    let mut rt=utils::parse_int(scvsig,1,&mut ptr); let der=rt.val;
    if rt.err!=0 || der!=0x30 {return 0;}
    rt=utils::parse_int(scvsig,1,&mut ptr); let slen=rt.val;
    if rt.err!=0 || slen+2!=scvsig.len() {return 0;}
// get r
    rt=utils::parse_int(scvsig,1,&mut ptr); let mut int=rt.val;
    if rt.err!=0 || int!=2 {return 0;}
    rt=utils::parse_int(scvsig,1,&mut ptr); let mut rlen=rt.val;
    if rt.err!=0 {return 0;}
    if rlen==hlen+1 { // one too big
        rlen-=1;
        rt=utils::parse_int(scvsig,1,&mut ptr); let lzero=rt.val;
        if rt.err!=0 || lzero!=0 {return 0;}
    }
    rt=utils::parse_bytes(&mut r[0..rlen],scvsig,&mut ptr); if rt.err!=0 {return 0;}

// get s
    rt=utils::parse_int(scvsig,1,&mut ptr); int=rt.val;
    if rt.err!=0 || int!=2 {return 0;}
    rt=utils::parse_int(scvsig,1,&mut ptr); let mut slen=rt.val;
    if rt.err!=0 {return 0;}
    if slen==hlen+1 { // one too big
        slen-=1;
        rt=utils::parse_int(scvsig,1,&mut ptr); let lzero=rt.val;
        if rt.err!=0 || lzero!=0 {return 0;}
    }
    rt=utils::parse_bytes(&mut s[0..slen],scvsig,&mut ptr); if rt.err!=0 {return 0;}

    if rlen<hlen || slen<hlen {return 0;}

    for i in 0..hlen {
        scvsig[i]=r[i];
        scvsig[hlen+i]=s[i];
    }
    return 2*hlen; // length of signature
}

pub fn check_server_cert_verifier(sigalg: usize,scvsig: &mut [u8],h: &[u8],certpk: &[u8]) -> bool {
    let mut scv:[u8;100+MAX_HASH]=[0;100+MAX_HASH];
    let mut ptr=0;
    ptr=utils::append_byte(&mut scv,ptr,32,64); // 64 spaces
    let txt="TLS 1.3, server CertificateVerify";
    ptr=utils::append_bytes(&mut scv,ptr,txt.as_bytes()); // 33 characters
    ptr=utils::append_byte(&mut scv,ptr,0,1);   // add 0
    ptr=utils::append_bytes(&mut scv,ptr,h);    // add transcript hash

    let mut siglen=scvsig.len();
// Special case processing required here for ECDSA signatures -  scvsig is modified
    if sigalg==ECDSA_SECP256R1_SHA256 || sigalg==ECDSA_SECP384R1_SHA384 {
        siglen=parse_out_ecdsa_sig(sal::hash_type_sig(sigalg),scvsig);
        if siglen == 0 {
            return false;
        }    
    }
    logger::logger(IO_DEBUG,"Certificate Signature = ",0,Some(&scvsig[0..siglen]));
    return sal::tls_signature_verify(sigalg,&scv[0..ptr],&scvsig[0..siglen],certpk);
}

pub fn derive_verifier_data(htype:usize,cf: &mut [u8],chts: &[u8],h: &[u8]) {
    let mut fk:[u8;MAX_HASH]=[0;MAX_HASH];  
    let info="finished";
    let hlen=sal::hash_len(htype);
    hkdf_expand_label(htype,&mut fk[0..hlen],chts,&info.as_bytes(),None);
    sal::hmac(htype,cf,&fk[0..hlen],h);
}

pub fn check_verifier_data(htype: usize,sf: &[u8],shts: &[u8],h: &mut [u8]) -> bool {
    let mut vd:[u8;MAX_HASH]=[0;MAX_HASH];
    let hlen=sal::hash_len(htype);
    derive_verifier_data(htype,&mut vd[0..hlen],shts,h);
    if &sf[0..hlen] == &vd[0..hlen] {
        return true;
    }
    return false;
}

