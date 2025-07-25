
//! Security Abstraction Layer. This version uses MIRACL core functions, plus elliptic curve crypto from TLSECC

#![allow(dead_code)]

use zeroize::Zeroize;

extern crate mcore;
extern crate tlsecc;
use mcore::hmac;
use mcore::hash256::HASH256;
use mcore::hash384::HASH384;
use mcore::hash512::HASH512;
use mcore::rand::RAND;
use mcore::gcm::GCM;

use crate::config;
use crate::tls13::keys;

extern crate rand;

//use oqs;
//use oqs::kem;

/// Return SAL name
pub fn name() -> &'static str {
    return "MIRACL Core and TII TLSECC";
}

/// Initialize SAL
pub fn init() -> bool {
//    oqs::init();
    return true;
}

// Assume a thread-safe global random number resource

/// Return a random byte
pub fn random_byte() -> u8 {
    return rand::random::<u8>();
}

/// Return a random word
pub fn random_word() -> u32 {
    return rand::random::<u32>();
}

/// Return an array of random bytes
pub fn random_bytes(len: usize,rn: &mut [u8]){
    for i in 0..len {
        rn[i]=random_byte();
    }
}

/// Return size of key exchange secret key in bytes
pub fn secret_key_size(group: u16) -> usize {
    if group==config::X25519 {
        return 32;
    }
    if group==config::SECP256R1 {
        return 32;
    }
    if group==config::SECP384R1 {    
        return 48;
    }
    if config::CRYPTO_SETTING>=config::POST_QUANTUM {
        if group==config::MLKEM768 {
            return mcore::kyber::SECRET_CCA_SIZE_768;
            //let kem = kem::Kem::new(kem::Algorithm::Kyber768).unwrap();
            //return kem.length_secret_key();
        }
        if group==config::HYBRID_KX {
            return mcore::kyber::SECRET_CCA_SIZE_768+32;
            //let kem = kem::Kem::new(kem::Algorithm::Kyber768).unwrap();
            //return kem.length_secret_key()+32;
        }
    }
    return 0;
}

/// Return size of clients key exchange public key in bytes
pub fn client_public_key_size(group: u16) -> usize {
    if group==config::X25519 {
        return 32;
    }
    if group==config::SECP256R1 {
        return 65;
    }
    if group==config::SECP384R1 {    
        return 97;
    }
    if config::CRYPTO_SETTING>=config::POST_QUANTUM {
        if group==config::MLKEM768 {
            return mcore::kyber::PUBLIC_SIZE_768;
            //let kem = kem::Kem::new(kem::Algorithm::Kyber768).unwrap();
            //return kem.length_public_key();              
        }
        if group==config::HYBRID_KX {
            return mcore::kyber::PUBLIC_SIZE_768+32;
            //let kem = kem::Kem::new(kem::Algorithm::Kyber768).unwrap();
            //return kem.length_public_key()+32;    
        }
    }
    return 0;
}

/// Return size of servers key exchange public key (or ciphertext) in bytes
pub fn server_public_key_size(group: u16) -> usize {
    if group==config::X25519 {
        return 32;
    }
    if group==config::SECP256R1 {
        return 65;
    }
    if group==config::SECP384R1 {    
        return 97;
    }
    if config::CRYPTO_SETTING>=config::POST_QUANTUM {
        if group==config::MLKEM768 {
            return mcore::kyber::CIPHERTEXT_SIZE_768;
            //let kem = kem::Kem::new(kem::Algorithm::Kyber768).unwrap();
            //return kem.length_ciphertext(); 
        }
        if group==config::HYBRID_KX {
            return mcore::kyber::CIPHERTEXT_SIZE_768+32;
            //let kem = kem::Kem::new(kem::Algorithm::Kyber768).unwrap();
            //return kem.length_ciphertext()+32;         
        }
    }
    return 0;
}

/// Return shared secret size in bytes
pub fn shared_secret_size(group: u16) -> usize {
    if group==config::X25519 {
        return 32;
    }
    if group==config::SECP256R1 {
        return 32;
    }
    if group==config::SECP384R1 {    
        return 48;
    }
    if config::CRYPTO_SETTING>=config::POST_QUANTUM {
        if group==config::MLKEM768 {
            return mcore::kyber::SHARED_SECRET_768;
            //let kem = kem::Kem::new(kem::Algorithm::Kyber768).unwrap();
            //return kem.length_shared_secret(); 
        }
        if group==config::HYBRID_KX {
            return mcore::kyber::SHARED_SECRET_768+32;
            //let kem = kem::Kem::new(kem::Algorithm::Kyber768).unwrap();
            //return kem.length_shared_secret()+32; 
        }
    }
    return 0;
}

/// Provide list of supported cipher suites
pub fn ciphers(ciphers: &mut [u16]) -> usize {
    let n=2;
    ciphers[0]=config::AES_128_GCM_SHA256;
    ciphers[1]=config::AES_256_GCM_SHA384;
    return n;
}

/// Provide list of supported key exchange groups
// The order matters - favourites first
pub fn groups(groups: &mut [u16]) -> usize {
    let mut n=0;

    if config::CRYPTO_SETTING==config::TINY_ECC || config::CRYPTO_SETTING==config::EDDSA || config::CRYPTO_SETTING==config::TYPICAL {
        n=3;
        groups[0]=config::X25519;
        groups[1]=config::SECP256R1;
        groups[2]=config::SECP384R1;        
    }
    if config::CRYPTO_SETTING==config::POST_QUANTUM {
        n=4;
        groups[0]=config::MLKEM768;
        groups[1]=config::X25519;
        groups[2]=config::SECP256R1;
        groups[3]=config::SECP384R1;
    }
    if config::CRYPTO_SETTING==config::HYBRID {
        n=5;
        groups[0]=config::HYBRID_KX;
        groups[1]=config::MLKEM768;
        groups[2]=config::X25519;
        groups[3]=config::SECP256R1;
        groups[4]=config::SECP384R1;
    }

    return n;
}

/// Provide list of supported signature algorithms (for TLS)
pub fn sigs(sig_algs: &mut [u16]) -> usize {
    let mut n=2;
    sig_algs[0]=config::ECDSA_SECP256R1_SHA256;
    sig_algs[1]=config::ECDSA_SECP384R1_SHA384;

    if config::CRYPTO_SETTING>=config::TYPICAL {
        sig_algs[n]=config::RSA_PSS_RSAE_SHA256; n+=1;
    }
    if config::CRYPTO_SETTING>=config::EDDSA {
        sig_algs[n]=config::ED25519; n+=1;
        sig_algs[n]=config::ED448; n+=1;
    }
    if config::CRYPTO_SETTING>=config::POST_QUANTUM {
        sig_algs[n]=config::MLDSA65; n+=1;
    }
    if config::CRYPTO_SETTING==config::HYBRID {
        sig_algs[n]=config::MLDSA44; n+=1;
        sig_algs[n]=config::MLDSA44_P256; n+=1; 
        sig_algs[n]=config::ECDSA_SECP256R1_SHA384; n+=1;         
    }
    return n;
}

/// Provide list of supported signature algorithms (for Certificates)
pub fn sig_certs(sig_algs_cert: &mut [u16]) -> usize {
    let mut n=2;
    sig_algs_cert[0]=config::ECDSA_SECP256R1_SHA256;
    sig_algs_cert[1]=config::ECDSA_SECP384R1_SHA384;

    if config::CRYPTO_SETTING>=config::TYPICAL {
        sig_algs_cert[n]=config::RSA_PKCS1_SHA256; n+=1;
        sig_algs_cert[n]=config::RSA_PKCS1_SHA384; n+=1;
        sig_algs_cert[n]=config::RSA_PKCS1_SHA512; n+=1;
    }
    if config::CRYPTO_SETTING>=config::EDDSA {
        sig_algs_cert[n]=config::ED25519; n+=1;
        sig_algs_cert[n]=config::ED448; n+=1;
    }
    if config::CRYPTO_SETTING>=config::POST_QUANTUM {
        sig_algs_cert[n]=config::MLDSA65; n+=1;   
    }
    if config::CRYPTO_SETTING==config::HYBRID {
        sig_algs_cert[n]=config::MLDSA44; n+=1; 
        sig_algs_cert[n]=config::MLDSA44_P256; n+=1; 
        sig_algs_cert[n]=config::ECDSA_SECP256R1_SHA384; n+=1;
    }
    return n;
}

/// Return hashtype from cipher_suite
pub fn hash_type(cipher_suite: u16) -> usize {
    let mut htype=0;  
    if cipher_suite==config::AES_128_GCM_SHA256 {htype=config::SHA256_T;}
    if cipher_suite==config::AES_256_GCM_SHA384 {htype=config::SHA384_T;}
    if cipher_suite==config::CHACHA20_POLY1305_SHA256 {htype=config::SHA256_T;}
    return htype;
}

/// Return hash length from hash type
pub fn hash_len(hash_type: usize) -> usize {
    let mut hlen=0;
    if hash_type==config::SHA256_T {hlen=32;}
    if hash_type==config::SHA384_T {hlen=48;}
    if hash_type==config::SHA512_T {hlen=64;}
    return hlen;
}

/// Get AEAD key length parameter
pub fn aead_key_len(cipher_suite:u16) -> usize {
    let mut klen=0;
    if cipher_suite==config::AES_128_GCM_SHA256 {
        klen=16;
    }
    if cipher_suite==config::AES_256_GCM_SHA384 {
        klen=32;
    }
    if cipher_suite==config::CHACHA20_POLY1305_SHA256 {
        klen=32;
    }
    return klen;
}

/// Get AEAD tag length parameter
pub fn aead_tag_len(cipher_suite:u16) -> usize {
    let mut tlen=0;
    if cipher_suite==config::AES_128_GCM_SHA256 {
        tlen=16;
    }
    if cipher_suite==config::AES_256_GCM_SHA384 {
        tlen=16;
    }
    if cipher_suite==config::CHACHA20_POLY1305_SHA256 { 
        tlen=16;
    }
    return tlen;
}

/// Key derivation function
pub fn hkdf_expand(htype:usize, okm: &mut [u8],prk: &[u8], info: &[u8])
{
    let hlen=hash_len(htype);
    hmac:: hkdf_expand(hmac::MC_SHA2,hlen,okm,okm.len(),prk,info);
}

/// HKDF - Extract secret from raw input
pub fn hkdf_extract(htype: usize,prk: &mut [u8],salt: Option<&[u8]>,ikm: &[u8])
{
    let hlen=hash_len(htype);
    hmac::hkdf_extract(hmac::MC_SHA2,hlen,prk,salt,ikm);
}

/// HMAC
pub fn hmac(htype: usize,t: &mut [u8],k: &[u8],m: &[u8]) {
    let hlen=hash_len(htype);
    hmac::hmac1(hmac::MC_SHA2,hlen,t,hlen,k,m);
}

/// Hash of NULL
pub fn hash_null(htype: usize,h: &mut [u8]) -> usize
{
    let hlen=hash_len(htype);
    if htype==config::SHA256_T {
        let mut sh = HASH256::new();
        let mh=sh.hash();
        for i in 0..hlen {h[i]=mh[i];}
    } 
    if htype==config::SHA384_T {
        let mut sh = HASH384::new();
        let mh=sh.hash();
        for i in 0..hlen {h[i]=mh[i];}
    }     
    if htype==config::SHA512_T {
        let mut sh = HASH512::new();
        let mh=sh.hash();
        for i in 0..hlen {h[i]=mh[i];}
    }     
    return hlen;    
}

/// Initialise transcript hash
pub fn hash_init(htype:usize,h: &mut config::UNIHASH)
{
    if htype==config::SHA256_T {
        let sh = HASH256::new();
        sh.as_bytes(&mut h.state);
    }
    if htype==config::SHA384_T {
        let sh = HASH384::new();
        sh.as_bytes(&mut h.state);
    }
    if htype==config::SHA512_T {
        let sh = HASH512::new();
        sh.as_bytes(&mut h.state);
    }
    h.htype=htype;
}

/// Hash an array of bytes
pub fn hash_process_array(h: &mut config::UNIHASH,b: &[u8])
{
    if h.htype==config::SHA256_T {
        let mut sh=HASH256::new();
        sh.from_bytes(&h.state);
        sh.process_array(b);
        sh.as_bytes(&mut h.state);
    }
    if h.htype==config::SHA384_T {
        let mut sh=HASH384::new();
        sh.from_bytes(&h.state);
        sh.process_array(b);
        sh.as_bytes(&mut h.state);
    }
    if h.htype==config::SHA512_T {
        let mut sh=HASH512::new();
        sh.from_bytes(&h.state);
        sh.process_array(b);
        sh.as_bytes(&mut h.state);
    }
}

/// Provide hash output
pub fn hash_output(h: &config::UNIHASH,o: &mut [u8]) -> usize
{
    let hlen=hash_len(h.htype);
    if h.htype==config::SHA256_T {
        let mut sh=HASH256::new();
        sh.from_bytes(&h.state);
        let mh=sh.continuing_hash();
        for i in 0..hlen {o[i]=mh[i];}
    }
    if h.htype==config::SHA384_T {
        let mut sh=HASH384::new();
        sh.from_bytes(&h.state);
        let mh=sh.continuing_hash();
        for i in 0..hlen {o[i]=mh[i];}
    }
    if h.htype==config::SHA512_T {
        let mut sh=HASH512::new();
        sh.from_bytes(&h.state);
        let mh=sh.continuing_hash();
        for i in 0..hlen {o[i]=mh[i];}
    }
    return hlen;
}

/// AEAD encryption assuming AES-GCM 
pub fn aead_encrypt(send: &keys::CRYPTO,hdr: &[u8],pt: &mut [u8],tag: &mut [u8])
{ 
    let mut g=GCM::new();
    let klen=aead_key_len(send.suite);
    g.init(klen,&send.k,12,&send.iv);
    g.add_header(hdr,hdr.len());
    g.add_plain(pt,None,pt.len());
    g.finish(&mut tag[0..send.taglen],true);
}

/// AEAD decryption assuming AES-GCM 
pub fn aead_decrypt(recv: &keys::CRYPTO,hdr: &[u8],ct: &mut [u8],tag: &[u8]) -> bool
{
    let mut ctag:[u8;config::MAX_TAG_SIZE]=[0;config::MAX_TAG_SIZE];
    let mut g=GCM::new();
    let klen=aead_key_len(recv.suite);
    g.init(klen,&recv.k,12,&recv.iv);
    g.add_header(hdr,hdr.len());
    g.add_cipher(ct,None,ct.len());
    g.finish(&mut ctag[0..recv.taglen],true);
    if ctag != tag {
        return false;
    }
    return true;
}

/// Generate key exchange private/public key pair
pub fn generate_key_pair(group: u16,csk: &mut [u8],pk: &mut [u8]) {
    if group==config::X25519 {
        use tlsecc::x25519;
        random_bytes(32,csk);
        x25519::KEY_PAIR(&csk[0..32],&mut pk[0..32]);
    }
    if group==config::SECP256R1 {
        use tlsecc::nist256;
        random_bytes(32,csk);
        nist256::KEY_PAIR(false,&csk[0..32], &mut pk[0..65]);
    }
    if group==config::SECP384R1 {
        use tlsecc::nist384;
        random_bytes(48,csk);
        nist384::KEY_PAIR(false,&csk[0..48], &mut pk[0..97]);
    }   
    if config::CRYPTO_SETTING>=config::POST_QUANTUM {    
        if group==config::MLKEM768 {
            use mcore::kyber;
            let mut r64: [u8;64]=[0;64];
            random_bytes(64,&mut r64);
            kyber::keypair_768(&r64,&mut csk[0..kyber::SECRET_CCA_SIZE_768],&mut pk[0..kyber::PUBLIC_SIZE_768]);
        }

        if group==config::HYBRID_KX {
            use mcore::kyber;          // first kyber
            let mut r64: [u8;64]=[0;64];
            random_bytes(64,&mut r64);
            kyber::keypair_768(&r64,&mut csk[0..kyber::SECRET_CCA_SIZE_768],&mut pk[0..kyber::PUBLIC_SIZE_768]);

            use tlsecc::x25519;// append an X25519
            let startsk=secret_key_size(config::MLKEM768);
            let startpk=client_public_key_size(config::MLKEM768);
            random_bytes(32,&mut csk[startsk..startsk+32]);
            x25519::KEY_PAIR(&csk[startsk..startsk+32], &mut pk[startpk..startpk+32]);
        }
    }
}

/// Given client public key cpk, generate shared secret ss and server public key or encapsulation spk
pub fn server_shared_secret(group: u16,cpk: &[u8],spk: &mut [u8],ss: &mut [u8]) -> bool {
    //let mut csk:[u8;config::MAX_KEX_SECRET_KEY]=[0;config::MAX_KEX_SECRET_KEY];
    let mut success=false;
    if group==config::X25519 {
        use tlsecc::x25519;
        let mut csk:[u8;32]=[0;32];
        random_bytes(32,&mut csk);
        x25519::KEY_PAIR(&csk[0..32],&mut spk[0..32]);
        success=x25519::SHARED_SECRET(&csk[0..32],&cpk[0..32],&mut ss[0..32]);
        csk.zeroize();
    }
    if group==config::SECP256R1 {
        use tlsecc::nist256;
        let mut csk:[u8;32]=[0;32];
        random_bytes(32,&mut csk);
        nist256::KEY_PAIR(false,&mut csk[0..32], &mut spk[0..65]);
        success=nist256::SHARED_SECRET(&csk[0..32],&cpk[0..65],&mut ss[0..32]);       
        csk.zeroize();
    }
    if group==config::SECP384R1 {
        use tlsecc::nist384;
        let mut csk:[u8;48]=[0;48];
        random_bytes(48,&mut csk);
        nist384::KEY_PAIR(false,&mut csk[0..48], &mut spk[0..97]);
        success=nist384::SHARED_SECRET(&csk[0..48],&cpk[0..97],&mut ss[0..48]);
        csk.zeroize();
    }
    if config::CRYPTO_SETTING>=config::POST_QUANTUM {    
        if group==config::MLKEM768 {
            use mcore::kyber;
            let mut r32: [u8;32]=[0;32];
            random_bytes(32,&mut r32);
            kyber::encrypt_768(&r32,&cpk[0..kyber::PUBLIC_SIZE_768],&mut ss[0..kyber::SHARED_SECRET_768],&mut spk[0..kyber::CIPHERTEXT_SIZE_768]);
            r32.zeroize();
            success=true;
        }
        if group==config::HYBRID_KX {
            use mcore::kyber;
            let mut r32: [u8;32]=[0;32];
            random_bytes(32,&mut r32);
            kyber::encrypt_768(&r32,&cpk[0..kyber::PUBLIC_SIZE_768],&mut ss[0..kyber::SHARED_SECRET_768],&mut spk[0..kyber::CIPHERTEXT_SIZE_768]);
            r32.zeroize();

            use tlsecc::x25519; // append an X25519
            let startct=server_public_key_size(config::MLKEM768);
            let startpk=client_public_key_size(config::MLKEM768);
            let startss=shared_secret_size(config::MLKEM768);

            let mut csk:[u8;32]=[0;32];
            random_bytes(32,&mut csk);
            x25519::KEY_PAIR(&csk, &mut spk[startct..startct+32]);
            success=x25519::SHARED_SECRET(&csk,&cpk[startpk..startpk+32],&mut ss[startss..startss+32]);        
            csk.zeroize();
        }
    }
// all zeros is suspect...
    let mut ors=ss[0];
    for i in 1..ss.len() {
        ors |= ss[i];
    }
    if ors==0 || !success {
        return false;
    }
    return true;
    //csk.zeroize();
}

/// Generate shared secret SS from secret key SK and public key PK
pub fn generate_shared_secret(group: u16,sk: &[u8],pk: &[u8],ss: &mut [u8]) -> bool {
    let mut success=false;
    if group==config::X25519 {
    	use tlsecc::x25519;
    	success=x25519::SHARED_SECRET(&sk[0..32],&pk[0..32],&mut ss[0..32]);   	
    }
    if group==config::SECP256R1 {
        use tlsecc::nist256;
        success=nist256::SHARED_SECRET(&sk[0..32],&pk[0..65],&mut ss[0..32]);
    }
    if group==config::SECP384R1 {
        use tlsecc::nist384;
        success=nist384::SHARED_SECRET(&sk[0..48],&pk[0..97],&mut ss[0..48]);
    }
    if config::CRYPTO_SETTING>=config::POST_QUANTUM {    
        if group==config::MLKEM768 {
            use mcore::kyber;
            kyber::decrypt_768(&sk[0..kyber::SECRET_CCA_SIZE_768],&pk[0..kyber::CIPHERTEXT_SIZE_768],&mut ss[0..kyber::SHARED_SECRET_768]);
            success=true;
        }
        if group==config::HYBRID_KX {
            use mcore::kyber;
            kyber::decrypt_768(&sk[0..kyber::SECRET_CCA_SIZE_768],&pk[0..kyber::CIPHERTEXT_SIZE_768],&mut ss[0..kyber::SHARED_SECRET_768]);
            use tlsecc::x25519;
            let startsk=secret_key_size(config::MLKEM768);
            let startct=server_public_key_size(config::MLKEM768);
            let startss=shared_secret_size(config::MLKEM768);
            success=x25519::SHARED_SECRET(&sk[startsk..startsk+32],&pk[startct..startct+32],&mut ss[startss..startss+32]);      
        }
    }
// all zeros is suspect...
    let mut ors=ss[0];
    for i in 1..ss.len() {
        ors |= ss[i];
    }
    if ors==0  || !success {
        return false;
    }
    return true;
}

/// Dilithium signature verification
fn dilithium3_verify(cert: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    use mcore::dilithium;
    return dilithium::verify_3(false,&pubkey[0..dilithium::PK_SIZE_3],None,cert,sig);
}

/// Dilithium signature 
pub fn dilithium3_sign(key: &[u8],mess: &[u8],sig: &mut [u8]) -> usize {
    use mcore::dilithium;
    dilithium::signature_3(false,None,&key[0..dilithium::SK_SIZE_3],None,mess,sig);
    return dilithium::SIG_SIZE_3;
}

/// Dilithium signature verification
fn dilithium2_verify(cert: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    use mcore::dilithium;
    return dilithium::verify_2(false,&pubkey[0..dilithium::PK_SIZE_2],None,cert,sig);
}

/// Dilithium signature 
pub fn dilithium2_sign(key: &[u8],mess: &[u8],sig: &mut [u8]) -> usize {
    use mcore::dilithium;
    dilithium::signature_2(false,None,&key[0..dilithium::SK_SIZE_2],None,mess,sig);
    return dilithium::SIG_SIZE_2;
}

/// RSA 2048-bit PKCS1.5 signature verification
fn rsa_2048_pkcs15_verify(hlen: usize,cert: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    use mcore::rsa2048::rsa;
    let mut ms: [u8;rsa::RFS]=[0;rsa::RFS];
    let mut cs: [u8;rsa::RFS]=[0;rsa::RFS];
    let mut pk=rsa::new_public_key();
    rsa::set_public_key(&mut pk,65537,&pubkey);
    rsa::encrypt(&pk,sig,&mut ms);
    hmac::pkcs15(hlen,cert,&mut cs,rsa::RFS);
    let mut res= ms==cs;
    if !res {
        hmac::pkcs15b(hlen,cert,&mut cs,rsa::RFS);
        res= ms==cs;
    }
    return res;
}

/// RSA 4096-bit PKCS1.5 signature verification
fn rsa_4096_pkcs15_verify(hlen: usize,cert: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    use mcore::rsa4096::rsa;
    let mut ms: [u8;rsa::RFS]=[0;rsa::RFS];
    let mut cs: [u8;rsa::RFS]=[0;rsa::RFS];
    let mut pk=rsa::new_public_key();
    rsa::set_public_key(&mut pk,65537,&pubkey);
    rsa::encrypt(&pk,sig,&mut ms);
    hmac::pkcs15(hlen,cert,&mut cs,rsa::RFS);
    let mut res= ms==cs;
    if !res {
        hmac::pkcs15b(hlen,cert,&mut cs,rsa::RFS);
        res= ms==cs;
    }
    return res;
}

/// RSA PKCS15 signature verification
pub fn rsa_pkcs15_verify(hlen: usize,cert: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    if pubkey.len()==256 {
        return rsa_2048_pkcs15_verify(hlen,cert,sig,pubkey);
    }
    if pubkey.len()==512 {
        return rsa_4096_pkcs15_verify(hlen,cert,sig,pubkey);
    }
    return false;
}

/// RSA 2048-bit PSS signature verification
fn rsa_2048_pss_rsae_verify(hlen: usize,mess: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    use mcore::rsa2048::rsa;
    let mut ms: [u8;rsa::RFS]=[0;rsa::RFS];
    let mut pk=rsa::new_public_key();
    rsa::set_public_key(&mut pk,65537,&pubkey);
    rsa::encrypt(&pk,sig,&mut ms);
    if hmac::pss_verify(hlen,mess,&ms) {
        return true;
    }
    return false;
}

/// RSA 4096-bit PSS signature verification
fn rsa_4096_pss_rsae_verify(hlen: usize,mess: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    use mcore::rsa4096::rsa;
    let mut ms: [u8;rsa::RFS]=[0;rsa::RFS];
    let mut pk=rsa::new_public_key();
    rsa::set_public_key(&mut pk,65537,&pubkey);
    rsa::encrypt(&pk,sig,&mut ms);
    if hmac::pss_verify(hlen,mess,&ms) {
        return true;
    }
    return false;
}

/// RSA PSS signature verification
pub fn rsa_pss_rsae_verify(hlen: usize,mess: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    if pubkey.len()==256 {
        return rsa_2048_pss_rsae_verify(hlen,mess,sig,pubkey);
    }
    if pubkey.len()==512 {
        return rsa_4096_pss_rsae_verify(hlen,mess,sig,pubkey);
    }
    return false;
}

/// NIST secp256r1 curve signature verification
pub fn secp256r1_ecdsa_verify(hlen: usize,cert: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    use tlsecc::nist256;
    let h=nist256::PREHASH(hlen,cert);
    return nist256::VERIFY(pubkey,&h,sig);
}

/// NIST secp384r1 curve signature verification
pub fn secp384r1_ecdsa_verify(hlen: usize,cert: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    use tlsecc::nist384;
    let h=nist384::PREHASH(hlen,cert);
    return nist384::VERIFY(pubkey,&h,sig);
}

pub fn ed25519_verify(cert: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    use tlsecc::ed25519;
    return ed25519::VERIFY(pubkey,cert,sig);
    //use mcore::ed25519::eddsa;
    //return eddsa::verify(false,pubkey,None,cert,sig);
}

pub fn ed448_verify(cert: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    use tlsecc::ed448;
    return ed448::VERIFY(pubkey,cert,sig);
}

/// Use Curve SECP256R1 ECDSA to digitally sign a message using a private key 
pub fn secp256r1_ecdsa_sign(hlen:usize,key: &[u8],mess: &[u8],sig: &mut [u8]) -> usize {
    use tlsecc::nist256;
    let mut r:[u8;40]=[0;40];
    random_bytes(40,&mut r);
    let h=nist256::PREHASH(hlen,mess);
    nist256::SIGN(key,&r,&h,sig);
    return 64;
}

/// Use Curve SECP384R1 ECDSA to digitally sign a message using a private key 
pub fn secp384r1_ecdsa_sign(hlen:usize,key: &[u8],mess: &[u8],sig: &mut [u8]) -> usize {
    use tlsecc::nist384;
    let mut r:[u8;56]=[0;56];
    random_bytes(56,&mut r);
    let h=nist384::PREHASH(hlen,mess);
    nist384::SIGN(key,&r,&h,sig);
    return 96;
}

pub fn ed25519_sign(key: &[u8],mess: &[u8],sig: &mut [u8]) -> usize {
    use tlsecc::ed25519;
    ed25519::SIGN(key,None,mess,sig);
    return 64;
}

pub fn ed448_sign(key: &[u8],mess: &[u8],sig: &mut [u8]) -> usize {
    use tlsecc::ed448;
    ed448::SIGN(key,None,mess,sig);
    return 114;
}

/// Use RSA-2048 PSS-RSAE to digitally sign a message using a private key
fn rsa_2048_pss_rsae_sign(hlen: usize,key: &[u8],mess: &[u8],sig: &mut [u8]) -> usize {
    use mcore::rsa2048::rsa;
    let len=key.len()/5;
    let p=&key[0..len];
    let q=&key[len..2*len];
    let dp=&key[2*len..3*len];
    let dq=&key[3*len..4*len];
    let c=&key[4*len..5*len];
    let mut sk=rsa::new_private_key();
    rsa::rsa_private_key_from_openssl(&p,&q,&dp,&dq,&c,&mut sk);
    let mut enc:[u8;256]=[0;256];
    let mut raw: [u8; 100] = [0; 100];
    random_bytes(100,&mut raw);
    let mut rng=RAND::new();
    rng.clean();
    rng.seed(100, &raw); 
    hmac::pss_encode(hlen,mess,&mut rng,&mut enc,256);
    rsa::decrypt(&sk,&enc,sig);
    return 256;
}

/// Use RSA-4096 PSS-RSAE to digitally sign a message using a private key
fn rsa_4096_pss_rsae_sign(hlen: usize,key: &[u8],mess: &[u8],sig: &mut [u8]) -> usize {
    use mcore::rsa4096::rsa;
    let len=key.len()/5;
    let p=&key[0..len];
    let q=&key[len..2*len];
    let dp=&key[2*len..3*len];
    let dq=&key[3*len..4*len];
    let c=&key[4*len..5*len];
    let mut sk=rsa::new_private_key();
    rsa::rsa_private_key_from_openssl(&p,&q,&dp,&dq,&c,&mut sk);
    let mut enc:[u8;512]=[0;512];
    let mut raw: [u8; 100] = [0; 100];
    random_bytes(100,&mut raw);
    let mut rng=RAND::new();
    rng.clean();
    rng.seed(100, &raw); 
    hmac::pss_encode(hlen,mess,&mut rng,&mut enc,512);
    rsa::decrypt(&sk,&enc,sig);
    return 512;
}

/// RSA PSS transcript signature using secret key
pub fn rsa_pss_rsae_sign(hlen:usize,key:&[u8],mess: &[u8],sig: &mut [u8]) -> usize {
    let len=key.len()/5;
    if len==128 {
        return rsa_2048_pss_rsae_sign(hlen,key,mess,sig);
    }
    if len==256 {
        return rsa_4096_pss_rsae_sign(hlen,key,mess,sig);
    }
    return 0;
}

// RFC8446:     "A TLS-compliant application MUST support digital signatures with
//              rsa_pkcs1_sha256 (for certificates), rsa_pss_rsae_sha256 (for
//              CertificateVerify and certificates), and ecdsa_secp256r1_sha256."
/// SAL signature verification
pub fn tls_signature_verify(sigalg: u16,buff: &[u8],sig: &[u8], pubkey: &[u8]) -> bool {
    
    match sigalg {
        config::ECDSA_SECP256R1_SHA256 => {return secp256r1_ecdsa_verify(32,buff,sig,pubkey);}, 
        config::ECDSA_SECP256R1_SHA384 => {return secp256r1_ecdsa_verify(48,buff,sig,pubkey);}, 
        config::ECDSA_SECP384R1_SHA384 => {return secp384r1_ecdsa_verify(48,buff,sig,pubkey);},
        _ => {}
    }

    if config::CRYPTO_SETTING>=config::TYPICAL {  
        match sigalg {  
            config::RSA_PKCS1_SHA256 => {return rsa_pkcs15_verify(32,buff,sig,pubkey);},
            config::RSA_PKCS1_SHA384 => {return rsa_pkcs15_verify(48,buff,sig,pubkey);},
            config::RSA_PKCS1_SHA512 => {return rsa_pkcs15_verify(64,buff,sig,pubkey);},
            config::RSA_PSS_RSAE_SHA256 => {return rsa_pss_rsae_verify(32,buff,sig,pubkey);},
            _ => {}
        }
    }
    if config::CRYPTO_SETTING>=config::EDDSA {   
        match sigalg {  
            config::ED25519 => { return ed25519_verify(buff,sig,pubkey);}, 
            config::ED448 => { return ed448_verify(buff,sig,pubkey);}, 
            _ => {}
        }
    }

    if config::CRYPTO_SETTING>=config::POST_QUANTUM {   
        match sigalg {  
            config::MLDSA65 => {return dilithium3_verify(buff,sig,pubkey);},
            config::MLDSA44 => {return dilithium2_verify(buff,sig,pubkey);},
            _ => {}
        }
    }
    return false;
/*
    match sigalg {
        config::ECDSA_SECP256R1_SHA256 => {return secp256r1_ecdsa_verify(32,buff,sig,pubkey);}, 
        config::ECDSA_SECP256R1_SHA384 => {return secp256r1_ecdsa_verify(48,buff,sig,pubkey);}, 
        config::ECDSA_SECP384R1_SHA384 => {return secp384r1_ecdsa_verify(48,buff,sig,pubkey);},
        config::ED25519 => { return ed25519_verify(buff,sig,pubkey);}, 
        config::ED448 => { return ed448_verify(buff,sig,pubkey);}, 
        config::RSA_PKCS1_SHA256 => {return rsa_pkcs15_verify(32,buff,sig,pubkey);},
        config::RSA_PKCS1_SHA384 => {return rsa_pkcs15_verify(48,buff,sig,pubkey);},
        config::RSA_PKCS1_SHA512 => {return rsa_pkcs15_verify(64,buff,sig,pubkey);},
        config::RSA_PSS_RSAE_SHA256 => {return rsa_pss_rsae_verify(32,buff,sig,pubkey);},
        config::MLDSA65 => {return dilithium3_verify(buff,sig,pubkey);},
        config::MLDSA44 => {return dilithium2_verify(buff,sig,pubkey);},
        _ => {return false;}
    }*/
}

/// Form Transcript Signature 
pub fn tls_signature(sigalg: u16,key: &[u8],trans: &[u8],sig: &mut [u8]) -> usize { // probably need to support more cases
    
    match sigalg {
        config:: ECDSA_SECP256R1_SHA256 => {return secp256r1_ecdsa_sign(32,key,trans,sig);},
        config:: ECDSA_SECP256R1_SHA384 => {return secp256r1_ecdsa_sign(48,key,trans,sig);},
        config:: ECDSA_SECP384R1_SHA384 => {return secp384r1_ecdsa_sign(48,key,trans,sig);},
        _ => {}
    }
    if config::CRYPTO_SETTING>=config::TYPICAL {  
        match sigalg {  
            config:: RSA_PSS_RSAE_SHA256 => {return rsa_pss_rsae_sign(32,key,trans,sig);},
            _ => {}
        }
    }
    if config::CRYPTO_SETTING>=config::EDDSA {  
        match sigalg {  
            config:: ED25519 => { return ed25519_sign(key,trans,sig);},
            config:: ED448 => { return ed448_sign(key,trans,sig);},
            _ => {}
        }
    }
    if config::CRYPTO_SETTING>=config::POST_QUANTUM {  
        match sigalg {  
            config:: MLDSA65 => {return dilithium3_sign(key,trans,sig);},
            config:: MLDSA44 => {return dilithium2_sign(key,trans,sig);},
            _ => {}
        }
    }
    return 0;
/*
    match sigalg {
        config:: ECDSA_SECP256R1_SHA256 => {return secp256r1_ecdsa_sign(32,key,trans,sig);},
        config:: ECDSA_SECP256R1_SHA384 => {return secp256r1_ecdsa_sign(48,key,trans,sig);},
        config:: ECDSA_SECP384R1_SHA384 => {return secp384r1_ecdsa_sign(48,key,trans,sig);},
        config:: RSA_PSS_RSAE_SHA256 => {return rsa_pss_rsae_sign(32,key,trans,sig);},
        config:: ED25519 => { return ed25519_sign(key,trans,sig);},
        config:: ED448 => { return ed448_sign(key,trans,sig);},
        config:: MLDSA65 => {return dilithium3_sign(key,trans,sig);},
        config:: MLDSA44 => {return dilithium2_sign(key,trans,sig);},
        _ => {return 0;}
    } */
}
