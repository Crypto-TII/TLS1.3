//
// Security Abstraction Layer
// This version uses only MIRACL core functions
//
use zeroize::Zeroize;

extern crate mcore;
use mcore::hmac;
use mcore::hash256::HASH256;
use mcore::hash384::HASH384;
use mcore::hash512::HASH512;
use mcore::rand::RAND;
use mcore::gcm::GCM;

use crate::config;
use crate::tls13::keys;

extern crate rand;

use oqs;
use oqs::kem;

pub fn name() -> &'static str {
    return "MIRACL Core";
}

// initialize SAL
pub fn init() -> bool {
    oqs::init();
    return true;
}

// Assume a thread-safe global random number resource

// return a random byte
pub fn random_byte() -> u8 {
    return rand::random::<u8>();
}

pub fn random_bytes(len: usize,rn: &mut [u8]){
    for i in 0..len {
        rn[i]=random_byte();
    }
}

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
    if group==config::KYBER768 {
        let kem = kem::Kem::new(kem::Algorithm::Kyber768).unwrap();
        return kem.length_secret_key();
    }
    if group==config::SIDH {
        let kem = kem::Kem::new(kem::Algorithm::SidhP751).unwrap();
        return kem.length_secret_key();
    }
    return 0;
}

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
    if group==config::KYBER768 {
        let kem = kem::Kem::new(kem::Algorithm::Kyber768).unwrap();
        return kem.length_public_key();              
    }
    if group==config::SIDH {
        let kem = kem::Kem::new(kem::Algorithm::SidhP751).unwrap();
        return kem.length_public_key();
    }
    return 0;
}

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
    if group==config::KYBER768 {
        let kem = kem::Kem::new(kem::Algorithm::Kyber768).unwrap();
        return kem.length_ciphertext(); 
    }
    if group==config::SIDH {
        let kem = kem::Kem::new(kem::Algorithm::SidhP751).unwrap();
        return kem.length_ciphertext(); 
    }
    return 0;
}

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
    if group==config::KYBER768 {
        let kem = kem::Kem::new(kem::Algorithm::Kyber768).unwrap();
        return kem.length_shared_secret(); 
    }
    if group==config::SIDH {
        let kem = kem::Kem::new(kem::Algorithm::SidhP751).unwrap();
        return kem.length_shared_secret(); 
    }
    return 0;
}

// provide list of supported cipher suites
pub fn ciphers(ciphers: &mut [u16]) -> usize {
    let n=2;
    ciphers[0]=config::AES_128_GCM_SHA256;
    ciphers[1]=config::AES_256_GCM_SHA384;
    return n;
}

// provide list of supported key exchange groups
pub fn groups(groups: &mut [u16]) -> usize {
    let n=5;
    groups[0]=config::X25519;
    groups[1]=config::SECP256R1;
    groups[2]=config::SECP384R1;
    groups[3]=config::KYBER768;
    groups[4]=config::SIDH;
    return n;
}

// provide list of supported signature algorithms (for TLS)
pub fn sigs(sig_algs: &mut [u16]) -> usize {
    let n=3;
    sig_algs[0]=config::ECDSA_SECP256R1_SHA256;
    sig_algs[1]=config::RSA_PSS_RSAE_SHA256;
    sig_algs[2]=config::ECDSA_SECP384R1_SHA384;
    return n;
}

// provide list of supported signature algorithms (for Certificates)
pub fn sig_certs(sig_algs_cert: &mut [u16]) -> usize {
    let n=5;
    sig_algs_cert[0]=config::ECDSA_SECP256R1_SHA256;
    sig_algs_cert[1]=config::RSA_PKCS1_SHA256;
    sig_algs_cert[2]=config::ECDSA_SECP384R1_SHA384;
    sig_algs_cert[3]=config::RSA_PKCS1_SHA384;
    sig_algs_cert[4]=config::RSA_PKCS1_SHA512;   
    return n;
}

// return hashtype from cipher_suite
pub fn hash_type(cipher_suite: u16) -> usize {
    let mut htype=0;  
    if cipher_suite==config::AES_128_GCM_SHA256 {htype=config::SHA256_T;}
    if cipher_suite==config::AES_256_GCM_SHA384 {htype=config::SHA384_T;}
    if cipher_suite==config::CHACHA20_POLY1305_SHA256 {htype=config::SHA256_T;}
    return htype;
}

// return hashtype from signature algorithm
pub fn hash_type_sig(sigalg: u16) -> usize {
    let mut htype=0;  
    if sigalg==config::ECDSA_SECP256R1_SHA256 {htype=config::SHA256_T;}
    if sigalg==config::ECDSA_SECP384R1_SHA384 {htype=config::SHA384_T;}
    if sigalg==config::RSA_PSS_RSAE_SHA256 {htype=config::SHA256_T;}
    if sigalg==config::RSA_PSS_RSAE_SHA384 {htype=config::SHA384_T;}
    if sigalg==config::RSA_PSS_RSAE_SHA512 {htype=config::SHA512_T;}
    if sigalg==config::RSA_PKCS1_SHA256 {htype=config::SHA256_T;}
    if sigalg==config::RSA_PKCS1_SHA384 {htype=config::SHA384_T;}
    if sigalg==config::RSA_PKCS1_SHA512 {htype=config::SHA512_T;}
    return htype;
}

// return hash length from hash type
pub fn hash_len(hash_type: usize) -> usize {
    let mut hlen=0;
    if hash_type==config::SHA256_T {hlen=32;}
    if hash_type==config::SHA384_T {hlen=48;}
    if hash_type==config::SHA512_T {hlen=64;}
    return hlen;
}

// get AEAD parameters
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

// Key derivation function
pub fn hkdf_expand(htype:usize, okm: &mut [u8],prk: &[u8], info: &[u8])
{
    let hlen=hash_len(htype);
    hmac:: hkdf_expand(hmac::MC_SHA2,hlen,okm,okm.len(),prk,info);
}

// hkdf - Extract secret from raw input
pub fn hkdf_extract(htype: usize,prk: &mut [u8],salt: Option<&[u8]>,ikm: &[u8])
{
    let hlen=hash_len(htype);
    hmac::hkdf_extract(hmac::MC_SHA2,hlen,prk,salt,ikm);
}

// hmac
pub fn hmac(htype: usize,t: &mut [u8],k: &[u8],m: &[u8]) {
    let hlen=hash_len(htype);
    hmac::hmac1(hmac::MC_SHA2,hlen,t,hlen,k,m);
}

// Hash of NULL
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

// transcript hash code
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

pub fn aead_encrypt(send: &keys::CRYPTO,hdr: &[u8],pt: &mut [u8],tag: &mut [u8])
{ // AEAD encryption assuming AES-GCM (but should check send.k.suite)
    let mut g=GCM::new();
    let klen=aead_key_len(send.suite);
    g.init(klen,&send.k,12,&send.iv);
    g.add_header(hdr,hdr.len());
    g.add_plain(pt,None,pt.len());
    g.finish(&mut tag[0..send.taglen],true);
}

pub fn aead_decrypt(recv: &keys::CRYPTO,hdr: &[u8],ct: &mut [u8],tag: &[u8]) -> bool
{ // AEAD decryption AES-GCM
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

// generate private/public key pair
pub fn generate_key_pair(group: u16,csk: &mut [u8],pk: &mut [u8]) {
    if group==config::X25519 {
        use mcore::c25519::ecdh;
        random_bytes(32,csk);
        csk[31] &= 248;
        csk[0] &=127;
        csk[0] |=64;
        ecdh::key_pair_generate(None::<&mut RAND>, &mut csk[0..32], &mut pk[0..32]);
        pk[0..32].reverse();
    }
    if group==config::SECP256R1 {
    	use mcore::nist256::ecdh;
    	random_bytes(32,csk);
    	ecdh::key_pair_generate(None::<&mut RAND>, &mut csk[0..32], &mut pk[0..65]);
    }
    if group==config::SECP384R1 {
    	use mcore::nist384::ecdh;
    	random_bytes(48,csk);
    	ecdh::key_pair_generate(None::<&mut RAND>, &mut csk[0..48], &mut pk[0..97]);
    }    
    if group==config::KYBER768 {
        let kem = kem::Kem::new(kem::Algorithm::Kyber768).unwrap();
        let (cpk, sk) = kem.keypair().unwrap();
        let pkbytes=&cpk.as_ref();
        let skbytes=&sk.as_ref();
        for i in 0..pkbytes.len() {
            pk[i]=pkbytes[i];
        }
        for i in 0..skbytes.len() {
            csk[i]=skbytes[i];
        }
    }
    if group==config::SIDH {
        let kem = kem::Kem::new(kem::Algorithm::SidhP751).unwrap();
        let (cpk, sk) = kem.keypair().unwrap();
        let pkbytes=&cpk.as_ref();
        let skbytes=&sk.as_ref();
        for i in 0..pkbytes.len() {
            pk[i]=pkbytes[i];
        }
        for i in 0..skbytes.len() {
            csk[i]=skbytes[i];
        }
    }
}

// Given client public key cpk, generate shared secret ss and server public key or encapsulation spk
pub fn server_shared_secret(group: u16,cpk: &[u8],spk: &mut [u8],ss: &mut [u8]) {
    let mut csk:[u8;config::MAX_SECRET_KEY]=[0;config::MAX_SECRET_KEY];
    if group==config::X25519 {
        use mcore::c25519::ecdh;
        random_bytes(32,&mut csk);
        csk[31] &= 248;
        csk[0] &=127;
        csk[0] |=64;
        ecdh::key_pair_generate(None::<&mut RAND>, &mut csk[0..32], &mut spk[0..32]);
        spk[0..32].reverse();
        let mut rpk:[u8;32]=[0;32];
        for i in 0..32 {
            rpk[i]=cpk[i]
        }
        rpk[0..32].reverse();
        ecdh::ecpsvdp_dh(&csk[0..32],&rpk[0..32],&mut ss[0..32],0);
        ss[0..32].reverse();
    }
    if group==config::SECP256R1 {
    	use mcore::nist256::ecdh;
    	random_bytes(32,&mut csk);
    	ecdh::key_pair_generate(None::<&mut RAND>, &mut csk[0..32], &mut spk[0..65]);
        ecdh::ecpsvdp_dh(&csk[0..32],&cpk[0..65],&mut ss[0..32],0);
    }
    if group==config::SECP384R1 {
    	use mcore::nist384::ecdh;
    	random_bytes(48,&mut csk);
    	ecdh::key_pair_generate(None::<&mut RAND>, &mut csk[0..48], &mut spk[0..97]);
        ecdh::ecpsvdp_dh(&csk[0..48],&cpk[0..97],&mut ss[0..48],0);
    }
    if group==config::KYBER768 {
        let kem = kem::Kem::new(kem::Algorithm::Kyber768).unwrap();
        let pk=kem.public_key_from_bytes(&cpk).unwrap().to_owned();
        let (ct, share) = kem.encapsulate(&pk).unwrap();
        let myss=share.as_ref();
        for i in 0..myss.len() {
            ss[i]=myss[i];
        }
        let myct=ct.as_ref();
        for i in 0..myct.len() {
            spk[i]=myct[i];
        }        
    }
    if group==config::SIDH {
        let kem = kem::Kem::new(kem::Algorithm::SidhP751).unwrap();
        let pk=kem.public_key_from_bytes(&cpk).unwrap().to_owned();
        let (ct, share) = kem.encapsulate(&pk).unwrap();
        let myss=share.as_ref();
        for i in 0..myss.len() {
            ss[i]=myss[i];
        }
        let myct=ct.as_ref();
        for i in 0..myct.len() {
            spk[i]=myct[i];
        }        
    }
    csk.zeroize();
}

// generate shared secret SS from secret key SK and public key PK
pub fn generate_shared_secret(group: u16,sk: &[u8],pk: &[u8],ss: &mut [u8])
{
    if group==config::X25519 {
        use mcore::c25519::ecdh;
        let mut rpk:[u8;32]=[0;32];
        for i in 0..32 {
            rpk[i]=pk[i]
        }
        rpk[0..32].reverse();
        ecdh::ecpsvdp_dh(&sk[0..32],&rpk[0..32],&mut ss[0..32],0);
        ss[0..32].reverse();
    }
    if group==config::SECP256R1 {
        use mcore::nist256::ecdh;
        ecdh::ecpsvdp_dh(&sk[0..32],&pk[0..65],&mut ss[0..32],0);

    }
    if group==config::SECP384R1 {
        use mcore::nist384::ecdh;
        ecdh::ecpsvdp_dh(&sk[0..48],&pk[0..97],&mut ss[0..48],0);
    }
    if group==config::KYBER768 {
        let kem = kem::Kem::new(kem::Algorithm::Kyber768).unwrap();
        let ct=kem.ciphertext_from_bytes(&pk).unwrap().to_owned();
        let sk=kem.secret_key_from_bytes(&sk).unwrap().to_owned();
        let share = kem.decapsulate(&sk, &ct).unwrap();
        let myss=share.as_ref();
        for i in 0..myss.len() {
            ss[i]=myss[i];
        }
    }
    if group==config::SIDH {
        let kem = kem::Kem::new(kem::Algorithm::SidhP751).unwrap();
        let ct=kem.ciphertext_from_bytes(&pk).unwrap().to_owned();
        let sk=kem.secret_key_from_bytes(&sk).unwrap().to_owned();
        let share = kem.decapsulate(&sk, &ct).unwrap();
        let myss=share.as_ref();
        for i in 0..myss.len() {
            ss[i]=myss[i];
        }
    }
}

// RSA 2048-bit PKCS1.5 signature verification
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

// RSA 4096-bit PKCS1.5 signature verification
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

pub fn rsa_pkcs15_verify(hlen: usize,cert: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    if pubkey.len()==256 {
        return rsa_2048_pkcs15_verify(hlen,cert,sig,pubkey);
    }
    if pubkey.len()==512 {
        return rsa_4096_pkcs15_verify(hlen,cert,sig,pubkey);
    }
    return false;
}

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

// RSA PSS signature verification
pub fn rsa_pss_rsae_verify(hlen: usize,mess: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    if pubkey.len()==256 {
        return rsa_2048_pss_rsae_verify(hlen,mess,sig,pubkey);
    }
    if pubkey.len()==512 {
        return rsa_4096_pss_rsae_verify(hlen,mess,sig,pubkey);
    }
    return false;
}

// NIST secp256r1 curve signature verification
pub fn secp256r1_ecdsa_verify(hlen: usize,cert: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    use mcore::nist256::ecdh;
    let mut res=ecdh::public_key_validate(pubkey);
    if res!=0 {
        return false;
    }
    let (r,s)=sig.split_at(32);
    res=ecdh::ecpvp_dsa(hlen,pubkey,cert,&r,&s);
    if res!=0 {
        return false;
    }
    return true;
}

// NIST secp384r1 curve signature verification
pub fn secp384r1_ecdsa_verify(hlen: usize,cert: &[u8],sig: &[u8],pubkey: &[u8]) -> bool {
    use mcore::nist384::ecdh;
    let mut res=ecdh::public_key_validate(pubkey);
    if res!=0 {
        return false;
    }
    let (r,s)=sig.split_at(48);
    res=ecdh::ecpvp_dsa(hlen,pubkey,cert,&r,&s);
    if res!=0 {
        return false;
    }
    return true;
}

// Use Curve SECP256R1 ECDSA to digitally sign a message using a private key 
pub fn secp256r1_ecdsa_sign(hlen:usize,key: &[u8],mess: &[u8],sig: &mut [u8]) -> usize {
    use mcore::nist256::ecdh;
    let mut r:[u8;32]=[0;32];
    let mut s:[u8;32]=[0;32];
    let mut raw: [u8; 100] = [0; 100];
    random_bytes(100,&mut raw);
    let mut rng=RAND::new();
    rng.clean();
    rng.seed(100, &raw); 
    ecdh::ecpsp_dsa(hlen,&mut rng,key,mess,&mut r,&mut s);
    for i in 0..32{
        sig[i]=r[i];
        sig[32+i]=s[i];
    }
    return 64;
}

// Use Curve SECP384R1 ECDSA to digitally sign a message using a private key 
pub fn secp384r1_ecdsa_sign(hlen:usize,key: &[u8],mess: &[u8],sig: &mut [u8]) -> usize {
    use mcore::nist384::ecdh;
    let mut r:[u8;48]=[0;48];
    let mut s:[u8;48]=[0;48];
    let mut raw: [u8; 100] = [0; 100];
    random_bytes(100,&mut raw);
    let mut rng=RAND::new();
    rng.clean();
    rng.seed(100, &raw); 
    ecdh::ecpsp_dsa(hlen,&mut rng,key,mess,&mut r,&mut s);
    for i in 0..48{
        sig[i]=r[i];
        sig[48+i]=s[i];
    }
    return 96;
}

// Use RSA-2048 PSS-RSAE to digitally sign a message using a private key
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

// Use RSA-4096 PSS-RSAE to digitally sign a message using a private key
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

// RSA PSS transcript signature using secret key
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
// SAL signature verification
pub fn tls_signature_verify(sigalg: u16,buff: &[u8],sig: &[u8], pubkey: &[u8]) -> bool {
    match sigalg {
        config::RSA_PKCS1_SHA256 => {return rsa_pkcs15_verify(32,buff,sig,pubkey);},
        config::ECDSA_SECP256R1_SHA256 => {return secp256r1_ecdsa_verify(32,buff,sig,pubkey);}, 
        config::RSA_PKCS1_SHA384 => {return rsa_pkcs15_verify(48,buff,sig,pubkey);},
        config::ECDSA_SECP384R1_SHA384 => {return secp384r1_ecdsa_verify(48,buff,sig,pubkey);},
        config::RSA_PKCS1_SHA512 => {return rsa_pkcs15_verify(64,buff,sig,pubkey);},
        config::RSA_PSS_RSAE_SHA256 => {return rsa_pss_rsae_verify(32,buff,sig,pubkey);},
        _ => {return false;}
    }
}

// Form Transcript Signature 
pub fn tls_signature(sigalg: u16,key: &[u8],trans: &[u8],sig: &mut [u8]) -> usize { // probably need to support more cases
    match sigalg {
        config:: RSA_PSS_RSAE_SHA256 => {return rsa_pss_rsae_sign(32,key,trans,sig);},
        config:: ECDSA_SECP256R1_SHA256 => {return secp256r1_ecdsa_sign(32,key,trans,sig);},
        config::ECDSA_SECP384R1_SHA384 => {return secp384r1_ecdsa_sign(48,key,trans,sig);},
        _ => {return 0;}
    }
}
