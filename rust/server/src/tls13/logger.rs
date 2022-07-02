//! Log protocol progress

use crate::config::*;
use crate::tls13::utils;
use crate::tls13::utils::RET;
use crate::tls13::x509;
use crate::tls13::certchain::CERT;
//use crate::tls13::ticket::TICKET;

/// Log a significant event and/or data
pub fn log(logit: usize,preamble: &str,info: isize,bytes: Option<&[u8]>) {
    if logit>VERBOSITY {
        return;
    }
    if VERBOSITY > IO_NONE {
        print!("{}",preamble);
        if let Some(sbytes) = bytes {
            let mut len=sbytes.len();
            if info<0 {
                for i in 0..len {
                    print!("{}",sbytes[i] as char);
                }
            } else {
                let mut truncated=false;
                print!("({}) ",len);
                if len>LOG_OUTPUT_TRUNCATION {
                    len=LOG_OUTPUT_TRUNCATION;
                    truncated=true;
                }
                utils::printbinary(&sbytes[0..len]);
                if truncated {
                    print!(" (truncated)");
                }
            }
            println!();
        }
        if info>0 {
            println!("{:#06x}",info);
        }
    }
}

/// Log the cipher suite
pub fn log_cipher_suite(cipher_suite: u16) {
    log(IO_DEBUG,"Cipher Suite is ",0,None);
    match cipher_suite {
        AES_128_GCM_SHA256 => log(IO_DEBUG,"AES_128_GCM_SHA256\n",0,None),
        AES_256_GCM_SHA384 => log(IO_DEBUG,"AES_256_GCM_SHA384\n",0,None),
        CHACHA20_POLY1305_SHA256 => log(IO_DEBUG,"CHACHA20_POLY1305_SHA256\n",0,None),
        _ => log(IO_DEBUG,"Non-standard\n",0,None)
    }
}

/// Log the signature algorithm
pub fn log_sig_alg(sigalg: u16) {
    log(IO_DEBUG,"Signature Algorithm is ",0,None);
    match sigalg {
        ECDSA_SECP256R1_SHA256 => log(IO_DEBUG,"ECDSA_SECP256R1_SHA256\n",0,None),
        RSA_PSS_RSAE_SHA256 => log(IO_DEBUG,"RSA_PSS_RSAE_SHA256\n",0,None),
        RSA_PKCS1_SHA256 => log(IO_DEBUG,"RSA_PKCS1_SHA256\n",0,None),
        ECDSA_SECP384R1_SHA384 => log(IO_DEBUG,"ECDSA_SECP384R1_SHA384\n",0,None),
        RSA_PSS_RSAE_SHA384 => log(IO_DEBUG,"RSA_PSS_RSAE_SHA384\n",0,None),
        RSA_PKCS1_SHA384 => log(IO_DEBUG,"RSA_PKCS1_SHA384\n",0,None),
        RSA_PSS_RSAE_SHA512 => log(IO_DEBUG,"RSA_PSS_RSAE_SHA512\n",0,None),
        RSA_PKCS1_SHA512 => log(IO_DEBUG,"RSA_PKCS1_SHA512\n",0,None),
        DILITHIUM3 => log(IO_DEBUG,"DILITHIUM3\n",0,None),
        _ => log(IO_DEBUG,"Non-standard\n",0,None)
    }     
}

/// Log the key exchange group
pub fn log_key_exchange(kex: u16) {
    log(IO_DEBUG,"Key Exchange Group is ",0,None);
    match kex {
        X25519 => log(IO_DEBUG,"x25519\n",0,None),
        SECP256R1 => log(IO_DEBUG,"secp256r1\n",0,None),
        SECP384R1 => log(IO_DEBUG,"secp384r1\n",0,None),
        KYBER768 => log(IO_DEBUG,"kyber768\n",0,None),
        SIDH => log(IO_DEBUG,"sidh\n",0,None),
        _  => log(IO_DEBUG,"Non-standard\n",0,None)
    }
}

/// Log certificate details
pub fn log_cert_details(d: &CERT)
{
    log(IO_DEBUG,"Parsing Certificate\n",0,None);
    log(IO_DEBUG,"Signature on Certificate is ",0,Some(&d.sig[0..d.sgt.len])); 
    if d.sgt.kind==x509::ECC {
        log(IO_DEBUG,"ECC signature ",0,None);
        if d.sgt.curve==x509::USE_NIST256 {
            log(IO_DEBUG,"Curve is SECP256R1\n",0,None);
        }
        if d.sgt.curve==x509::USE_NIST384 {
            log(IO_DEBUG,"Curve is SECP384R1\n",0,None);
        }
        if d.sgt.curve==x509::USE_NIST521 {
            log(IO_DEBUG,"Curve is SECP521R1\n",0,None);
        }
        if d.sgt.hash == x509::H256 {log(IO_DEBUG,"Hashed with SHA256\n",0,None);}
        if d.sgt.hash == x509::H384 {log(IO_DEBUG,"Hashed with SHA384\n",0,None);}
        if d.sgt.hash == x509::H512 {log(IO_DEBUG,"Hashed with SHA512\n",0,None);}
    }
    if d.sgt.kind==x509::RSA {
        log(IO_DEBUG,"RSA signature of length ",d.sgt.curve as isize,None);
    }

    log(IO_DEBUG,"Public key from Certificate is ",0,Some(&d.pk[0..d.pkt.len])); 
    if d.pkt.kind==x509::ECC {
        log(IO_DEBUG,"ECC public key ",0,None);
        if d.pkt.curve==x509::USE_NIST256 {
            log(IO_DEBUG,"Curve is SECP256R1\n",0,None);
        }
        if d.pkt.curve==x509::USE_NIST384 {
            log(IO_DEBUG,"Curve is SECP384R1\n",0,None);
        }
        if d.pkt.curve==x509::USE_NIST521 {
            log(IO_DEBUG,"Curve is SECP521R1\n",0,None);
        }
    }
    if d.pkt.kind==x509::RSA {
        log(IO_DEBUG,"Certificate public key is RSA of length ",d.pkt.curve as isize,None);
    }
    log(IO_DEBUG,"Issuer is  ",-1,Some(&d.issuer[0..d.islen]));
    log(IO_DEBUG,"Subject is ",-1,Some(&d.subject[0..d.sblen]));
}

/// Log a received alert
pub fn log_alert(detail: u8) {
    //log(IO_PROTOCOL,"Alert received - ",0,None);
    match detail {
        0  => log(IO_PROTOCOL,"Close notify\n",0,None),
        10 => log(IO_PROTOCOL,"Unexpected Message\n",0,None),
        20 => log(IO_PROTOCOL,"Bad record mac\n",0,None),
        22 => log(IO_PROTOCOL,"Record overflow\n",0,None),
        40 => log(IO_PROTOCOL,"Handshake Failure (not TLS1.3?)\n",0,None),
        42 => log(IO_PROTOCOL,"Bad Certificate\n",0,None),
        43 => log(IO_PROTOCOL,"Unsupported certificate\n",0,None),
        44 => log(IO_PROTOCOL,"Certificate revoked\n",0,None),
        45 => log(IO_PROTOCOL,"Certificate expired\n",0,None),
        46 => log(IO_PROTOCOL,"Certificate unknown\n",0,None),
        47 => log(IO_PROTOCOL,"Illegal parameter\n",0,None),
        48 => log(IO_PROTOCOL,"Unknown CA\n",0,None),
        49 => log(IO_PROTOCOL,"Access denied\n",0,None),
        50 => log(IO_PROTOCOL,"Decode error\n",0,None),
        51 => log(IO_PROTOCOL,"Decrypt error\n",0,None),
        70 => log(IO_PROTOCOL,"Protocol version\n",0,None),
        71 => log(IO_PROTOCOL,"Insufficient security\n",0,None),
        80 => log(IO_PROTOCOL,"Internal error\n",0,None),
        86 => log(IO_PROTOCOL,"Inappropriate fallback\n",0,None),
        90 => log(IO_PROTOCOL,"User cancelled\n",0,None),
        109 => log(IO_PROTOCOL,"Missing Extension\n",0,None),
        110 => log(IO_PROTOCOL,"Unsupported extension\n",0,None),
        112 => log(IO_PROTOCOL,"Unrecognized name\n",0,None),
        113 => log(IO_PROTOCOL,"Bad certificate status response\n",0,None),
        115 => log(IO_PROTOCOL,"Unknown PSK identity\n",0,None),
        116 => log(IO_PROTOCOL,"Valid Certificate required\n",0,None),
        120 => log(IO_PROTOCOL,"No application protocol\n",0,None),
        _ => log(IO_PROTOCOL,"Unrecognized alert\n",0,None)
    }
}

/// Log the Server's response
pub fn log_server_response(r: &RET) {
    let rtn=r.err;
    if rtn==0 {
        return;
    }
    if rtn<0 {
        match rtn {
            NOT_TLS1_3 => log(IO_DEBUG,"Not TLS1.3\n",0,None),
            BAD_CERT_CHAIN => log(IO_DEBUG,"Bad Certificate Chain\n",0,None),
            ID_MISMATCH => log(IO_DEBUG,"Identity Mismatch\n",0,None),
            UNRECOGNIZED_EXT => log(IO_DEBUG,"Unrecognized Extension\n",0,None),
            BAD_HELLO => log(IO_DEBUG,"Malformed Hello\n",0,None),
            WRONG_MESSAGE => log(IO_DEBUG,"Message received out-of-order\n",0,None),
            MISSING_REQUEST_CONTEXT => log(IO_DEBUG,"Missing Request Context\n",0,None),
            AUTHENTICATION_FAILURE => log(IO_DEBUG,"Authentication Failure\n",0,None),
            BAD_RECORD => log(IO_DEBUG,"Malformed Record received (max size exceeded?)\n",0,None),
            BAD_TICKET => log(IO_DEBUG,"Malformed Ticket received\n",0,None),
            EMPTY_CERT_CHAIN => log(IO_DEBUG,"Client Certificate required\n",0,None),
            BAD_PROTOCOL => log(IO_DEBUG,"Wrong ALPN protocol\n",0,None),
            _ => log(IO_DEBUG,"Unknown Error\n",0,None),
        }
    } else {
        match rtn as u8 {
            TIMED_OUT => log(IO_DEBUG,"Time Out\n",0,None),
            ALERT => log(IO_DEBUG,"Alert received from Client\n",0,None),
            _ => log(IO_DEBUG,"Unknown issue\n",0,None)
        }
    }
}
