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
        } else {
            if info>=0 {
                println!("{:#06x}",info);
            } 
        }
    }
}

/// Log the cipher suite
pub fn log_cipher_suite(cipher_suite: u16) {
    log(IO_DEBUG,"Cipher Suite is ",-1,None);
    match cipher_suite {
        AES_128_GCM_SHA256 => log(IO_DEBUG,"AES_128_GCM_SHA256\n",-1,None),
        AES_256_GCM_SHA384 => log(IO_DEBUG,"AES_256_GCM_SHA384\n",-1,None),
        CHACHA20_POLY1305_SHA256 => log(IO_DEBUG,"CHACHA20_POLY1305_SHA256\n",-1,None),
        _ => log(IO_DEBUG,"Non-standard\n",-1,None)
    }
}

/// Log the signature algorithm
pub fn log_sig_alg(sigalg: u16) {
    log(IO_PROTOCOL,"Signature Algorithm is ",-1,None);
    match sigalg {
        ECDSA_SECP256R1_SHA256 => log(IO_PROTOCOL,"ECDSA_SECP256R1_SHA256\n",-1,None),
        RSA_PSS_RSAE_SHA256 => log(IO_PROTOCOL,"RSA_PSS_RSAE_SHA256\n",-1,None),
        RSA_PKCS1_SHA256 => log(IO_PROTOCOL,"RSA_PKCS1_SHA256\n",-1,None),
        ECDSA_SECP384R1_SHA384 => log(IO_PROTOCOL,"ECDSA_SECP384R1_SHA384\n",-1,None),
        RSA_PSS_RSAE_SHA384 => log(IO_PROTOCOL,"RSA_PSS_RSAE_SHA384\n",-1,None),
        RSA_PKCS1_SHA384 => log(IO_PROTOCOL,"RSA_PKCS1_SHA384\n",-1,None),
        RSA_PSS_RSAE_SHA512 => log(IO_PROTOCOL,"RSA_PSS_RSAE_SHA512\n",-1,None),
        RSA_PKCS1_SHA512 => log(IO_PROTOCOL,"RSA_PKCS1_SHA512\n",-1,None),
        MLDSA65 => log(IO_PROTOCOL,"MLDSA65\n",-1,None),
        MLDSA44 => log(IO_PROTOCOL,"MLDSA44\n",-1,None),
        MLDSA44_P256 => log(IO_PROTOCOL,"MLDSA44 + P256\n",-1,None),
        ED25519 => log(IO_PROTOCOL,"Ed25519\n",-1,None),
        ED448 => log(IO_PROTOCOL,"Ed448\n",-1,None),
        _ => log(IO_PROTOCOL,"Non-standard\n",-1,None)
    }     
}

/// Log the key exchange group
pub fn log_key_exchange(kex: u16) {
    log(IO_PROTOCOL,"Key Exchange Group is ",-1,None);
    match kex {
        X25519 => log(IO_PROTOCOL,"X25519\n",-1,None),
        SECP256R1 => log(IO_PROTOCOL,"SECP256R1\n",-1,None),
        SECP384R1 => log(IO_PROTOCOL,"SECP384R1\n",-1,None),
        MLKEM768 => log(IO_PROTOCOL,"MLKEM768\n",-1,None),
        HYBRID_KX => log(IO_PROTOCOL,"HYBRID MLKEM768+X25519\n",-1,None),
        SIDH => log(IO_PROTOCOL,"SIDH\n",-1,None),
        _  => log(IO_PROTOCOL,"Non-standard\n",-1,None)
    }
}




/// Log certificate details
pub fn log_cert_details(d: &CERT)
{
    log(IO_DEBUG,"Parsing Certificate\n",-1,None);
    log(IO_DEBUG,"Signature on Certificate is ",0,Some(&d.sig[0..d.sgt.len])); 
    if d.sgt.kind==x509::ECC {
        log(IO_DEBUG,"ECDSA signature ",-1,None);
        if d.sgt.curve==x509::USE_NIST256 {
            log(IO_DEBUG,"Curve is SECP256R1 ",-1,None);
        }
        if d.sgt.curve==x509::USE_NIST384 {
            log(IO_DEBUG,"Curve is SECP384R1 ",-1,None);
        }
        if d.sgt.curve==x509::USE_NIST521 {
            log(IO_DEBUG,"Curve is SECP521R1 ",-1,None);
        }
        if d.sgt.hash == x509::H256 {log(IO_DEBUG,"Hashed with SHA256\n",-1,None);}
        if d.sgt.hash == x509::H384 {log(IO_DEBUG,"Hashed with SHA384\n",-1,None);}
        if d.sgt.hash == x509::H512 {log(IO_DEBUG,"Hashed with SHA512\n",-1,None);}
    }
    if d.sgt.kind==x509::ECD {
        log(IO_DEBUG,"EDDSA signature ",-1,None);
        if d.sgt.curve==x509::USE_ED25519 {
            log(IO_DEBUG,"Curve is ED25519 ",-1,None);
        }
        if d.sgt.curve==x509::USE_ED448 {
            log(IO_DEBUG,"Curve is ED448 ",-1,None);
        }
    }
    if d.sgt.kind==x509::RSA {
        log(IO_DEBUG,"RSA signature of length ",d.sgt.curve as isize,None);
    }

    log(IO_DEBUG,"Public key from Certificate is ",0,Some(&d.pk[0..d.pkt.len])); 
    if d.pkt.kind==x509::ECC {
        log(IO_DEBUG,"ECC public key ",-1,None);
        if d.pkt.curve==x509::USE_NIST256 {
            log(IO_DEBUG,"Curve is SECP256R1\n",-1,None);
        }
        if d.pkt.curve==x509::USE_NIST384 {
            log(IO_DEBUG,"Curve is SECP384R1\n",-1,None);
        }
        if d.pkt.curve==x509::USE_NIST521 {
            log(IO_DEBUG,"Curve is SECP521R1\n",-1,None);
        }
    }
    if d.pkt.kind==x509::RSA {
        log(IO_DEBUG,"Certificate public key is RSA of length ",d.pkt.curve as isize,None);
    }
    let mut dn:[u8;256]=[0;256];

    let mut n=utils::make_dn(&mut dn,&d.issuer);
    log(IO_DEBUG,"Issuer is   ",-1,Some(&dn[0..n]));

    n=utils::make_dn(&mut dn,&d.subject);
    log(IO_DEBUG,"Subject is  ",-1,Some(&dn[0..n]));
}

/// Log a received alert
pub fn log_alert(detail: u8) {
    //log(IO_PROTOCOL,"Alert received - ",-1,None);
    match detail {
        0  => log(IO_PROTOCOL,"Close notify\n",-1,None),
        10 => log(IO_PROTOCOL,"Unexpected Message\n",-1,None),
        20 => log(IO_PROTOCOL,"Bad record mac\n",-1,None),
        22 => log(IO_PROTOCOL,"Record overflow\n",-1,None),
        40 => log(IO_PROTOCOL,"Handshake Failure (not TLS1.3?)\n",-1,None),
        42 => log(IO_PROTOCOL,"Bad Certificate\n",-1,None),
        43 => log(IO_PROTOCOL,"Unsupported certificate\n",-1,None),
        44 => log(IO_PROTOCOL,"Certificate revoked\n",-1,None),
        45 => log(IO_PROTOCOL,"Certificate expired\n",-1,None),
        46 => log(IO_PROTOCOL,"Certificate unknown\n",-1,None),
        47 => log(IO_PROTOCOL,"Illegal parameter\n",-1,None),
        48 => log(IO_PROTOCOL,"Unknown CA\n",-1,None),
        49 => log(IO_PROTOCOL,"Access denied\n",-1,None),
        50 => log(IO_PROTOCOL,"Decode error\n",-1,None),
        51 => log(IO_PROTOCOL,"Decrypt error\n",-1,None),
        70 => log(IO_PROTOCOL,"Protocol version\n",-1,None),
        71 => log(IO_PROTOCOL,"Insufficient security\n",-1,None),
        80 => log(IO_PROTOCOL,"Internal error\n",-1,None),
        86 => log(IO_PROTOCOL,"Inappropriate fallback\n",-1,None),
        90 => log(IO_PROTOCOL,"User cancelled\n",-1,None),
        109 => log(IO_PROTOCOL,"Missing Extension\n",-1,None),
        110 => log(IO_PROTOCOL,"Unsupported extension\n",-1,None),
        112 => log(IO_PROTOCOL,"Unrecognized name\n",-1,None),
        113 => log(IO_PROTOCOL,"Bad certificate status response\n",-1,None),
        115 => log(IO_PROTOCOL,"Unknown PSK identity\n",-1,None),
        116 => log(IO_PROTOCOL,"Valid Certificate required\n",-1,None),
        120 => log(IO_PROTOCOL,"No application protocol\n",-1,None),
        _ => log(IO_PROTOCOL,"Unrecognized alert\n",-1,None)
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
            NOT_TLS1_3 => log(IO_DEBUG,"Not TLS1.3\n",-1,None),
            ID_MISMATCH => log(IO_DEBUG,"Identity Mismatch\n",-1,None),
            UNRECOGNIZED_EXT => log(IO_DEBUG,"Unrecognized Extension\n",-1,None),
            BAD_HELLO => log(IO_DEBUG,"Malformed Hello\n",-1,None),
            WRONG_MESSAGE => log(IO_DEBUG,"Message received out-of-order\n",-1,None),
            BAD_CERT_CHAIN => log(IO_DEBUG,"Bad Certificate Chain\n",-1,None),
            MISSING_REQUEST_CONTEXT => log(IO_DEBUG,"Missing Request Context\n",-1,None),
            AUTHENTICATION_FAILURE => log(IO_DEBUG,"Authentication Failure\n",-1,None),
            BAD_RECORD => log(IO_DEBUG,"Malformed Record received (max size exceeded?)\n",-1,None),
            BAD_TICKET => log(IO_DEBUG,"Malformed Ticket received\n",-1,None),
            NOT_EXPECTED => log(IO_DEBUG,"Unexpected message/extension\n",-1,None),
            CA_NOT_FOUND => log(IO_DEBUG,"Certificate Authority not found\n",-1,None),
            CERT_OUTOFDATE => log(IO_DEBUG,"Certificate is out of date\n",-1,None),
            MEM_OVERFLOW => log(IO_DEBUG,"Memory overflow\n",-1,None),
            FORBIDDEN_EXTENSION => log(IO_DEBUG,"Forbidden extension found\n",-1,None),
            MAX_EXCEEDED => log(IO_DEBUG,"Maximum record size exceeded\n",-1,None),
            EMPTY_CERT_CHAIN => log(IO_DEBUG,"Client Certificate required\n",-1,None),
            TIME_OUT => log(IO_DEBUG,"Waited too long for response\n",-1,None),
            ERROR_ALERT_RECEIVED => log(IO_DEBUG,"Received a fatal alert\n",-1,None),
            CLOSURE_ALERT_RECEIVED => log(IO_DEBUG,"Received a normal closure alert\n",-1,None),
            BAD_MESSAGE => log(IO_DEBUG,"Malformed Message received\n",-1,None),
            BAD_PARAMETER => log(IO_DEBUG,"Received Bad parameter\n",-1,None),
            BAD_PROTOCOL => log(IO_DEBUG,"Wrong ALPN protocol\n",-1,None),
            BAD_HANDSHAKE => log(IO_DEBUG,"Handshake protocol failure\n",-1,None),
            CERT_VERIFY_FAIL => log(IO_DEBUG,"Certificate verification failure\n",-1,None),
            FINISH_FAIL => log(IO_DEBUG,"Handshake Finish failed to verify\n",-1,None),
            BAD_REQUEST_UPDATE => log(IO_DEBUG,"Bad Key update request\n",-1,None),
            MISSING_EXTENSIONS => log(IO_DEBUG,"Some extension(s) are missing\n",-1,None),
            _ => log(IO_DEBUG,"Unknown Error\n",-1,None),
        }
    } else {
        match rtn as u8 {
            TIMED_OUT => log(IO_DEBUG,"Time Out\n",-1,None),
            ALERT => log(IO_DEBUG,"Alert received from Client\n",-1,None),
            _ => log(IO_DEBUG,"Unknown issue\n",-1,None)
        }
    }
}
