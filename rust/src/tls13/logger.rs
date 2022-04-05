
use crate::config::*;
use crate::tls13::utils;
use crate::tls13::utils::RET;
use crate::tls13::utils::EESTATUS;
use crate::tls13::x509;
use crate::tls13::x509::PKTYPE;
use crate::tls13::ticket::TICKET;

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
            println!("{}",info);
        }
    }
}

pub fn log_cipher_suite(cipher_suite: u16) {
    log(IO_DEBUG,"Cipher Suite is ",0,None);
    match cipher_suite {
        AES_128_GCM_SHA256 => log(IO_DEBUG,"AES_128_GCM_SHA256\n",0,None),
        AES_256_GCM_SHA384 => log(IO_DEBUG,"AES_256_GCM_SHA384\n",0,None),
        CHACHA20_POLY1305_SHA256 => log(IO_DEBUG,"CHACHA20_POLY1305_SHA256\n",0,None),
        _ => log(IO_DEBUG,"Non-standard\n",0,None)
    }
}

pub fn log_sig_alg(sigalg: u16) {
    match sigalg {
        ECDSA_SECP256R1_SHA256 => log(IO_DEBUG,"ECDSA_SECP256R1_SHA256\n",0,None),
        RSA_PSS_RSAE_SHA256 => log(IO_DEBUG,"RSA_PSS_RSAE_SHA256\n",0,None),
        RSA_PKCS1_SHA256 => log(IO_DEBUG,"RSA_PKCS1_SHA256\n",0,None),
        ECDSA_SECP384R1_SHA384 => log(IO_DEBUG,"ECDSA_SECP384R1_SHA384\n",0,None),
        RSA_PSS_RSAE_SHA384 => log(IO_DEBUG,"RSA_PSS_RSAE_SHA384\n",0,None),
        RSA_PKCS1_SHA384 => log(IO_DEBUG,"RSA_PKCS1_SHA384\n",0,None),
        RSA_PSS_RSAE_SHA512 => log(IO_DEBUG,"RSA_PSS_RSAE_SHA512\n",0,None),
        RSA_PKCS1_SHA512 => log(IO_DEBUG,"RSA_PKCS1_SHA512\n",0,None),
        _ => log(IO_DEBUG,"Non-standard\n",0,None)
    }     
}

pub fn log_key_exchange(kex: u16) {
    log(IO_DEBUG,"Key Exchange Group is ",0,None);
    match kex {
        X25519 => log(IO_DEBUG,"x25519\n",0,None),
        SECP256R1 => log(IO_DEBUG,"secp256r1\n",0,None),
        SECP384R1 => log(IO_DEBUG,"secp384r1\n",0,None),
        _  => log(IO_DEBUG,"Non-standard\n",0,None)
    }
}

pub fn log_server_hello(cipher_suite: u16,kex: u16,pskid: isize,pk: &[u8],ck: &[u8]) {
    log(IO_DEBUG,"Parsing Server Hello\n",0,None);
    log_cipher_suite(cipher_suite);
    log_key_exchange(kex);
    if pskid>=0 {
        log(IO_DEBUG,"PSK identity= ",pskid,None);
    }
    if pk.len()>0 {
        log(IO_DEBUG,"Server Public Key= ",0,Some(&pk));
    }
    if ck.len()>0 {
       log(IO_DEBUG,"Cookie= ",0,Some(&ck));
    }
}

pub fn log_ticket(t: &TICKET) {
    log(IO_DEBUG,"\nParsing Ticket\n",0,None);
    log(IO_DEBUG,"Ticket = ",0,Some(&t.tick[0..t.tklen])); 
    let minutes=t.lifetime/60;
    log(IO_DEBUG,"life time in minutes = ",minutes as isize,None);
    log(IO_DEBUG,"Pre-Shared Key = ",0,Some(&t.psk[0..t.psklen])); 
    log(IO_DEBUG,"max_early_data = ",t.max_early_data as isize,None);
    log(IO_DEBUG,"\n",0,None);
}

pub fn log_enc_ext(expected: &EESTATUS,response: &EESTATUS) {
    if expected.early_data {
        if response.early_data {
            log(IO_PROTOCOL,"Early Data Accepted\n",0,None);
        } else {
            log(IO_PROTOCOL,"Early Data NOT accepted\n",0,None);
        }
    }

    if expected.alpn {
        if response.alpn {
            log(IO_DEBUG,"ALPN extension acknowledged by server\n",0,None);
        } else {
            log(IO_DEBUG,"Warning - ALPN extension NOT acknowledged\n",0,None);
        }
    }
    if expected.server_name {
        if response.server_name {
            log(IO_DEBUG,"Server name acknowledged\n",0,None);
        } else {
            log(IO_DEBUG,"Server name NOT acknowledged\n",0,None);
        }
    }
    if expected.max_frag_len {
       if response.max_frag_len {
            log(IO_DEBUG,"Max frag length request acknowledged\n",0,None);
        } else {
            log(IO_DEBUG,"Max frag length request NOT acknowledged\n",0,None);
        }
    }
}

// log certificate details
pub fn log_cert_details(pubkey: &[u8],pkt: &PKTYPE,sig: &[u8],sgt: &PKTYPE,issuer: &[u8],subject: &[u8])
{
    log(IO_DEBUG,"Parsing Certificate\n",0,None);
    log(IO_DEBUG,"Signature on Certificate is ",0,Some(sig)); 
    if sgt.kind==x509::ECC {
        log(IO_DEBUG,"ECC signature ",0,None);
        if sgt.curve==x509::USE_NIST256 {
            log(IO_DEBUG,"Curve is SECP256R1\n",0,None);
        }
        if sgt.curve==x509::USE_NIST384 {
            log(IO_DEBUG,"Curve is SECP384R1\n",0,None);
        }
        if sgt.curve==x509::USE_NIST521 {
            log(IO_DEBUG,"Curve is SECP521R1\n",0,None);
        }
        if sgt.hash == x509::H256 {log(IO_DEBUG,"Hashed with SHA256\n",0,None);}
        if sgt.hash == x509::H384 {log(IO_DEBUG,"Hashed with SHA384\n",0,None);}
        if sgt.hash == x509::H512 {log(IO_DEBUG,"Hashed with SHA512\n",0,None);}
    }
    if sgt.kind==x509::RSA {
        log(IO_DEBUG,"RSA signature of length ",sgt.curve as isize,None);
    }

    log(IO_DEBUG,"Public key from Certificate is ",0,Some(pubkey)); 
    if pkt.kind==x509::ECC {
        log(IO_DEBUG,"ECC public key ",0,None);
        if pkt.curve==x509::USE_NIST256 {
            log(IO_DEBUG,"Curve is SECP256R1\n",0,None);
        }
        if pkt.curve==x509::USE_NIST384 {
            log(IO_DEBUG,"Curve is SECP384R1\n",0,None);
        }
        if pkt.curve==x509::USE_NIST521 {
            log(IO_DEBUG,"Curve is SECP521R1\n",0,None);
        }
    }
    if pkt.kind==x509::RSA {
        log(IO_DEBUG,"Certificate public key is RSA of length ",pkt.curve as isize,None);
    }
    log(IO_DEBUG,"Issuer is  ",-1,Some(issuer));
    log(IO_DEBUG,"Subject is ",-1,Some(subject));
}


pub fn log_alert(detail: u8) {
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
        116 => log(IO_PROTOCOL,"Certificate required\n",0,None),
        120 => log(IO_PROTOCOL,"No application protocol\n",0,None),
        _ => log(IO_PROTOCOL,"Unrecognized alert\n",0,None)
    }
}

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
            _ => log(IO_DEBUG,"Unknown Error\n",0,None)
        }
    } else {
        match rtn as u8 {
            TIMED_OUT => log(IO_DEBUG,"Time Out\n",0,None),
            ALERT => log(IO_DEBUG,"Alert received from Server\n",0,None),
            _ => log(IO_DEBUG,"Unknown issue\n",0,None)
        }
    }
}
