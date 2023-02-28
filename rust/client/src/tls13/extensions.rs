//! Build TLS1.3 extensions

use crate::tls13::utils;
use crate::config::*;

/// Create cipher suite bytes for Client Hello
pub fn cipher_suites(cs: &mut [u8],nsc:usize,ciphers: &[u16]) -> usize {
    let mut ptr=0;
    ptr=utils::append_int(cs,ptr,2*nsc,2);
    for i in 0..nsc {
        ptr=utils::append_int(cs,ptr,ciphers[i] as usize,2);
    }
    return ptr;
}

// Functions to build clientHello Extensions based on our preferences/capabilities

/// Build Heartbeat extension
pub fn add_heartbeat(ext: &mut [u8],ptr: usize) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,HEARTBEAT,2);
    nptr=utils::append_int(ext,nptr,1,2);
    if PEER_CAN_HEARTBEAT {
        nptr=utils::append_int(ext,nptr,1,1);
    } else {
        nptr=utils::append_int(ext,nptr,2,1);
    }
    return nptr; 
}

/// Build Servername Extension
pub fn add_server_name(ext: &mut [u8],ptr: usize,name: &[u8],len: usize) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,SERVER_NAME,2);  // This extension is SERVER_NAME(0)
    nptr=utils::append_int(ext,nptr,5+len,2);  // In theory its a list..
    nptr=utils::append_int(ext,nptr,3+len,2);  // but only one entry
    nptr=utils::append_int(ext,nptr,0,1);      // Server is of type DNS Hostname (only one type supported, and only one of each type)
    nptr=utils::append_int(ext,nptr,len,2);    // serverName length
    nptr=utils::append_bytes(ext,nptr,&name[0..len]);   // servername 
    return nptr;
}

/// Build Supported Groups Extension
pub fn add_supported_groups(ext: &mut [u8],ptr: usize, nsg: usize, groups: &[u16]) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,SUPPORTED_GROUPS,2); // This extension is SUPPORTED GROUPS(0x0a)
    nptr=utils::append_int(ext,nptr,2*nsg+2,2);        // Total length
    nptr=utils::append_int(ext,nptr,2*nsg,2);          // Number of entries
    for i in 0..nsg {
        nptr=utils::append_int(ext,nptr,groups[i] as usize,2);
    }
    return nptr;
}

/// Build client cert type extension to ask for raw public key
// X.509 cert assumed always possible
#[allow(dead_code)]
pub fn add_client_raw_public_key(ext: &mut [u8],ptr: usize) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,CLIENT_CERT_TYPE,2);
    nptr=utils::append_int(ext,nptr,3,2); // extension length
    nptr=utils::append_byte(ext,nptr,2,1);
    nptr=utils::append_byte(ext,nptr,RAW_PUBLIC_KEY,1);
    nptr=utils::append_byte(ext,nptr,X509_CERT,1);
    return nptr;

}

/// Build server cert type extension to ask for raw public key
// X.509 cert assumed always possible
#[allow(dead_code)]
pub fn add_server_raw_public_key(ext: &mut [u8],ptr: usize) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,SERVER_CERT_TYPE,2);
    nptr=utils::append_int(ext,nptr,3,2); // extension length
    nptr=utils::append_byte(ext,nptr,2,1);
    nptr=utils::append_byte(ext,nptr,RAW_PUBLIC_KEY,1);
    nptr=utils::append_byte(ext,nptr,X509_CERT,1);
    return nptr;

}

/// Build Signature algorithms Extension
pub fn add_supported_sigs(ext: &mut [u8],ptr: usize, nsa: usize, sig_algs: &[u16]) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,SIG_ALGS,2); // This extension is SUPPORTED GROUPS(0x0a)
    nptr=utils::append_int(ext,nptr,2*nsa+2,2);        // Total length
    nptr=utils::append_int(ext,nptr,2*nsa,2);          // Number of entries
    for i in 0..nsa {
        nptr=utils::append_int(ext,nptr,sig_algs[i] as usize,2);
    }
    return nptr;
}

/// Build Signature algorithms Cert Extension
pub fn add_supported_sigcerts(ext: &mut [u8],ptr: usize, nsac: usize, sig_alg_certs: &[u16]) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,SIG_ALGS_CERT,2); // This extension is SUPPORTED GROUPS(0x0a)
    nptr=utils::append_int(ext,nptr,2*nsac+2,2);        // Total length
    nptr=utils::append_int(ext,nptr,2*nsac,2);          // Number of entries
    for i in 0..nsac {
        nptr=utils::append_int(ext,nptr,sig_alg_certs[i] as usize,2);
    }
    return nptr;
}

/// Add Client Key Share extension
// Offer just one public key
pub fn add_key_share(ext: &mut [u8],ptr: usize,alg: u16,pk: &[u8]) -> usize {
    let mut nptr=ptr;
    let tlen=pk.len()+4;
    nptr=utils::append_int(ext,nptr,KEY_SHARE,2); // This extension is KEY_SHARE(0x0033)
    nptr=utils::append_int(ext,nptr,tlen+2,2);
    nptr=utils::append_int(ext,nptr,tlen,2);
    nptr=utils::append_int(ext,nptr,alg as usize,2);
    nptr=utils::append_int(ext,nptr,pk.len(),2);
    nptr=utils::append_bytes(ext,nptr,pk);
    return nptr;
}

/// Add ALPN extension
// Offer just one option
pub fn add_alpn(ext: &mut [u8],ptr: usize,ap: &[u8]) -> usize {
    let tlen=ap.len()+1;
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,APP_PROTOCOL,2);
    nptr=utils::append_int(ext,nptr,tlen+2,2);
    nptr=utils::append_int(ext,nptr,tlen,2);
    nptr=utils::append_int(ext,nptr,ap.len(),1);
    nptr=utils::append_bytes(ext,nptr,ap);
    return nptr;
}

/// Indicate supported PSK mode
pub fn add_psk(ext: &mut [u8],ptr: usize,mode: usize) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,PSK_MODE,2);
    nptr=utils::append_int(ext,nptr,2,2);
    nptr=utils::append_int(ext,nptr,1,1);
    nptr=utils::append_int(ext,nptr,mode,1);
    return nptr;
}

/// Indicate TLS version support
pub fn add_version(ext: &mut [u8],ptr: usize,version: usize) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,TLS_VER,2);
    nptr=utils::append_int(ext,nptr,3,2);
    nptr=utils::append_int(ext,nptr,2,1);
    nptr=utils::append_int(ext,nptr,version,2);
    return nptr;
}

/// Indicate preferred maximum fragment length
pub fn add_mfl(ext: &mut [u8],ptr: usize, mode: usize) -> usize {
    let mut nptr=ptr;
    if mode>0 {
    nptr=utils::append_int(ext,nptr,MAX_FRAG_LENGTH,2);
    nptr=utils::append_int(ext,nptr,1,2);
    nptr=utils::append_int(ext,nptr,mode,1);
    }
    return nptr;
}

/// Indicate preferred maximum record size
pub fn add_rsl(ext: &mut [u8],ptr: usize, size: usize) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,RECORD_SIZE_LIMIT,2);
    nptr=utils::append_int(ext,nptr,2,2);
    nptr=utils::append_int(ext,nptr,size,2);
    return nptr;    
}

/// Add n padding bytes
pub fn add_padding(ext: &mut [u8],ptr: usize, n: usize) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,PADDING,2);
    nptr=utils::append_int(ext,nptr,n,2);
    nptr=utils::append_byte(ext,nptr,0,n);
    return nptr;
}

/// Add a cookie - useful for handshake resumption
pub fn add_cookie(ext: &mut [u8],ptr: usize,ck: &[u8]) -> usize {
    let mut nptr=ptr;  
    nptr=utils::append_int(ext,nptr,COOKIE,2);
    nptr=utils::append_int(ext,nptr,ck.len(),2);
    nptr=utils::append_bytes(ext,nptr,ck);
    return nptr;    
}

/// indicate desire to send early data
pub fn add_early_data(ext: &mut [u8],ptr: usize) -> usize {
    let mut nptr=ptr; 
    nptr=utils::append_int(ext,nptr,EARLY_DATA,2);
    nptr=utils::append_int(ext,nptr,0,2);
    return nptr;
}

/// indicate willingness to do post handshake authentication
pub fn add_post_handshake_auth(ext: &mut [u8],ptr: usize) -> usize {
    let mut nptr=ptr; 
    nptr=utils::append_int(ext,nptr,POST_HANDSHAKE_AUTH,2);
    nptr=utils::append_int(ext,nptr,0,2);
    return nptr;
}

/// Add Pre-Shared-Key ....but omit binding
pub fn add_presharedkey(ext: &mut [u8],ptr: usize,age: usize,ids: &[u8],sha: usize,extra: &mut usize) -> usize {
    let mut nptr=ptr;
    let mut tlen1=0;
    let mut tlen2=0;
    tlen1+=ids.len()+2+4;
    tlen2+=sha+1;
    nptr=utils::append_int(ext,nptr,PRESHARED_KEY,2);
    nptr=utils::append_int(ext,nptr,tlen1+tlen2+4,2);
//PSK identifiers
    nptr=utils::append_int(ext,nptr,tlen1,2);
    nptr=utils::append_int(ext,nptr,ids.len(),2);
    nptr=utils::append_bytes(ext,nptr,ids);
    nptr=utils::append_int(ext,nptr,age,4);

    *extra=tlen2+2;
    return nptr;
}
