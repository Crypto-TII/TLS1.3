//! Build TLS1.3 extensions

use crate::tls13::utils;
use crate::config::*;

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

/// Add Key Share extension. Offer just one public key
pub fn add_key_share(ext: &mut [u8],ptr: usize,alg: u16,pk: &[u8]) -> usize {
    let mut nptr=ptr;
    let tlen=pk.len()+4;
    nptr=utils::append_int(ext,nptr,KEY_SHARE,2); // This extension is KEY_SHARE(0x0033)
    nptr=utils::append_int(ext,nptr,tlen,2);
    nptr=utils::append_int(ext,nptr,alg as usize,2);
    nptr=utils::append_int(ext,nptr,pk.len(),2);
    nptr=utils::append_bytes(ext,nptr,pk);
    return nptr;
}

/// Add empty Key Share extension
pub fn add_key_no_share(ext: &mut [u8],ptr: usize,alg: u16) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,KEY_SHARE,2); // This extension is KEY_SHARE(0x0033)
    nptr=utils::append_int(ext,nptr,2,2);
    nptr=utils::append_int(ext,nptr,alg as usize,2);
    return nptr;
}

/// Indicate TLS version support
pub fn add_version(ext: &mut [u8],ptr: usize,version: usize) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,TLS_VER,2);
    nptr=utils::append_int(ext,nptr,2,2);
    nptr=utils::append_int(ext,nptr,version,2);
    return nptr;
}

/// Build client cert type extension - select type
#[allow(dead_code)]
pub fn add_supported_client_cert_type(ext: &mut [u8],ptr: usize,cert_type: u8) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,CLIENT_CERT_TYPE,2);
    nptr=utils::append_int(ext,nptr,1,2); // extension length
    nptr=utils::append_byte(ext,nptr,cert_type,1);
    return nptr;

}

/// Build server cert type extension - select type
#[allow(dead_code)]
pub fn add_supported_server_cert_type(ext: &mut [u8],ptr: usize,cert_type: u8) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,SERVER_CERT_TYPE,2);
    nptr=utils::append_int(ext,nptr,1,2); // extension length
    nptr=utils::append_byte(ext,nptr,cert_type,1);
    return nptr;

}

/// Add Pre-Shared Key extension (accepting a key)
pub fn add_presharedkey(ext: &mut [u8],ptr: usize,index: usize,) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,PRESHARED_KEY,2);
    nptr=utils::append_int(ext,nptr,2,2);
    nptr=utils::append_int(ext,nptr,index,2);
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
#[allow(dead_code)]
pub fn add_rsl(ext: &mut [u8],ptr: usize, size: usize) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,RECORD_SIZE_LIMIT,2);
    nptr=utils::append_int(ext,nptr,2,2);
    nptr=utils::append_int(ext,nptr,size,2);
    return nptr;    
}

/// Build Servername Extension
pub fn add_server_name(ext: &mut [u8],ptr: usize) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,SERVER_NAME,2);  // This extension is SERVER_NAME(0)
    nptr=utils::append_int(ext,nptr,0,2);  // Empty
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

/// Indicate willingness to accept early data
pub fn add_early_data(ext: &mut [u8],ptr: usize) -> usize {
    let mut nptr=ptr; 
    nptr=utils::append_int(ext,nptr,EARLY_DATA,2);
    nptr=utils::append_int(ext,nptr,0,2);
    return nptr;
}

/// Build Signature algorithms Extension
pub fn add_supported_sigs(ext: &mut [u8],ptr: usize, nsa: usize, sig_algs: &[u16]) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,SIG_ALGS,2);    // This extension is SUPPORTED GROUPS(0x0a)
    nptr=utils::append_int(ext,nptr,2*nsa+2,2);     // Total length
    nptr=utils::append_int(ext,nptr,2*nsa,2);       // Number of entries
    for i in 0..nsa {
        nptr=utils::append_int(ext,nptr,sig_algs[i] as usize,2);
    }
    return nptr;
}
