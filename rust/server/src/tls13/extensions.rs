// Build TLS1.3 extensions
//

use crate::tls13::utils;
use crate::config::*;

// Add Client Key Share extension
// Offer just one public key
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

// Add Client Key Share extension
// Offer just one public key
pub fn add_key_no_share(ext: &mut [u8],ptr: usize,alg: u16) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,KEY_SHARE,2); // This extension is KEY_SHARE(0x0033)
    nptr=utils::append_int(ext,nptr,2,2);
    nptr=utils::append_int(ext,nptr,alg as usize,2);
    return nptr;
}

// indicate TLS version support
pub fn add_version(ext: &mut [u8],ptr: usize,version: usize) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,TLS_VER,2);
    nptr=utils::append_int(ext,nptr,2,2);
    nptr=utils::append_int(ext,nptr,version,2);
    return nptr;
}

pub fn add_presharedkey(ext: &mut [u8],ptr: usize,index: usize,) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,PRESHARED_KEY,2);
    nptr=utils::append_int(ext,nptr,2,2);
    nptr=utils::append_int(ext,nptr,index,2);
    return nptr;
}

// indicate preferred maximum fragment length
pub fn add_mfl(ext: &mut [u8],ptr: usize, mode: usize) -> usize {
    let mut nptr=ptr;
    if mode>0 {
    nptr=utils::append_int(ext,nptr,MAX_FRAG_LENGTH,2);
    nptr=utils::append_int(ext,nptr,1,2);
    nptr=utils::append_int(ext,nptr,mode,1);
    }
    return nptr;
}

// indicate preferred maximum record size
#[allow(dead_code)]
pub fn add_rsl(ext: &mut [u8],ptr: usize, size: usize) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,RECORD_SIZE_LIMIT,2);
    nptr=utils::append_int(ext,nptr,2,2);
    nptr=utils::append_int(ext,nptr,size,2);
    return nptr;    
}

// Build Servername Extension
pub fn add_server_name(ext: &mut [u8],ptr: usize) -> usize {
    let mut nptr=ptr;
    nptr=utils::append_int(ext,nptr,SERVER_NAME,2);  // This extension is SERVER_NAME(0)
    nptr=utils::append_int(ext,nptr,0,2);  // Empty
    return nptr;
}

// Add ALPN extension
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

// indicate desire to send early data
pub fn add_early_data(ext: &mut [u8],ptr: usize) -> usize {
    let mut nptr=ptr; 
    nptr=utils::append_int(ext,nptr,EARLY_DATA,2);
    nptr=utils::append_int(ext,nptr,0,2);
    return nptr;
}


