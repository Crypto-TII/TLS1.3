//! Utility functions

use crate::config;

/// Function return structure
pub struct RET {
    pub val: usize,
    pub err: isize
}

/*
pub struct EESTATUS {
    pub early_data : bool,
    pub alpn : bool,
    pub server_name: bool,
    pub max_frag_len: bool
}
*/

/// Parse out slice from array m into e where ptr is a pointer into m, which increments if successful
pub fn parse_bytes(e: &mut [u8],m: &[u8],ptr: &mut usize) -> RET {
    let mut r=RET{val:0,err:config::BAD_RECORD};
    if *ptr+e.len()>m.len() {  // can't go beyond end of array
        return r;
    }
    for i in 0..e.len() {
        if i<m.len() {
            e[i]=m[*ptr]; *ptr +=1;
        } else {
            return r;
        }
    }
    r.val=e.len(); r.err=0;
    return r;
}

/// parse an integer from m of length len, ptr increments if successful
pub fn parse_int(m: &[u8],len: usize,ptr: &mut usize) -> RET {
    let mut r=RET{val:0,err:config::BAD_RECORD};
    if *ptr+len > m.len() { // can't go beyond end of array
        return r;
    }
    r.val=0;
    for _ in 0..len {
        r.val=256*r.val+(m[*ptr] as usize); *ptr +=1;
    }
    r.err=0;
    return r;
}

/// Convert character to integer
fn char2int(inp: u8) -> u8 {
    if inp>='0' as u8 && inp <='9' as u8 {
        return inp-'0' as u8;
    }
    if inp>='A' as u8 && inp <='F' as u8 {
        return inp-('A' as u8) +10;
    }
    if inp>='a' as u8 && inp <='f' as u8 {
        return inp-('a' as u8) +10;
    }
    return 0;
}

/// Decode hex to bytes
// s better have even number of characters!
#[allow(dead_code)]
pub fn decode_hex(x: &mut[u8],s: &str) -> usize {
    let c=s.as_bytes();
    let mut i=0;
    let mut j=0;

    while j<c.len() {
        x[i]=char2int(c[j])*16+char2int(c[j+1]);
        i+=1;
        j+=2;
    }
    return i;
}

/// Decode hex bytes into unsigned number
#[allow(dead_code)]
pub fn decode_hex_num(s: &str) -> usize {
    let mut buf:[u8;16]=[0;16];
    let len=decode_hex(&mut buf,s);
    let mut n=0;
    for i in 0..len {
        n=n*256+buf[i] as usize; 
    }
    return n;
}

/// Print out byte array in hex
pub fn printbinary(array: &[u8]) {
    for i in 0..array.len() {
        print!("{:02X}", array[i])
    }
    print!("")
}

/// Append byte to buffer
pub fn append_byte(buf: &mut [u8],ptr: usize, b: u8, rep:usize) -> usize {
    for i in 0..rep { 
        buf[ptr+i]=b;
    }
    return ptr+rep;
}

/// Append bytes to buffer
pub fn append_bytes(buf: &mut [u8],ptr: usize, b: &[u8]) -> usize {
    for i in 0..b.len() {
        buf[ptr+i]=b[i];
    }
    return ptr+b.len();
}

/// Append integer to buffer
pub fn append_int(buf: &mut [u8],ptr: usize, int: usize, len:usize) -> usize {
    let mut m=int;
    let mut i=len;
    while i>0 {
        i -= 1;
        buf[ptr+i]=(m%256) as u8;
        m /= 256;
    }
    return ptr+len;
}

/// Shift a buffer left - used to empty input buffer as it is processed
pub fn shift_left(buf: &mut [u8],n: usize) -> usize { // return new length
    let mut blen=buf.len();
    if n>=blen {
        return 0;
    }
    blen-=n;
    for i in 0..blen {
        buf[i]=buf[i+n];
    }
    return blen;
}
