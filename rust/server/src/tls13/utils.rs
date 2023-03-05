//! Utility functions

use crate::config;
use crate::tls13::x509;

/// Function return structure
pub struct RET {
    pub val: usize,
    pub err: isize
}

/// base64 decoding
pub fn decode_b64(b: &[u8],w:&mut [u8]) -> usize { // decode from base64 in place
    let mut j=0;
    let mut k=0;
    let len=b.len();
    let mut ch:[u8;4]=[0;4];
    let mut ptr:[u8;3]=[0;3];
    while j<len {
        let mut pads=0;
        for i in 0..4 {
            let mut c=80+b[j]; j+=1;
            if c<=112 {continue;}
            if c>144 && c<171 {
                c-=145;
            }
            if c>176 && c<203 { 
                c-=151;
            }
            if c>127 && c<138 {
                c-=76;
            }
            if c==123 {c=62;}
            if c==127 {c=63;}
            if c==141 {
                pads+=1;
                continue;
            }
            ch[i]=c;
        }
        ptr[0] = (ch[0] << 2) | (ch[1] >> 4);
        ptr[1] = (ch[1] << 4) | (ch[2] >> 2);
        ptr[2] = (ch[2] << 6) | ch[3];
        for i in 0..3 - pads {
            /* don't put in leading zeros */
            w[k] = ptr[i]; k+=1;
        }
    }
    return k;
}

/// create Distinguished name from DER encoding
pub fn make_dn(dn: &mut [u8],der: &[u8]) -> usize{
    let mut n=0;
    dn[n]=b'{'; n+=1;
    let mut ep=x509::find_entity_property(der,&x509::MN,0);
    for i in 0..ep.length {
        dn[n]=der[ep.index+i];
        n+=1;
    }
    dn[n]=b','; n+=1;
    ep=x509::find_entity_property(der,&x509::UN,0);
    for i in 0..ep.length {
        dn[n]=der[ep.index+i];
        n+=1;
    }
    dn[n]=b','; n+=1;
    ep=x509::find_entity_property(der,&x509::ON,0);
    for i in 0..ep.length {
        dn[n]=der[ep.index+i];
        n+=1;
    }
    dn[n]=b','; n+=1;
    ep=x509::find_entity_property(der,&x509::CN,0);
    for i in 0..ep.length {
        dn[n]=der[ep.index+i];
        n+=1;
    }
    dn[n]=b'}'; n+=1;
    return n;
}

 // "Clients offering these values MUST list them as the lowest priority (listed after all other algorithms in SignatureSchemeList)."
 /// Ensure legacy algorithms are at lowest priority
 pub fn check_legacy_priorities(algs: &[u16]) -> bool {
    let n=algs.len();
    let mut foundone=false;
    for i in 0..n {
        if (algs[i]&0xFF00) == 0x0200 { // legacy signature scheme detected
            foundone=true;
        } else {
            if foundone {
                return false; // legacy scheme was not last in list
            }
        }
    }
    return true;
}

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
