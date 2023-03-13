//! Read data from a socket

use std::net::{TcpStream};
use std::io::{Read,Write};

//static mut BYTES_READ: usize = 0;
//static mut BYTES_WRITTEN: usize = 0;

pub fn get_bytes(stream:&mut TcpStream,buf: &mut [u8]) -> bool {
//    unsafe {
//        BYTES_READ += buf.len();
//    }
    match stream.read_exact(buf) {
        Ok(_) => {
            return true;
        }
        Err(_) => {
            return false;
        }
    }
}

pub fn get_int16(stream:&mut TcpStream) -> usize {
    let mut b:[u8;2]=[0;2];
    get_bytes(stream,&mut b[0..2]);
    return 256*(b[0] as usize)+(b[1] as usize);
}

pub fn send_bytes(stream:&mut TcpStream,buf: &[u8]) {
//    unsafe {
//        BYTES_WRITTEN+=buf.len();
//    }
/*
let mlen=(buf[3] as usize)*256+(buf[4] as usize);
let rlen=mlen+5;
print!("rec= ({}) ",mlen);
let mut plen=rlen;
if plen>128 {
    plen=128;
}
for i in 0..plen-1 {
    print!("{},",buf[i]);
}
if plen<rlen {
    print!("....");
}
println!("{}",buf[rlen-1]);

if buf.len()!=rlen {
    println!("OOPS!");
}
*/
    stream.write(buf).unwrap();
//    unsafe {
//        println!("BYTE_READ= {} BYTES_WRITTEN= {}",BYTES_READ,BYTES_WRITTEN);
//    }
}
