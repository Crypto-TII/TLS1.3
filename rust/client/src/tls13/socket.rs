//! Read data from a socket

use std::net::{TcpStream};
use std::io::{Read,Write};

//static mut BYTES_READ: usize = 0;
//static mut BYTES_WRITTEN: usize = 0;


/// Read bytes into buffer
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

/// Read in 16-bit number
pub fn get_int16(stream:&mut TcpStream) -> usize {
    let mut b:[u8;2]=[0;2];
    get_bytes(stream,&mut b[0..2]);
    return 256*(b[0] as usize)+(b[1] as usize);
}

pub fn send_bytes(stream:&mut TcpStream,buf: &[u8]) {
//    unsafe {
//        BYTES_WRITTEN += buf.len();
//    }
    stream.write(buf).unwrap();
//    unsafe {
//        println!("BYTE_READ= {} BYTES_WRITTEN= {}",BYTES_READ,BYTES_WRITTEN);
//    }

}

/*
pub fn get_int24(stream:&mut TcpStream) -> usize {
    let mut b:[u8;3]=[0;3];
    get_bytes(stream,&mut b[0..3]);
    return 65536*(b[0] as usize)+256*(b[1] as usize)+(b[2] as usize);
}

pub fn get_byte(stream:&mut TcpStream) -> u8 {
    let mut b:[u8;1]=[0;1];  
    get_bytes(stream,&mut b[0..1]);
    return b[0];
}
*/