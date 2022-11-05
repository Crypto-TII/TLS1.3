//! TLS1.3 server example program

mod tls13;
mod config;

use std::thread;
use std::net::{TcpListener, TcpStream};
use std::env;

use crate::tls13::logger::log;
use tls13::sal;
use tls13::connection::SESSION;
use config::*;

use std::time::Instant;

const MIN_ITERS: isize = 10;
const MIN_TIME: isize = 1;

/// Print out byte array in hex
pub fn printbinary(array: &[u8]) {
    for i in 0..array.len() {
        print!("{:02X}", array[i])
    }
    println!("")
}

/// Name the cipher suite
fn name_ciphers(cipher_suite: u16) {
    match cipher_suite {
        AES_128_GCM_SHA256 => println!("TLS_AES_128_GCM_SHA256"),
        AES_256_GCM_SHA384 => println!("TLS_AES_256_GCM_SHA384"),   
        CHACHA20_POLY1305_SHA256 => println!("TLS_CHACHA20_POLY1305_SHA256"),  
        _ => println!("Non-standard")
    }
}

/// Name the key exchange group
fn name_group(group: u16) {
    match group {
        X25519 => println!("X25519"),
        SECP256R1 => println!("SECP256R1"),   
        SECP384R1 => println!("SECP384R1"),   
        KYBER768 => println!("KYBER768"),
        SIDH => println!("SIDH"),
        _ => println!("Non-standard")
    }
}

/// Name the signature algorithm
fn name_signature(sigalg: u16) {
    match sigalg {
        ECDSA_SECP256R1_SHA256 => println!("ECDSA_SECP256R1_SHA256"),
        RSA_PSS_RSAE_SHA256 => println!("RSA_PSS_RSAE_SHA256"),
        RSA_PKCS1_SHA256 => println!("RSA_PKCS1_SHA256"),
        ECDSA_SECP384R1_SHA384 => println!("ECDSA_SECP384R1_SHA384"),
        RSA_PSS_RSAE_SHA384 => println!("RSA_PSS_RSAE_SHA384"),
        RSA_PKCS1_SHA384 => println!("RSA_PKCS1_SHA384"),
        RSA_PSS_RSAE_SHA512 => println!("RSA_PSS_RSAE_SHA512"),
        RSA_PKCS1_SHA512 => println!("RSA_PKCS1_SHA512"),
        DILITHIUM3 => println!("DILITHIUM3"),
        _ => println!("Non-standard")        
    }
}

/// Send a short server response
fn make_server_message(get: &mut[u8]) -> usize {
    let mut ptr=0;
    let str1="HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: text/html\r\n\r\nHello, World!".as_bytes();
    for i in 0..str1.len() {
        get[ptr]=str1[i]; ptr+=1;
    }
    return ptr;
}

/// Handle a client connection
fn handle_client(stream: TcpStream,port: u16) {
    let mut mess:[u8;MAX_EARLY_DATA]=[0;MAX_EARLY_DATA];
    let mut post:[u8;256]=[0;256];
    let ptlen=make_server_message(&mut post);
    let mut session=SESSION::new(stream,port);
    println!("Session commenced {}",port);
    let mut msize=0;
    let rtn=session.connect(&mut mess,&mut msize);
    let mut mslen=msize as isize;

    if rtn==TLS_SUCCESS {
        session.send_ticket();
        session.send_ticket();
        session.send_key_update(UPDATE_NOT_REQUESTED);  // UPDATE_REQUESTED can be used here instead

// got to recv here, or we miss key update!

        if mslen>0 {
            log(IO_APPLICATION,"Received client message as early data\n",-1,Some(&mess[0..mslen as usize]));
        } else { // wait for a message from client
            mslen=session.recv(&mut mess);
            if mslen>=0 {
                if mslen>0 {
                    log(IO_APPLICATION,"Received client message\n",-1,Some(&mess[0..mslen as usize]));
                }
            } else { // got alert from client - just exit
                return;
            }
        }

        log(IO_APPLICATION,"Sending Application Response (truncated HTML) = ",0,Some(&post[0..40]));
        session.send(&post[0..ptlen]);
        session.stop();

// ... but still open to receiving stuff .. but what if I need to send an alert in response to bad input?
// if I receive an error alert, just end it. 
// if its a close notify, keep listening until I get a close notify from the other side 
// Each party MUST send a close notify before it stops sending

        loop { // but wait for close-notify response from client - ignore messages
            mslen=session.recv(&mut mess);
            if mslen<0 { // hopefully close notify alert
                break;
            }
        }
    } //else {
        //session.stop();
    //}

}

/// Main program
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len()>1 {
        if args[1].as_str() == "/s" {
            let mut nt:[u16;20]=[0;20];
            println!("Cryptography by {}",sal::name());
            println!("SAL supported Key Exchange groups");
            let ns=sal::groups(&mut nt);
            for i in 0..ns {
                print!("    ");
                name_group(nt[i]);
                let mut csk: [u8;MAX_KEX_SECRET_KEY]=[0;MAX_KEX_SECRET_KEY];
                let mut cpk: [u8;MAX_KEX_PUBLIC_KEY]=[0;MAX_KEX_PUBLIC_KEY];
                let mut spk: [u8;MAX_KEX_CIPHERTEXT]=[0;MAX_KEX_CIPHERTEXT];
                let mut ss: [u8;MAX_SHARED_SECRET_SIZE]=[0;MAX_SHARED_SECRET_SIZE];
                let sklen=sal::secret_key_size(nt[i]);   // may change on a handshake retry
                let cpklen=sal::client_public_key_size(nt[i]);
                let spklen=sal::server_public_key_size(nt[i]);
                let sslen=sal::shared_secret_size(nt[i]);

                sal::generate_key_pair(nt[i],&mut csk[0..sklen],&mut cpk[0..cpklen]);

                let start = Instant::now();
                let mut iterations = 0;
                let mut dur = 0 as u64;
                while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
                    sal::server_shared_secret(nt[i],&cpk[0..cpklen],&mut spk[0..spklen],&mut ss[0..sslen]);
                    iterations += 1;
                    let elapsed = start.elapsed();
                    dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
                }
                let duration = (dur as f64) / (iterations as f64);
                println!("        Server Shared Secret {:0.2} ms", duration);
                println!("        Client Public Key size {} bytes",cpklen);
                println!("        Server Public Key/Encapsulation size {} bytes",spklen);
                
            }
            println!("SAL supported Cipher suites");
            let ns=sal::ciphers(&mut nt);
            for i in 0..ns {
                print!("    ");
                name_ciphers(nt[i]);
            }
            println!("SAL supported TLS Signatures");
            let ns=sal::sigs(&mut nt);
            for i in 0..ns {
                print!("    ");
                name_signature(nt[i]);
            }
            println!("SAL supported Certificate Signatures");
            let ns=sal::sig_certs(&mut nt);
            for i in 0..ns {
                print!("    ");
                name_signature(nt[i]);
            }
            return
        } else {
            return;
        }
    }
    if !tls13::sal::init() {
        log(IO_PROTOCOL,"SAL failed to start",-1,None);
        return;
    }
    let listener = TcpListener::bind("0.0.0.0:4433").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 4433");

    if CRYPTO_SETTING==TYPICAL {
        println!("Configured for typical RSA/ECC TLS client connections");
    }
    if CRYPTO_SETTING==TINY_ECC {
        println!("Configured for Small ECC TLS client connections");
    }
    if CRYPTO_SETTING==POST_QUANTUM {
        println!("Configured for Post Quantum TLS client connections");
    }
    if CRYPTO_SETTING==HYBRID {
        println!("Configured for Hybrid Post Quantum TLS client connections");
    }
    if CERTIFICATE_REQUEST {
        println!("Looking for Client Authentication");
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let port=stream.peer_addr().unwrap().port();
                println!("\nNew connection: {}", port);
                thread::spawn(move|| {
                    // connection succeeded
                    handle_client(stream,port)
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    // close the socket server
    drop(listener);
}
