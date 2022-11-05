//! TLS1.3 client example program

mod tls13;
mod config;

use std::fs;
use std::fs::File;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::net::{Shutdown, TcpStream};
use tls13::connection::SESSION;
use tls13::logger::log;
use tls13::sal;
use tls13::utils;
use config::*;
use std::env;

use std::time::Instant;

const MIN_ITERS: isize = 10;
const MIN_TIME: isize = 1;

extern crate mcore;

/// create a test message to send to Server
fn make_client_message(get: &mut[u8],host: &str) -> usize {
    let mut ptr=0;
    let str1="GET / HTTP/1.1".as_bytes();
    let str2="Host: ".as_bytes();
    for i in 0..str1.len() {
        get[ptr]=str1[i]; ptr+=1;
    }
    get[ptr]=0x0d; get[ptr+1]=0x0a; ptr+=2;
    for i in 0..str2.len() {
        get[ptr]=str2[i]; ptr+=1;
    }
    
    let hst=host.as_bytes();

    for i in 0..hst.len() {
        get[ptr]=hst[i]; ptr+=1;
    }
    
    get[ptr]=0x0d; get[ptr+1]=0x0a; ptr+=2;
    get[ptr]=0x0d; get[ptr+1]=0x0a; ptr+=2;
    return ptr;
}

/// store ticket in cookie
fn store_ticket(s: &SESSION,fname: &str) {
    let mut fp = File::create(fname).unwrap(); //expect("Unable to create file for ticket");
    for i in 0..s.hlen {
        write!(&mut fp,"{}",s.hostname[i] as char).unwrap();
    }
    writeln!(&mut fp).unwrap();
    for i in 0..s.t.tklen {
        write!(&mut fp,"{:02X}",s.t.tick[i]).unwrap();
    }
    writeln!(&mut fp).unwrap();

//
//    for i in 0..s.t.nnlen {
//        write!(&mut fp,"{:02X}",s.t.nonce[i]).unwrap();
//    }
//    writeln!(&mut fp).unwrap();
//
    for i in 0..s.t.psklen {
        write!(&mut fp,"{:02X}",s.t.psk[i]).unwrap();
    }
    writeln!(&mut fp).unwrap();
    writeln!(&mut fp,"{:016X}",s.t.age_obfuscator).unwrap();
    writeln!(&mut fp,"{:016X}",s.t.max_early_data).unwrap();
    writeln!(&mut fp,"{:016X}",s.t.birth).unwrap();
    writeln!(&mut fp,"{:016X}",s.t.lifetime).unwrap();
    writeln!(&mut fp,"{:016X}",s.t.cipher_suite).unwrap();
    writeln!(&mut fp,"{:016X}",s.t.favourite_group).unwrap();
    writeln!(&mut fp,"{:016X}",s.t.origin).unwrap();
}

/// retrieve ticket from cookie
fn recover_ticket(s: &mut SESSION,fname: &str) -> bool {
    match File::open(fname) {
        Ok(file) => {
            let mut reader = BufReader::new(file); 
            let mut line = String::new();
            let mut len = reader.read_line(&mut line).unwrap();
            let mut myline=&line[0..len-1];
            if myline.as_bytes() != &s.hostname[0..s.hlen] {
                return false; // not a ticket for this website
            }
            line.clear();
            len = reader.read_line(&mut line).unwrap();
            myline=&line[0..len-1];
            s.t.tklen=utils::decode_hex(&mut s.t.tick,myline);
//
//            line.clear();
//            len = reader.read_line(&mut line).unwrap();
//            myline=&line[0..len-1];
//            s.t.nnlen=utils::decode_hex(&mut s.t.nonce,myline);
//
            line.clear();
            len = reader.read_line(&mut line).unwrap();
            myline=&line[0..len-1];
            s.t.psklen=utils::decode_hex(&mut s.t.psk,myline);
   
            line.clear();
            len = reader.read_line(&mut line).unwrap();
            myline=&line[0..len-1];
            s.t.age_obfuscator=utils::decode_hex_num(myline);
    
            line.clear();
            len = reader.read_line(&mut line).unwrap();
            myline=&line[0..len-1];
            s.t.max_early_data=utils::decode_hex_num(myline);

            line.clear();
            len = reader.read_line(&mut line).unwrap();
            myline=&line[0..len-1];
            s.t.birth=utils::decode_hex_num(myline);

            line.clear();
            len = reader.read_line(&mut line).unwrap();
            myline=&line[0..len-1];
            s.t.lifetime=utils::decode_hex_num(myline);

            line.clear();
            len = reader.read_line(&mut line).unwrap();
            myline=&line[0..len-1];
            s.t.cipher_suite=utils::decode_hex_num(myline) as u16;

            line.clear();
            len = reader.read_line(&mut line).unwrap();
            myline=&line[0..len-1];
            s.t.favourite_group=utils::decode_hex_num(myline) as u16;

            line.clear();
            len = reader.read_line(&mut line).unwrap();
            myline=&line[0..len-1];
            s.t.origin=utils::decode_hex_num(myline);
       },
       Err(_e) => {
            return false;
       }
    }
    s.t.valid=true;
    return true;
}

/// Respond to bad input
fn bad_input()
{
    println!("Incorrect Usage");
    println!("client <hostname>, or");
    println!("client <flags>");
    println!("(hostname may be localhost)");
    println!("(port defaults to 443, or 4433 on localhost)");
    println!("Resumption automatically attempted if recent ticket found");
    println!("Valid flags:- ");
    println!("    /p <n> (where <n> is preshared key label shared with localhost)");
    println!("    /r remove stored ticket");
    println!("    /r <hostname> remove stored ticket and connect to hostname");
    println!("    /s show SAL capabilities");
    println!("Example:- client www.bbc.co.uk");
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

/// delete the ticket
fn remove_ticket() {       
    match fs::remove_file("cookie.txt") {
        Ok(_) => return,
        Err(_e) => return
    }
}

/// Main program
fn main() {
    let mut args: Vec<String> = env::args().collect();

    if args.len()<2 {
        log(IO_PROTOCOL,"Command line error\n",-1,None);
        bad_input();
        return;
    }

    if !tls13::sal::init() {
        log(IO_PROTOCOL,"SAL failed to start\n",-1,None);
        return;
    }

    let mut ip=1;
    if args[ip].as_str() == "/r" {
        println!("Ticket removed");
        remove_ticket();
        ip+=1; if ip>=args.len() {
            return;
        }   
    }
    if args[ip].as_str() == "/s" {
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

            let start = Instant::now();
            let mut iterations = 0;
            let mut dur = 0 as u64;
            while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
                sal::generate_key_pair(nt[i],&mut csk[0..sklen],&mut cpk[0..cpklen]);
                iterations += 1;
                let elapsed = start.elapsed();
                dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
            }
            let duration = (dur as f64) / (iterations as f64);
            println!("        Client Key Generation {:0.2} ms", duration);

            sal::server_shared_secret(nt[i],&cpk[0..cpklen],&mut spk[0..spklen],&mut ss[0..sslen]);

            let start = Instant::now();
            let mut iterations = 0;
            let mut dur = 0 as u64;
            while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
                sal::generate_shared_secret(nt[i],&csk[0..sklen],&spk[0..spklen],&mut ss[0..sslen]);
                iterations += 1;
                let elapsed = start.elapsed();
                dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
            }
            let duration = (dur as f64) / (iterations as f64);
            println!("        Client Shared Secret {:0.2} ms", duration);
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
    }

    let mut have_psk=false;
    let psk:[u8;16]=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]; // fake a pre-shared key
    
    if args[ip].as_str() == "/p" { // psk label is in args[2]
        println!("PSK mode selected");
        have_psk=true;
    }

    let mut localhost=false;
    if args[ip].as_str()=="localhost" || have_psk {
        localhost=true;
    }

    let host:&str;
    let fullhost:&str;
    if localhost {
        host="localhost";
        fullhost="localhost:4433";
    } else {
        let hn=args[ip].as_str();
        let hlen=hn.len();

        if let Some(_index)=hn.find(':') { // already has a port
        } else {
            let port: &str = ":443";
            args[ip].push_str(port);
        }
        fullhost = &args[ip].as_str();
        host=&fullhost[0..hlen];
    }

    match TcpStream::connect(&fullhost) {
        Ok(stream) => {
            
            log(IO_PROTOCOL,"Hostname= ",-1,Some(&host.as_bytes()));
            let mut get:[u8;256]=[0;256];
            let mut resp:[u8;40]=[0;40];
            let gtlen=make_client_message(&mut get,&host);
            let mut session=SESSION::new(stream,&host);

            let mut have_ticket=true;
            let mut ticket_failed=false;
            if have_psk {     
                let pl=args[2].as_bytes();  // Insert a special ticket into session 
                for i in 0..pl.len() {
                    session.t.tick[i]=pl[i];
                }
                session.t.tklen=pl.len();
                for i in 0..16 {
                    session.t.psk[i]=psk[i];
                }
                session.t.psklen=16;
                session.t.max_early_data=1024;
                session.t.cipher_suite=AES_128_GCM_SHA256;
                session.t.favourite_group=X25519;
                session.t.origin=EXTERNAL_PSK;
                session.t.valid=true;
                remove_ticket(); // delete any stored ticket - fall into resumption mode
            } else {
                if !recover_ticket(&mut session,"cookie.txt") {
                    have_ticket=false;
                }
            }

// Make connection and send initial data
// If resumption is possible it may go as "early data"
            if !session.connect(Some(&mut get[0..gtlen])) {
                if have_ticket {
                    ticket_failed=true;
                    remove_ticket();
                    session.stop();
                    session.sockptr.shutdown(Shutdown::Both).unwrap();
                    session.sockptr=TcpStream::connect(&fullhost).unwrap();
                    if !session.connect(Some(&mut get[0..gtlen])) {
                        log(IO_APPLICATION,"TLS Handshake failed\n",-1,None);
                        session.stop();
                        session.sockptr.shutdown(Shutdown::Both).unwrap();
                        return;
                    } 
                } else {
                    log(IO_APPLICATION,"TLS Handshake failed\n",-1,None);
                    session.stop();
                    session.sockptr.shutdown(Shutdown::Both).unwrap();
                    return;
                }
            } 
// Get server response, may attach resumption ticket to session
            let mut rplen:isize;
            if !localhost {
                rplen=session.recv(&mut resp);
                if rplen>0 {
                    log(IO_APPLICATION,"Receiving application data (truncated HTML) = ",0,Some(&resp[0..rplen as usize]));
                    session.stop();
                }
            } else {
                loop {
                    rplen=session.recv(&mut resp);
                    if rplen<0 { // Either problem on my side, or I got an alert
                        break;
                    } 
                    if rplen>0 {
                        log(IO_APPLICATION,"Receiving application data (truncated HTML) = ",0,Some(&resp[0..rplen as usize]));
                    }
                }
            }
            if rplen==CLOSURE_ALERT_RECEIVED { // I am exiting voluntarily, so send close notify
                session.stop();
                session.sockptr.shutdown(Shutdown::Both).unwrap();
            }

            if session.t.valid && !ticket_failed {
                store_ticket(&session,"cookie.txt");
            }
        },
        Err(_e) => {
            log(IO_PROTOCOL,"Failed to connect\n",-1,None);
        } 
    } 
}

