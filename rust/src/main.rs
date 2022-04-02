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
    for i in 0..s.t.nnlen {
        write!(&mut fp,"{:02X}",s.t.nonce[i]).unwrap();
    }
    writeln!(&mut fp).unwrap();
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

            line.clear();
            len = reader.read_line(&mut line).unwrap();
            myline=&line[0..len-1];
            s.t.nnlen=utils::decode_hex(&mut s.t.nonce,myline);

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
    println!("    /s show SAL capabilities");
    println!("Example:- client www.bbc.co.uk");
}

fn name_ciphers(cipher_suite: u16) {
    match cipher_suite {
        AES_128_GCM_SHA256 => println!("TLS_AES_128_GCM_SHA256"),
        AES_256_GCM_SHA384 => println!("TLS_AES_256_GCM_SHA384"),   
        CHACHA20_POLY1305_SHA256 => println!("TLS_CHACHA20_POLY1305_SHA256"),  
        _ => println!("Non-standard")
    }
}

fn name_group(group: u16) {
    match group {
        X25519 => println!("X25519"),
        SECP256R1 => println!("SECP256R1"),   
        SECP384R1 => println!("SECP384R1"),   
        _ => println!("Non-standard")
    }
}

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
        _ => println!("Non-standard")        
    }
}

fn remove_ticket() {       
    match fs::remove_file("cookie.txt") {
        Ok(_) => return,
        Err(_e) => return
    }
}

fn main() {
    let mut args: Vec<String> = env::args().collect();

    if args.len()<2 {
        log(IO_PROTOCOL,"Command line error\n",0,None);
        bad_input();
        return;
    }

    if !tls13::sal::init() {
        log(IO_PROTOCOL,"SAL failed to start\n",0,None);
        return;
    }

    if args[1].as_str() == "/r" {
        println!("Ticket removed");
        remove_ticket();
        return;
    }
    if args[1].as_str() == "/s" {
        let mut nt:[u16;20]=[0;20];
        println!("Cryptography by {}",sal::name());
        println!("SAL supported Key Exchange groups");
        let ns=sal::groups(&mut nt);
        for i in 0..ns {
            print!("    ");
            name_group(nt[i]);
            let mut csk: [u8;MAX_SECRET_KEY]=[0;MAX_SECRET_KEY];
            let mut pk: [u8;MAX_PUBLIC_KEY]=[0;MAX_PUBLIC_KEY];
            let mut ss: [u8;MAX_SHARED_SECRET_SIZE]=[0;MAX_SHARED_SECRET_SIZE];
            let sklen=sal::secret_key_size(nt[i]);   // may change on a handshake retry
            let pklen=sal::public_key_size(nt[i]);
            let sslen=sal::shared_secret_size(nt[i]);

            let start = Instant::now();
            let mut iterations = 0;
            let mut dur = 0 as u64;
            while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
                sal::generate_key_pair(nt[i],&mut csk[0..sklen],&mut pk[0..pklen]);
                iterations += 1;
                let elapsed = start.elapsed();
                dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
            }
            let duration = (dur as f64) / (iterations as f64);
            println!("        Key Generation {:0.2} ms", duration);

            let start = Instant::now();
            let mut iterations = 0;
            let mut dur = 0 as u64;
            while dur < (MIN_TIME as u64) * 1000 || iterations < MIN_ITERS {
                sal::generate_shared_secret(nt[i],&csk[0..sklen],&pk[0..pklen],&mut ss[0..sslen]);
                iterations += 1;
                let elapsed = start.elapsed();
                dur = (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64;
            }
            let duration = (dur as f64) / (iterations as f64);
            println!("        Shared Secret {:0.2} ms", duration);
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
    
    if args[1].as_str() == "/p" { // psk label is in args[2]
        println!("PSK mode selected");
        have_psk=true;
    }

    let mut localhost=false;
    if args.len()==1 || have_psk {
        localhost=true;
    }

    let host:&str;
    let fullhost:&str;
    if localhost {
        host="localhost";
        fullhost="localhost:4433";
    } else {
        let hn=args[1].as_str();
        let hlen=hn.len();
        let port: &str = ":443";
        args[1].push_str(port);
        fullhost = &args[1].as_str();
        host=&fullhost[0..hlen];
    }

    match TcpStream::connect(&fullhost) {
        Ok(stream) => {
            
            log(IO_PROTOCOL,"Successfully connected to server\n",0,None);
            let mut get:[u8;256]=[0;256];
            let mut resp:[u8;256]=[0;256];
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
            if !session.connect(Some(&mut get[0..gtlen])) {
                if have_ticket {
                    ticket_failed=true;
                    remove_ticket();
                    session.sockptr.shutdown(Shutdown::Both).unwrap();
                    session.sockptr=TcpStream::connect(&fullhost).unwrap();
                    if !session.connect(Some(&mut get[0..gtlen])) {
                        log(IO_APPLICATION,"TLS Handshake failed\n",0,None);
                        return;
                    } 
                } else {
                    log(IO_APPLICATION,"TLS Handshake failed\n",0,None);
                    return;
                }
            } 
            let mut rplen=0;
            let rtn=session.recv(&mut resp,&mut rplen);
            log(IO_APPLICATION,"Receiving application data (truncated HTML) = ",0,Some(&resp[0..rplen]));
            if rtn<0 {
                session.send_alert(alert_from_cause(rtn));
            } else {
                session.send_alert(CLOSE_NOTIFY);
            }
            if session.t.valid && !ticket_failed {
                store_ticket(&session,"cookie.txt");
            }
            session.clean();
/*
            let r=session.tls_full();
            if r!=TLS_FAILURE {
                session.send(&get[0..gtlen]);
                let mut rplen=0;
                session.recv(&mut resp,&mut rplen);
                log(IO_APPLICATION,"Receiving application data (truncated HTML) = ",0,Some(&resp[0..rplen]));
            }

            store_ticket(&session,"cookie.txt");
            session.t.clear();
            recover_ticket(&mut session,"cookie.txt"); */
        },
        Err(_e) => {
            log(IO_PROTOCOL,"Failed to connect\n",0,None);
        } 
    } 

 // Read the file line by line using the lines() iterator from std::io::BufRead.
    
 //   for (index, line) in reader.lines().enumerate() {
 //       let line = line.unwrap(); // Ignore errors.
 //       // Show the line and its number.
 //       println!("{}. {}", index + 1, line);
 //   }

}
