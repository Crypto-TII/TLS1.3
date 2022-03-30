mod tls13;
mod config;

use std::fs;
use std::fs::File;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::net::{Shutdown, TcpStream};
use tls13::connection::SESSION;
use tls13::logger;
use tls13::sal;
use tls13::utils;
use config::*;
use std::env;

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
    let htype=sal::hash_type(s.t.cipher_suite);
    let hlen=sal::hash_len(htype);
    for i in 0..hlen {
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
            utils::decode_hex(&mut s.t.psk,myline);
   
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
            s.t.cipher_suite=utils::decode_hex_num(myline);

            line.clear();
            len = reader.read_line(&mut line).unwrap();
            myline=&line[0..len-1];
            s.t.favourite_group=utils::decode_hex_num(myline);

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

fn main() {
    let mut args: Vec<String> = env::args().collect();

    if args.len()>2 || args.len()<1 {
        logger::logger(IO_PROTOCOL,"Command line error\n",0,None);
        return;
    }

    let host:&str;
    let fullhost:&str;
    if args.len()==1 {
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

    if !tls13::sal::init() {
        logger::logger(IO_PROTOCOL,"SAL failed to start\n",0,None);
        return;
    }

    match TcpStream::connect(&fullhost) {
        Ok(stream) => {
            
            logger::logger(IO_PROTOCOL,"Successfully connected to server\n",0,None);
            let mut get:[u8;256]=[0;256];
            let mut resp:[u8;256]=[0;256];
            let gtlen=make_client_message(&mut get,&host);
            let mut session=SESSION::new(stream,&host);

            let mut have_ticket=true;
            let mut ticket_failed=false;
            if !recover_ticket(&mut session,"cookie.txt") {
                have_ticket=false;
            }
            if !session.connect(Some(&mut get[0..gtlen])) {
                if have_ticket {
                    ticket_failed=true;
                    fs::remove_file("cookie.txt");
                    session.sockptr.shutdown(Shutdown::Both);
                    session.sockptr=TcpStream::connect(&fullhost).unwrap();
                    if !session.connect(Some(&mut get[0..gtlen])) {
                        logger::logger(IO_APPLICATION,"TLS Handshake failed\n",0,None);
                        return;
                    } 
                } else {
                    logger::logger(IO_APPLICATION,"TLS Handshake failed\n",0,None);
                    return;
                }
            } 
            let mut rplen=0;
            let rtn=session.recv(&mut resp,&mut rplen);
            logger::logger(IO_APPLICATION,"Receiving application data (truncated HTML) = ",0,Some(&resp[0..rplen]));
            if rtn<0 {
                session.send_client_alert(alert_from_cause(rtn));
            } else {
                session.send_client_alert(CLOSE_NOTIFY);
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
                logger::logger(IO_APPLICATION,"Receiving application data (truncated HTML) = ",0,Some(&resp[0..rplen]));
            }

            store_ticket(&session,"cookie.txt");
            session.t.clear();
            recover_ticket(&mut session,"cookie.txt"); */
        },
        Err(_e) => {
            logger::logger(IO_PROTOCOL,"Failed to connect\n",0,None);
        } 
    } 

 // Read the file line by line using the lines() iterator from std::io::BufRead.
    
 //   for (index, line) in reader.lines().enumerate() {
 //       let line = line.unwrap(); // Ignore errors.
 //       // Show the line and its number.
 //       println!("{}. {}", index + 1, line);
 //   }

}

