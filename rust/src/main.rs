mod tls13;
mod config;

use std::fs;
use std::fs::File;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::net::{TcpStream};
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

fn store_ticket(s: &SESSION) {
    let mut fp = File::create("cookie.txt").unwrap(); //expect("Unable to create file for ticket");
    for i in 0..s.hlen {
        write!(&mut fp,"{}",s.hostname[i] as char);
    }
    writeln!(&mut fp);
    for i in 0..s.t.tklen {
        write!(&mut fp,"{:02X}",s.t.tick[i]);
    }
    writeln!(&mut fp);
    for i in 0..s.t.nnlen {
        write!(&mut fp,"{:02X}",s.t.nonce[i]);
    }
    writeln!(&mut fp);
    let htype=sal::hash_type(s.t.cipher_suite);
    let hlen=sal::hash_len(htype);
    for i in 0..hlen {
        write!(&mut fp,"{:02X}",s.t.psk[i]);
    }
    writeln!(&mut fp);
    writeln!(&mut fp,"{:016X}",s.t.age_obfuscator).unwrap();
    writeln!(&mut fp,"{:016X}",s.t.max_early_data);
    writeln!(&mut fp,"{:016X}",s.t.birth);
    writeln!(&mut fp,"{:016X}",s.t.lifetime);
    writeln!(&mut fp,"{:016X}",s.t.cipher_suite);
    writeln!(&mut fp,"{:016X}",s.t.favourite_group);
    writeln!(&mut fp,"{:016X}",s.t.origin);
}

fn recover_ticket(s: &mut SESSION) {
    let file = File::open("cookie.txt").unwrap();
    let mut reader = BufReader::new(file); 
    let mut line = String::new();
    let mut len = reader.read_line(&mut line).unwrap();
    let myline=&line[0..len];
    
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
            let r=session.tls_full();
            if r!=TLS_FAILURE {
                session.send(&get[0..gtlen]);
                let mut rplen=0;
                session.recv(&mut resp,&mut rplen);
                logger::logger(IO_APPLICATION,"Receiving application data (truncated HTML) = ",0,Some(&resp[0..rplen]));
            }

    

            store_ticket(&session);
    let file = File::open("cookie.txt").unwrap();
    let mut reader = BufReader::new(file);

    let mut line = String::new();
    let mut len = reader.read_line(&mut line).unwrap();
    let mut myline=&line[0..len-1];
    println!("{} {}",myline.len(),myline);
    println!("{} ",session.hlen);
    if myline.as_bytes() == &session.hostname[0..session.hlen] {
        println!("They are the same");
    }
    line.clear();
    len = reader.read_line(&mut line).unwrap();
    myline=&line[0..len-1];
    //println!("{}",myline);
    let tklen=utils::decode_hex(&mut session.t.tick,myline);
    for i in 0..session.t.tklen {
        print!("{:02X}",session.t.tick[i]);
    }
    println!("");
    line.clear();
    len = reader.read_line(&mut line).unwrap();
    myline=&line[0..len-1];
    //println!("{}",myline);
    session.t.nnlen=utils::decode_hex(&mut session.t.nonce,myline);
    for i in 0..session.t.nnlen {
        print!("{:02X}",session.t.nonce[i]);
    }
    println!("");
    let htype=sal::hash_type(session.t.cipher_suite);
    let hlen=sal::hash_len(htype);

    line.clear();
    len = reader.read_line(&mut line).unwrap();
    myline=&line[0..len-1];
    //println!("{}",myline);
    utils::decode_hex(&mut session.t.psk,myline);
    for i in 0..hlen {
        print!("{:02X}",session.t.psk[i]);
    }    
    println!("");
    line.clear();
    len = reader.read_line(&mut line).unwrap();
    myline=&line[0..len-1];
    //println!("{}",myline);
    let mut num=utils::decode_hex_num(myline);
    print!("{:X}",num);
    println!("");     
    line.clear();
    len = reader.read_line(&mut line).unwrap();
    myline=&line[0..len-1];
    //println!("{}",myline);
    num=utils::decode_hex_num(myline);
    print!("{:X}",num);
    println!("");
    line.clear();
    len = reader.read_line(&mut line).unwrap();
    myline=&line[0..len-1];
    //println!("{}",myline);
    num=utils::decode_hex_num(myline);
    print!("{:X}",num);
    println!("");
    line.clear();
    len = reader.read_line(&mut line).unwrap();
    myline=&line[0..len-1];
    //println!("{}",myline);
    num=utils::decode_hex_num(myline);
    print!("{:X}",num);
    println!("");
    line.clear();
    len = reader.read_line(&mut line).unwrap();
    myline=&line[0..len-1];
    //println!("{}",myline);
    num=utils::decode_hex_num(myline);
    print!("{:X}",num);
    println!("");
    line.clear();
    len = reader.read_line(&mut line).unwrap();
    myline=&line[0..len-1];
    //println!("{}",myline);
    num=utils::decode_hex_num(myline);
    print!("{:X}",num);
    println!("");
    line.clear();
    len = reader.read_line(&mut line).unwrap();
    myline=&line[0..len-1];
    //println!("{}",myline);
    num=utils::decode_hex_num(myline);
    print!("{:X}",num);
    println!("");
        },
        Err(_e) => {
            logger::logger(IO_PROTOCOL,"Failed to connect\n",0,None);
        }
    }
/*
    let file = File::open("cookie.txt").unwrap();
    let mut reader = BufReader::new(file);

    let mut line = String::new();
    let mut len = reader.read_line(&mut line).unwrap();
    let myline=&line[0..len];
    println!("{} {}",len,myline);
    println!("{} {}",session.hlen,session.hostname);

    let mut hname:[u8;256]=[0;256];
    //let hlen=utils::decode_hex(&mut hname,myline);
    line.clear();
    //len = reader.read_line(&mut line).unwrap();
    //println!("{} {}",len,&line[0..len-1]);
*/
    // Read the file line by line using the lines() iterator from std::io::BufRead.
    
 //   for (index, line) in reader.lines().enumerate() {
 //       let line = line.unwrap(); // Ignore errors.
 //       // Show the line and its number.
 //       println!("{}. {}", index + 1, line);
 //   }

}

