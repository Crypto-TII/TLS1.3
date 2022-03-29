mod tls13;
mod config;

use std::net::{TcpStream};
use tls13::connection::SESSION;
use tls13::logger;
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
        },
        Err(_e) => {
            logger::logger(IO_PROTOCOL,"Failed to connect\n",0,None);
        }
    }
}

