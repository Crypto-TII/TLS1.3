
//! Main TLS1.3 protocol 

use std::net::{TcpStream};
use std::io::{Write};
use std::time::{SystemTime, UNIX_EPOCH};
//use std::time::Duration;
//use std::thread;


use zeroize::Zeroize;

use crate::config::*;
use crate::tls13::sal;
use crate::tls13::socket;
use crate::tls13::extensions;
use crate::tls13::certchain;
use crate::tls13::keys;
use crate::tls13::logger;
use crate::tls13::logger::log;
use crate::tls13::utils;
use crate::tls13::utils::RET;

/// Milliseconds since epoch
pub fn millis() -> usize {
    return SystemTime::now().duration_since(UNIX_EPOCH).expect("").as_millis() as usize;    
}

/// TLS1.3 session structure
pub struct SESSION {
    pub port: u16,         // Connection port
    pub status: usize,     // Connection status 
    pub max_record: usize, // max record size I should send
    pub sockptr: TcpStream,   // Pointer to socket 
    pub iolen: usize,           // IO buffer length - input decrypted data
    pub ptr: usize,             // IO buffer pointer - consumed portion
    pub session_id:[u8;33],  // legacy session ID
    pub hostname: [u8;MAX_SERVER_NAME],     // Server name for connection 
    pub hlen: usize,        // hostname length
    pub cipher_suite: u16,      // agreed cipher suite 
    pub favourite_group: u16,   // favourite key exchange group 
    pub k_send: keys::CRYPTO,   // Sending Key 
    pub k_recv: keys::CRYPTO,   // Receiving Key 
    pub hs: [u8;MAX_HASH],      // Handshake secret Secret  
    pub rms: [u8;MAX_HASH],     // Resumption Master Secret         
    pub sts: [u8;MAX_HASH],     // Server Traffic secret             
    pub cts: [u8;MAX_HASH],     // Client Traffic secret                
    pub io: [u8;MAX_IO],        // Main IO buffer for this connection 
    pub tlshash: UNIHASH,       // Transcript hash recorder 
    pub clientid: [u8;MAX_X509_FIELD], // Client identity for this session
    pub cidlen: usize,      // client id length
    ticket: [u8;MAX_TICKET_SIZE], //psk identity (resumption ticket)
    tklen: usize,           // psk identity length
    ticket_obf_age: u32,    // psk obfuscated age
}

/// Do I support this group? Check with SAL..
fn group_support(alg: u16) -> bool {
    let mut kxs:[u16;MAX_SUPPORTED_GROUPS]=[0;MAX_SUPPORTED_GROUPS];
    let nkxs=sal::groups(&mut kxs);
    for i in 0..nkxs {
        if alg == kxs[i] {
            return true;
        }
    }
    return false;
}

/// Do I support this cipher-suite ?
fn cipher_support(alg: u16) -> bool {
    let mut cps:[u16;MAX_CIPHER_SUITES]=[0;MAX_CIPHER_SUITES];
    let ncps=sal::ciphers(&mut cps);
    for i in 0..ncps {
        if alg == cps[i] {
            return true;
        }
    }
    return false;
}

// IO buffer
// xxxxxxxxxxxxxxxxxxxxxxxxxxxyyyyyyyyyyyyyyyyyyyyyyyyyyy
// -------------ptr---------->----------iolen----------->
//
// when ptr becomes equal to iolen, pull in another record (and maybe decrypt it)

impl SESSION {
    pub fn new(stream: TcpStream,pt: u16) -> SESSION  {
        let this=SESSION {
            port: pt,
            status:DISCONNECTED,
            max_record: MAX_RECORD,
            sockptr: stream,
            iolen: 0,
            ptr: 0,
            session_id: [0;33],
            hostname: [0; MAX_SERVER_NAME],
            hlen: 0,
            cipher_suite: 0,  //AES_128_GCM_SHA256,
            favourite_group: 0,
            k_send: keys::CRYPTO::new(), 
            k_recv: keys::CRYPTO::new(),
            hs: [0;MAX_HASH],
            rms: [0;MAX_HASH],
            sts: [0;MAX_HASH],
            cts: [0;MAX_HASH],   
            io: [0;MAX_IO],
            tlshash:{UNIHASH{state:[0;MAX_HASH_STATE],htype:0}},
            clientid:[0;MAX_X509_FIELD],
            cidlen: 0,
            ticket: [0;MAX_TICKET_SIZE],
            tklen: 0,
            ticket_obf_age: 0,
        }; 
        return this;
    }
 
 /// Get an integer of length len bytes from io stream
    fn parse_int_pull(&mut self,len:usize) -> RET {
        let mut r=utils::parse_int(&self.io[0..self.iolen],len,&mut self.ptr);
        while r.err !=0 { // not enough bytes in IO - pull in another record
            let rtn=self.get_record();  // gets more stuff and increments iolen
            if rtn!=HSHAKE as isize as isize {
                r.err=rtn;
                if rtn==ALERT as isize {
                    r.val=self.io[1] as usize;
                }
                break;
            }
            r=utils::parse_int(&self.io[0..self.iolen],len,&mut self.ptr);
        }
        return r;
    }  
    
/// pull bytes from io into array
    fn parse_bytes_pull(&mut self,e: &mut[u8]) -> RET {
        let mut r=utils::parse_bytes(e,&self.io[0..self.iolen],&mut self.ptr);
        while r.err !=0 { // not enough bytes in IO - pull in another record
            let rtn=self.get_record();  // gets more stuff and increments iolen
            if rtn!=HSHAKE as isize  {
                r.err=rtn;
                if rtn==ALERT as isize {
                    r.val=self.io[1] as usize;    // 0 is alert level, 1 is alert description
                }
                break;
            }
            r=utils::parse_bytes(e,&self.io[0..self.iolen],&mut self.ptr);
        }
        return r;
    }

/// Pull bytes into input buffer
    fn parse_pull(&mut self,n: usize) -> RET { // get n bytes into self.io
        let mut r=RET{val:0,err:0};
        while self.ptr+n>self.iolen {
            let rtn=self.get_record();
            if rtn!=HSHAKE  as isize  {
                r.err=rtn;
                if rtn==ALERT as isize {
                    r.val=self.io[1] as usize;    // 0 is alert level, 1 is alert description
                }
                break;
            }
        }
        self.ptr += n;
        return r;
    }

/// Initialise transcript hash
    fn init_transcript_hash(&mut self) {
        let htype=sal::hash_type(self.cipher_suite);
        sal::hash_init(htype,&mut self.tlshash);
    }

/// Add octad to transcript hash 
    fn running_hash(&mut self,o: &[u8]) {
        sal::hash_process_array(&mut self.tlshash,o);
    }

/// Output transcript hash 
    fn transcript_hash(&self,o: &mut [u8]) {
        sal::hash_output(&self.tlshash,o); 
    }

/// Rewind iobuffer
    fn rewind(&mut self) {
        self.iolen=utils::shift_left(&mut self.io[0..self.iolen],self.ptr); // rewind
        self.ptr=0;        
    }

/// Add I/O buffer self.io to transcript hash 
    fn running_hash_io(&mut self) {
        sal::hash_process_array(&mut self.tlshash,&self.io[0..self.ptr]);
        self.rewind();
    }

/// Special case handling for first clientHello after retry request
    fn running_synthetic_hash_io(&mut self) {
        let htype=self.tlshash.htype; 
        let hlen=sal::hash_len(htype);
        let mut rhash=UNIHASH{state:[0;MAX_HASH_STATE],htype:0};
        let mut h:[u8;MAX_HASH]=[0;MAX_HASH];
        sal::hash_init(htype,&mut rhash);
// RFC 8446 - "special synthetic message"
        sal::hash_process_array(&mut rhash,&self.io[0..self.ptr]);
        sal::hash_output(&rhash,&mut h);
        let t:[u8;4]=[MESSAGE_HASH,0,0,hlen as u8];
        sal::hash_process_array(&mut self.tlshash,&t);
        self.running_hash(&h[0..hlen]);
        self.iolen=utils::shift_left(&mut self.io[0..self.iolen],self.ptr); // rewind
        self.ptr=0;
    }

// Note these are flipped from the client side
/// Create a sending crypto context
    pub fn create_send_crypto_context(&mut self) {
        self.k_send.init(self.cipher_suite,&self.sts);
    }

/// Create a receiving crypto context
    pub fn create_recv_crypto_context(&mut self) {
        self.k_recv.init(self.cipher_suite,&self.cts);
    }
    
/// Get Client and Server Handshake secrets for encrypting rest of handshake, from Shared secret SS and early secret ES
    pub fn derive_handshake_secrets(&mut self,ss: &[u8],es: &[u8],h: &[u8]) {
        let dr="derived";
        let ch="c hs traffic";
        let sh="s hs traffic";
        let mut ds:[u8;MAX_HASH]=[0;MAX_HASH];
        let mut emh:[u8;MAX_HASH]=[0;MAX_HASH];
        let htype=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(htype);
        sal::hash_null(htype,&mut emh[0..hlen]);
        keys::hkdf_expand_label(htype,&mut ds[0..hlen],es,dr.as_bytes(),Some(&emh[0..hlen]));
        sal::hkdf_extract(htype,&mut self.hs[0..hlen],Some(&ds[0..hlen]),ss);
        keys::hkdf_expand_label(htype,&mut self.cts[0..hlen],&self.hs[0..hlen],ch.as_bytes(),Some(h));
        keys::hkdf_expand_label(htype,&mut self.sts[0..hlen],&self.hs[0..hlen],sh.as_bytes(),Some(h));
    }

/// Extract Client and Server Application Traffic secrets from Transcript Hashes, Handshake secret 
    pub fn derive_application_secrets(&mut self,sfh: &[u8],cfh: &[u8],ems: Option<&mut [u8]>) {
        let dr="derived";
        let ch="c ap traffic";
        let sh="s ap traffic";
        let rh="res master";
        let mut ds:[u8;MAX_HASH]=[0;MAX_HASH];
        let mut ms:[u8;MAX_HASH]=[0;MAX_HASH];
        let zk:[u8;MAX_HASH]=[0;MAX_HASH];
        let mut emh:[u8;MAX_HASH]=[0;MAX_HASH];
        let htype=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(htype);
        sal::hash_null(htype,&mut emh);
        keys::hkdf_expand_label(htype,&mut ds[0..hlen],&self.hs[0..hlen],dr.as_bytes(),Some(&emh[0..hlen]));
        sal::hkdf_extract(htype,&mut ms[0..hlen],Some(&ds[0..hlen]),&zk[0..hlen]);
        keys::hkdf_expand_label(htype,&mut self.cts[0..hlen],&ms[0..hlen],ch.as_bytes(),Some(sfh));
        keys::hkdf_expand_label(htype,&mut self.sts[0..hlen],&ms[0..hlen],sh.as_bytes(),Some(sfh));

        if let Some(sems) = ems {
            let eh="exp master";
            keys::hkdf_expand_label(htype,&mut sems[0..hlen],&ms[0..hlen],eh.as_bytes(),Some(sfh));
        }
        keys::hkdf_expand_label(htype,&mut self.rms[0..hlen],&ms[0..hlen],rh.as_bytes(),Some(cfh));
    }

/// Send a message - could/should be broken down into multiple records.
/// Message comes in two halves - cm and (optional) ext.
/// Message is constructed in IO buffer, and finally written to the socket.
/// note that IO buffer is overwritten
    pub fn send_message(&mut self,rectype: u8,version: usize,cm: &[u8],ext: Option<&[u8]>) {
        if self.status==DISCONNECTED {
            self.clean_io();
            return;
        }
        let mut ptr=0;
        let rbytes=(sal::random_byte()%16) as usize;
        if !self.k_send.active { // no encryption
            ptr=utils::append_byte(&mut self.io,ptr,rectype,1);
            ptr=utils::append_int(&mut self.io,ptr,version,2);
            if let Some(sext) = ext {
                ptr=utils::append_int(&mut self.io,ptr,cm.len()+sext.len(),2);
                ptr=utils::append_bytes(&mut self.io,ptr,cm);
                ptr=utils::append_bytes(&mut self.io,ptr,sext);
            } else {
                ptr=utils::append_int(&mut self.io,ptr,cm.len(),2);
                ptr=utils::append_bytes(&mut self.io,ptr,cm);
            }   
        } else { // encrypted, and sent disguised as application record
            let mut tag:[u8;MAX_TAG_SIZE]=[0;MAX_TAG_SIZE];
            ptr=utils::append_byte(&mut self.io,ptr,APPLICATION,1);
            ptr=utils::append_int(&mut self.io,ptr,TLS1_2,2);
            let taglen=self.k_send.taglen;
            let mut reclen=cm.len()+taglen+rbytes+1; // 16 for the TAG, 1 for the record type, + some random padding
            if let Some(sext) = ext {
                reclen += sext.len();
                ptr=utils::append_int(&mut self.io,ptr,reclen,2);
                ptr=utils::append_bytes(&mut self.io,ptr,cm);
                ptr=utils::append_bytes(&mut self.io,ptr,sext);
            } else {
                ptr=utils::append_int(&mut self.io,ptr,reclen,2);
                ptr=utils::append_bytes(&mut self.io,ptr,cm);
            }
            ptr=utils::append_byte(&mut self.io,ptr,rectype,1); // append and encrypt actual record type
            ptr=utils::append_byte(&mut self.io,ptr,0,rbytes);
            let mut rh:[u8;5]=[0;5];  // record header - may form part of transcript hash!
            for i in 0..5 {
                rh[i]=self.io[i];
            }
            sal::aead_encrypt(&self.k_send,&rh,&mut self.io[5..5+reclen-taglen],&mut tag[0..taglen]);
            self.k_send.increment_crypto_context(); //increment iv
            ptr=utils::append_bytes(&mut self.io,ptr,&tag[0..taglen]);
        }

// trying to create TCP fragmentation
//self.sockptr.set_nodelay(true);
//        if ptr>20 {
//            self.sockptr.write(&self.io[0..10]).unwrap();
//let ten_millis = Duration::from_millis(1000);


//thread::sleep(ten_millis);
//            self.sockptr.write(&self.io[10..ptr]).unwrap();
//        } else {
            self.sockptr.write(&self.io[0..ptr]).unwrap();
//        }
        self.clean_io();
    }   

/// Check for a bad response. If not happy with what received - send alert and close. If alert received from Server, log it and close.
    fn bad_response(&mut self,r: &RET) -> bool {
        logger::log_server_response(r);
        if r.err !=0 {
            log(IO_PROTOCOL,"Handshake Failed\n",0,None);
        }
        if r.err<0 {
            self.send_alert(alert_from_cause(r.err));
            return true;
        }
        if r.err == ALERT as isize {
            //if r.val==CLOSE_NOTIFY as usize{
		    //    self.send_alert(CLOSE_NOTIFY);  // I'm closing down, and so are you
            //}
            logger::log_alert(r.val as u8);
            return true;
        }
        if r.err != 0 {
            return true;
        }
        return false;
    }

/// Send an alert to the Client
    pub fn send_alert(&mut self,kind: u8) {
        let pt: [u8;2]=[0x02,kind];
        self.clean_io();
        self.send_message(ALERT,TLS1_2,&pt[0..2],None);
        log(IO_PROTOCOL,"Alert sent to Client - ",0,None);
        logger::log_alert(kind);
    }

/// Send Change Cipher Suite - helps get past middleboxes (?)
    pub fn send_cccs(&mut self) {
        let cccs:[u8;6]=[0x14,0x03,0x03,0x00,0x01,0x01];
        self.sockptr.write(&cccs).unwrap();
    }

/// Send Server Certificate chain
    fn send_server_certificate(&mut self,certchain: &[u8]) {
        let mut pt:[u8;8]=[0;8];
        let mut ptr=0;
        let len=certchain.len();

        ptr=utils::append_byte(&mut pt,ptr,CERTIFICATE,1);
        ptr=utils::append_int(&mut pt,ptr,4+len,3);
        ptr=utils::append_byte(&mut pt,ptr,0,1);
        ptr=utils::append_int(&mut pt,ptr,len,3);

        self.running_hash(&pt[0..ptr]);
        self.running_hash(certchain);

// Certificate chain might be too long - break it up into record fragments

        let pieces=(ptr+len+self.max_record-1)/self.max_record;
        let size=(ptr+len)/pieces;
        self.send_message(HSHAKE,TLS1_2,&pt[0..ptr],Some(&certchain[0..size-ptr]));
        let mut left=len+ptr-size;

        if left>0 {
            let mut start=size-ptr;
            while left>size {
                self.send_message(HSHAKE,TLS1_2,&certchain[start..start+size],None);
                start+=size;
                left-=size;
            }
            self.send_message(HSHAKE,TLS1_2,&certchain[start..len],None);
        }
    }

/// Send Encrypted Extensions
    fn send_encrypted_extensions(&mut self,ext: &[u8]) {
        let mut pt:[u8;6]=[0;6];
        let mut ptr=0;

        ptr=utils::append_byte(&mut pt,ptr,ENCRYPTED_EXTENSIONS,1);
        ptr=utils::append_int(&mut pt,ptr,ext.len()+2,3);
        ptr=utils::append_int(&mut pt,ptr,ext.len(),2);
        
        self.running_hash(&pt[0..ptr]);
        self.running_hash(ext);

        self.send_message(HSHAKE,TLS1_2,&pt[0..ptr],Some(ext));
    }

/// Send Server Certificate Verify 
    fn send_server_cert_verify(&mut self, sigalg: u16,scvsig: &[u8]) { 
        let mut pt:[u8;8]=[0;8];
        let mut ptr=0;
        ptr=utils::append_byte(&mut pt,ptr,CERT_VERIFY,1); // indicates handshake message "certificate verify"
        ptr=utils::append_int(&mut pt,ptr,4+scvsig.len(),3); // .. and its length
        ptr=utils::append_int(&mut pt,ptr,sigalg as usize,2);
        ptr=utils::append_int(&mut pt,ptr,scvsig.len(),2);
        self.running_hash(&pt[0..ptr]);
        self.running_hash(scvsig);
        self.send_message(HSHAKE,TLS1_2,&pt[0..ptr],Some(scvsig));
    }

/// Send Server Certificate Request 
    fn send_certificate_request(&mut self) { 
        let mut sig_algs:[u16;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS]; 
        let mut pt:[u8;11+2*MAX_SUPPORTED_SIGS]=[0;11+2*MAX_SUPPORTED_SIGS];

        let nsa=sal::sigs(&mut sig_algs);  // get supported sigs
        let len=13+2*nsa;

        let mut ptr=0;
        ptr=utils::append_byte(&mut pt,ptr,CERT_REQUEST,1); // indicates handshake message "certificate request"
        ptr=utils::append_int(&mut pt,ptr,len-4,3); // .. and its length
        ptr=utils::append_int(&mut pt,ptr,0,1);   // .. Request Context
        ptr=utils::append_int(&mut pt,ptr,len-7,2);
        ptr=utils::append_int(&mut pt,ptr,SIG_ALGS,2); // extension
        ptr=utils::append_int(&mut pt,ptr,len-11,2);
        ptr=utils::append_int(&mut pt,ptr,2*nsa,2);
        for i in 0..nsa {
            ptr=utils::append_int(&mut pt,ptr,sig_algs[i] as usize,2);
        }
        self.running_hash(&pt[0..ptr]);
        self.send_message(HSHAKE,TLS1_2,&pt[0..ptr],None);
    }

/// Send final server handshake finish
    fn send_server_finish(&mut self,shf: &[u8]) {
        let mut pt:[u8;4]=[0;4];
        let mut ptr=0;
        ptr=utils::append_byte(&mut pt,ptr,FINISHED,1); // indicates handshake message "server finished"
        ptr=utils::append_int(&mut pt,ptr,shf.len(),3); // .. and its length
        self.running_hash(&pt[0..ptr]);
        self.running_hash(shf);
        self.send_message(HSHAKE,TLS1_2,&pt[0..ptr],Some(shf));
    }

/// Send Key update demand
    pub fn send_key_update(&mut self,kur: usize) {
        let mut up:[u8;5]=[0;5];
        let mut ptr=0;
        ptr=utils::append_byte(&mut up,ptr,KEY_UPDATE,1);  // message type
        ptr=utils::append_int(&mut up,ptr,1,3);      // message length
        ptr=utils::append_int(&mut up,ptr,kur,1);
        self.clean_io();
        self.send_message(HSHAKE,TLS1_2,&up[0..ptr],None);
        let htype=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(htype);
        self.k_send.update(&mut self.sts[0..hlen]);
        log(IO_PROTOCOL,"KEY UPDATE REQUESTED\n",0,None);
    }

/// Send resumption ticket
    pub fn send_ticket(&mut self) {
        let mut tick:[u8;MAX_TICKET_SIZE]=[0;MAX_TICKET_SIZE];
        let mut nonce:[u8;32]=[0;32];
        for i in 0..32 {
            nonce[i]=sal::random_byte();
        }
        let mut iv:[u8;12]=[0;12];
        for i in 0..12 {
            iv[i]=sal::random_byte();
        }
        let mut tag:[u8;16]=[0;16];
        let mut psk:[u8;MAX_HASH]=[0;MAX_HASH];
        let rs="resumption";
        let htype=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(htype);
        keys::hkdf_expand_label(htype,&mut psk[0..hlen],&self.rms[0..hlen],rs.as_bytes(),Some(&nonce));
  
        let ticket_age_add = sal::random_word();
// gather state
        let mut state:[u8;MAX_TICKET_SIZE]=[0;MAX_TICKET_SIZE];
        let mut sptr=0;

// put 12 bytes of iv in here
        sptr=utils::append_bytes(&mut state,sptr,&mut iv);
        sptr=utils::append_int(&mut state,sptr,millis(),4);
        sptr=utils::append_int(&mut state,sptr,ticket_age_add as usize,4);
        sptr=utils::append_int(&mut state,sptr,self.cipher_suite as usize,2);
        sptr=utils::append_int(&mut state,sptr,self.favourite_group as usize,2);
        sptr=utils::append_byte(&mut state,sptr,hlen as u8,1);
        sptr=utils::append_bytes(&mut state,sptr,&mut psk[0..hlen]);
        sptr=utils::append_int(&mut state,sptr,self.cidlen as usize,2);
        sptr=utils::append_bytes(&mut state,sptr,&self.clientid[0..self.cidlen]);
// encrypt state
        let mut context=keys::CRYPTO::new();
        context.special_init(&iv);
        sal::aead_encrypt(&context,&iv,&mut state[12..sptr],&mut tag);  // iv | state | tag

// encrypt from 12..sptr+12 
        let mut ptr=0;

// construct ticket message
        let len=sptr+69;
        ptr=utils::append_byte(&mut tick,ptr,TICKET,1);  // message type
        ptr=utils::append_int(&mut tick,ptr,len,3);      // message length
        ptr=utils::append_int(&mut tick,ptr,TICKET_LIFETIME as usize,4);
        ptr=utils::append_int(&mut tick,ptr,ticket_age_add as usize,4);
        ptr=utils::append_byte(&mut tick,ptr,32,1);
        ptr=utils::append_bytes(&mut tick,ptr,&nonce[0..32]);
        ptr=utils::append_int(&mut tick,ptr,sptr+16,2);           // length of state+tag
        ptr=utils::append_bytes(&mut tick,ptr,&state[0..sptr]);
        ptr=utils::append_bytes(&mut tick,ptr,&tag);
 // ticket extensions
        ptr=utils::append_int(&mut tick,ptr,8,2);
        ptr=utils::append_int(&mut tick,ptr,EARLY_DATA as usize,2);
        ptr=utils::append_int(&mut tick,ptr,4,2);
        ptr=utils::append_int(&mut tick,ptr,MAX_EARLY_DATA as usize,4);

        self.send_message(HSHAKE,TLS1_2,&tick[0..ptr],None);
    }

/// Receive Client Certificate Verifier
    fn get_client_cert_verify(&mut self,scvsig: &mut [u8],siglen: &mut usize,sigalg: &mut u16) -> RET {
        let mut r=self.parse_int_pull(1); // get message type
        if r.err!=0 {return r;}
        let nb=r.val as u8;
        if nb != CERT_VERIFY {
            r.err=WRONG_MESSAGE;
            return r;
        }

        let mut r=self.parse_int_pull(3); let mut left=r.val; if r.err!=0 {return r;}

        r=self.parse_int_pull(2); *sigalg=r.val as u16; if r.err!=0 {return r;}

        let mut sig_algs:[u16;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS];
        let nsa=sal::sigs(&mut sig_algs);
        let mut offered=false;
        for i in 0..nsa {
            if *sigalg==sig_algs[i] {
                offered=true;
            }
        }
        if !offered {
            r.err=CERT_VERIFY_FAIL;
            return r;
        }

        r=self.parse_int_pull(2); let len=r.val; if r.err!=0 {return r;}
        r=self.parse_bytes_pull(&mut scvsig[0..len]); if r.err!=0 {return r;}
        left-=4+len;
        if left!=0 {
            r.err=BAD_MESSAGE;
            return r;
        }
        *siglen=len;
        self.running_hash_io();
        r.val=CERT_VERIFY as usize;
        return r;
    }

/// Get client certificate chain, and check its validity. Need to get client full Identity
    pub fn get_check_client_certificatechain(&mut self,cpk:&mut [u8],cpklen: &mut usize) -> RET {
        //let mut ptr=0;
        let mut r=self.parse_int_pull(1); // get message type
        if r.err!=0 {return r;}
        let nb=r.val as u8;
        if nb != CERTIFICATE {
            r.err=WRONG_MESSAGE;
            return r;
        }
        let mut r=self.parse_int_pull(3); let len=r.val; if r.err!=0 {return r;}         // message length   
        log(IO_DEBUG,"Certificate Chain Length= ",len as isize,None);
        r=self.parse_int_pull(1); let nb=r.val; if r.err!=0 {return r;} 
        if nb!=0x00 {
            r.err=MISSING_REQUEST_CONTEXT;// expecting 0x00 Request context
            return r;
        }
        r=self.parse_int_pull(3); let tlen=r.val; if r.err!=0 {return r;}   // get length of certificate chain
	    if tlen==0 {
		    r.err=EMPTY_CERT_CHAIN;
            self.running_hash_io();
		    return r;
	    }
	    if tlen+4!=len {
		    r.err=BAD_CERT_CHAIN;
            self.running_hash_io();
		    return r;
	    }
        let start=self.ptr;
        r=self.parse_pull(tlen); if r.err!=0 {return r;} // get pointer to certificate chain, and pull it all into self.io
// Update Transcript hash
        r.err=certchain::check_certchain(&self.io[start..start+tlen],None,cpk,cpklen,&mut self.clientid,&mut self.cidlen); 
        self.running_hash_io();
        r.val=CERTIFICATE as usize;
        return r;
    }

/// Get handshake finish verifier data
    fn get_client_finished(&mut self,hfin: &mut [u8],hflen: &mut usize) -> RET {
        //let mut ptr=0;
        let mut r=self.parse_int_pull(1); // get message type
        if r.err!=0 {return r;}
        let nb=r.val as u8;
        if nb != FINISHED {
            r.err=WRONG_MESSAGE;
            return r;
        }
        r=self.parse_int_pull(3); let len=r.val; if r.err!=0 {return r;}
        r=self.parse_bytes_pull(&mut hfin[0..len]); if r.err!=0 {return r;}
        *hflen=len;
        self.running_hash_io();
        //sal::hash_process_array(&mut self.tlshash,&self.io[0..ptr]);
        //self.iolen=utils::shift_left(&mut self.io[0..self.iolen],ptr);
        r.val=FINISHED as usize;
        return r;
    }

/// Get End of Early data indication
    fn get_end_of_early_data(&mut self) -> RET {
        let mut r=self.parse_int_pull(1); if r.err!=0 {return r;} // get message type
        let nb=r.val as u8;
        if nb != END_OF_EARLY_DATA {
            r.err=WRONG_MESSAGE;
            return r;
        }
        r=self.parse_int_pull(3); let left=r.val;  if r.err!=0 || left!=0 {return r;}  // get message length
        self.running_hash_io();
        r.val=END_OF_EARLY_DATA as usize;
        return r;
    }

// Protocol messages can be fragmented, and arrive as multiple records. 
// Record contents are appended to the input buffer. 
// Messages are read from the input buffer, and on reaching the end of the buffer, 
// new records are pulled in to complete a message. 
// Most records must be decrypted before being appended to the message buffer.

/// Receive a single record. Could be fragment of a full message. Could be encrypted.
/// Returns +ve type of record, or negative error.
// should I check version? RFC - "MUST be ignored for all purposes"
    pub fn get_record(&mut self) -> isize {
        let mut rh:[u8;5]=[0;5];
        let mut tag:[u8;MAX_TAG_SIZE]=[0;MAX_TAG_SIZE];
        let pos=self.iolen;
        if !socket::get_bytes(&mut self.sockptr,&mut rh[0..3]) {
            return TIMED_OUT as isize;
        }

        if rh[0]==ALERT { // scrub iobuffer, and just leave alert code
            let left=socket::get_int16(&mut self.sockptr);
            if left!=2 {
                return BAD_RECORD;
            }
            socket::get_bytes(&mut self.sockptr,&mut self.io[0..left]); self.iolen=left;
            return ALERT as isize;
        }
        if rh[0]==CHANGE_CIPHER { // read it, and ignore it
            let mut sccs:[u8;10]=[0;10];
            let left=socket::get_int16(&mut self.sockptr);
            if left!=1 {
                return BAD_RECORD;
            }
            socket::get_bytes(&mut self.sockptr,&mut sccs[0..left]);
            if self.status!=HANDSHAKING {
                return WRONG_MESSAGE;
            }
            socket::get_bytes(&mut self.sockptr,&mut rh[0..3]);
        }
        if rh[0]!=HSHAKE && rh[0]!=APPLICATION { // rh[0]=0x80 means SSLv2 connection attempted - reject it
            return NOT_TLS1_3;
        }
        let left=socket::get_int16(&mut self.sockptr);
        if left>MAX_CIPHER_FRAG {
            return MAX_EXCEEDED;
        }
        utils::append_int(&mut rh,3,left,2);
        if left+pos>self.io.len() { // this commonly happens with big records of application data from server
            return MEM_OVERFLOW;    // record is too big - memory overflow
        }
        if !self.k_recv.is_active() { // not encrypted
            if left>MAX_PLAIN_FRAG {
                return MAX_EXCEEDED;
            }
            if left==0 {
                return WRONG_MESSAGE;
            }
            socket::get_bytes(&mut self.sockptr,&mut self.io[pos..pos+left]); 
            self.iolen+=left; // read in record body
            return HSHAKE as isize;
        }

// OK, its encrypted, so aead decrypt it, check tag
        let taglen=self.k_recv.taglen;
        let mut rlen=left-taglen;

        if rlen>MAX_PLAIN_FRAG+1 {
            return MAX_EXCEEDED;
        }

        socket::get_bytes(&mut self.sockptr,&mut self.io[pos..pos+rlen]); // read in record body
        self.iolen+=rlen;
        socket::get_bytes(&mut self.sockptr,&mut tag[0..taglen]);
        let success=sal::aead_decrypt(&self.k_recv,&rh,&mut self.io[pos..pos+rlen],&tag[0..taglen]);
        if !success {
            return AUTHENTICATION_FAILURE;
        }
        self.k_recv.increment_crypto_context();
// get record ending - encodes real (disguised) record type. Could be an Alert.        
        let mut lb=self.io[self.iolen-1];
        self.iolen -= 1; rlen -= 1;// remove it
        while lb==0 && self.iolen>0 {
            lb=self.io[self.iolen-1];
            self.iolen -= 1; rlen -= 1;// remove it
        }
        if (lb == HSHAKE || lb == ALERT) && rlen==0 {
            return WRONG_MESSAGE; // RFC section 5.4
        }
        if lb == HSHAKE {
            return HSHAKE as isize;
        }
        if lb == APPLICATION {
            return APPLICATION as isize;
        }
        if lb==ALERT { // Alert record received, delete anything in IO prior to alert, and just leave 2-byte alert
            self.iolen=utils::shift_left(&mut self.io[0..self.iolen],pos); // rewind
            return ALERT as isize;
        }
        return APPLICATION as isize;
    }

    /// Get client hello. Output encrypted extensions, client public key, client signature algorithms.
    /// Put together Server Hello response. Also generate extensions that are to be encrypted
    fn process_client_hello(&mut self,sh: &mut [u8],shlen: &mut usize,encext: &mut [u8],enclen: &mut usize,ss: &mut [u8],sig_algs: &mut [u16],nsa: &mut usize,early_indication: &mut bool,is_retry: bool) -> RET {
        let mut host:[u8;MAX_SERVER_NAME]=[0;MAX_SERVER_NAME];
        let mut alpn:[u8;32]=[0;32];
        let mut rn: [u8;32]=[0;32];
        let mut tick:[u8;MAX_TICKET_SIZE]=[0;MAX_TICKET_SIZE];
        let nccs:usize;
        let mut ccs:[u16;MAX_CIPHER_SUITES]=[0;MAX_CIPHER_SUITES];
        let mut ncg:usize=0;
        let mut cg:[u16;MAX_SUPPORTED_GROUPS]=[0;MAX_SUPPORTED_GROUPS];
        let mut alg:u16=0;
        let mut cpklen=0;
        let mut cpk:[u8;MAX_KEX_PUBLIC_KEY]=[0;MAX_KEX_PUBLIC_KEY];
        let mut nsac:usize;
        let mut sig_algs_cert:[u16;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS];
        let tls_version=TLS1_3; // only
        let mut hrr: [u8; HRR.len()/2]=[0;HRR.len()/2];
        utils::decode_hex(&mut hrr,&HRR);

        self.ptr=0;  
        self.iolen=0;

        let mut r=self.parse_int_pull(1); if r.err!=0 {return r;}

        if r.val!=CLIENT_HELLO as usize { // should be Client Hello
            r.err=BAD_HELLO;
            return r;
        }

        r=self.parse_int_pull(3); let mut left=r.val; if r.err!=0 {return r;} // If not enough, pull in another fragment
        r=self.parse_int_pull(2); let svr=r.val; if r.err!=0 {return r;}

        left-=2;                // whats left in message
        if svr!=TLS1_2 { 
            r.err=NOT_TLS1_3;  // don't ask
            return r;
        }

        r= self.parse_bytes_pull(&mut rn); if r.err!=0 {return r;}   // 32 random bytes
        left-=32;

        r=self.parse_int_pull(1); let cilen=r.val; if r.err!=0 {return r;}
        if cilen!=32 && cilen!=0 { // could be 0?
            r.err=BAD_HELLO;
            return r;
        }
        self.session_id[0]=cilen as u8;
        left-=1;

        if cilen==32 {
            let mut legacy_id:[u8;32]=[0;32];
            r=self.parse_bytes_pull(&mut legacy_id); if r.err!=0 {return r;}
            left-=cilen;  
            for i in 0..cilen {
                self.session_id[i+1]=legacy_id[i];
            }
        }
        r=self.parse_int_pull(2); nccs=r.val/2; if r.err!=0 {return r;}
        for i in 0..nccs {
            r=self.parse_int_pull(2); ccs[i]=r.val as u16; if r.err!=0 {return r;}
        }
        left-=2+2*nccs;
        r=self.parse_int_pull(2); if r.err!=0 {return r;}
        left-=2;
        if r.val!=0x0100 {
            r.err=BAD_HELLO;
            return r;
        }

        r=self.parse_int_pull(2); let extlen=r.val; if r.err!=0 {return r;}
        left-=2;  
        if left!=extlen { // Check space left is size of extensions
            r.err=BAD_HELLO;
            return r;
        }

        let mut resume=false;
        let mut agreed=false;
        let mut mfl_mode=0;
        let mut sni_ack=false;
        let mut alplen=0;
        *early_indication=false;
        while left>0 {
            if resume {
                log(IO_DEBUG,"Preshared Key must be last extension",0,None);
                r.err=BAD_MESSAGE;
                return r;
            }
            r=self.parse_int_pull(2); let ext=r.val; if r.err!=0 {return r;} // get extension type
//println!("Ext={:#06x} ",ext);
            r=self.parse_int_pull(2); let extlen=r.val; if r.err!=0 {return r;}  // length of this extension
            if extlen+2>left {r.err=BAD_MESSAGE;return r;} 
            left-=4+extlen;
            match ext {
                SERVER_NAME => {
                    r=self.parse_int_pull(2); let len=r.val;
                    r=self.parse_int_pull(1); let etype=r.val;
                    if etype!=0 || len+2!=extlen {
                        r.err=BAD_MESSAGE;
                        return r;
                    }
                    r=self.parse_int_pull(2);
                    self.parse_bytes_pull(&mut host[0..r.val]);
                    self.hlen=r.val;
                    for i in 0..self.hlen {
                        self.hostname[i]=host[i];
                    }
                    sni_ack=true;
                }
                SUPPORTED_GROUPS => {
                    r=self.parse_int_pull(2); ncg=r.val/2; if r.err!=0 {return r;}
                    for i in 0..ncg {
                        r=self.parse_int_pull(2); if r.err!=0 {return r;}
                        cg[i]=r.val as u16;
                    }
                },
                KEY_SHARE => {
                    r=self.parse_int_pull(2); let len=r.val; if r.err!=0 {return r;}
                    if len+2!=extlen {
                        r.err=BAD_MESSAGE;
                        return r;
                    }
                    let mut remain=len;
                    while remain>0 {
                        r=self.parse_int_pull(2); alg=r.val as u16; if r.err!=0 {return r;}
                        r=self.parse_int_pull(2); cpklen=r.val; if r.err!=0 {return r;}
                        r=self.parse_bytes_pull(&mut cpk[0..cpklen]); if r.err!=0 {return r;}
                        remain-=4+cpklen;
                        if group_support(alg) {
                            self.favourite_group=alg;
                            agreed=true;
                            break;
                        }
                    }
                    r=self.parse_pull(remain); if r.err!=0 {return r;}  // drain the rest
                },
                APP_PROTOCOL => {
                    r=self.parse_int_pull(2); let len=r.val; if r.err!=0 {return r;}
                    if len+2!=extlen {
                        r.err=BAD_MESSAGE;
                        return r;
                    }
                    let protocol=APPLICATION_PROTOCOL;  // Server expects this protocol
                    let server_alpn=protocol.as_bytes();
                    let mut remain=len;
                    let mut found=false;
                    while remain>0 {
                        r=self.parse_int_pull(1); alplen=r.val; if r.err!=0 {return r;}
                        let alpn_s=&mut alpn[0..alplen];
                        r=self.parse_bytes_pull(alpn_s); if r.err!=0 {return r;}  // get first entry
                        remain-=1+alplen; 
                        if server_alpn==alpn_s {found=true;}
                    }
                    if !found {
                        r.err=BAD_PROTOCOL;
                        return r;
                    }
                },
                PSK_MODE => {
                    r=self.parse_int_pull(1); let len=r.val; if r.err!=0 {return r;}
                    if len!=1 {
                        r.err=BAD_MESSAGE;
                        return r;
                    }
                    r=self.parse_int_pull(1); let pskmode=r.val; if r.err!=0 {return r;}
                    if pskmode!=PSKWECDHE {  // only mode acceptable!
                        r.err=BAD_MESSAGE;
                    }
                },
                TLS_VER => {
                    r=self.parse_int_pull(1); let len=r.val/2; if r.err!=0 {return r;}
                    r.err=BAD_MESSAGE;
                    for _ in 0..len {
                        r=self.parse_int_pull(2); let tls=r.val; if r.err!=0 {return r;}
                        if tls==TLS1_3 {
                            r.err=0;
                        }
                    }
                },
                MAX_FRAG_LENGTH => {
                    r=self.parse_int_pull(1); mfl_mode=r.val; self.max_record=1<<(8+mfl_mode); if r.err!=0 {return r;}
                },
                RECORD_SIZE_LIMIT => {
                    r=self.parse_int_pull(2); self.max_record=r.val; if r.err!=0 {return r;}
                },
                PADDING => {
                    r=self.parse_pull(extlen); if r.err!=0 {return r;}
                },
                SIG_ALGS => {
                    r=self.parse_int_pull(2); *nsa=r.val/2; if r.err!=0 {return r;}
                    for i in 0..*nsa {
                        r=self.parse_int_pull(2); if r.err!=0 {return r;}
                        sig_algs[i]=r.val as u16;
                    }                    
                },
                SIG_ALGS_CERT => {
                    r=self.parse_int_pull(2); nsac=r.val/2; if r.err!=0 {return r;}
                    for i in 0..nsac {
                        r=self.parse_int_pull(2); if r.err!=0 {return r;}
                        sig_algs_cert[i]=r.val as u16;
                    }                     
                },
                EARLY_DATA => {
                    if extlen!=0 {
                        r.err=UNRECOGNIZED_EXT;
                    }
                    *early_indication=true;
                }
                PRESHARED_KEY => {  // extlen=tlen1+tlen2+4
                    r=self.parse_int_pull(2); let tlen1=r.val; if r.err!=0 {return r;}
                    r=self.parse_int_pull(2); if r.err!=0 {return r;}
                    self.tklen=r.val;
                    r=self.parse_bytes_pull(&mut tick[0..self.tklen]); if r.err!=0 {return r;}
                    for i in 0..self.tklen {
                        self.ticket[i]=tick[i];
                    }
                    r=self.parse_int_pull(4); self.ticket_obf_age=r.val as u32; if r.err!=0 {return r;}
                    let remain=tlen1-self.tklen-2-4;
                    r=self.parse_pull(remain); if r.err!=0 {return r;}  // only take first PSK - drain the rest
                    //extra=extlen-tlen1-2;
                    resume=true;
                }
                _ => {
                    r=self.parse_pull(extlen); if r.err!=0 {return r;} // just ignore
                    log(IO_DEBUG,"Unrecognized Extension = ",ext as isize,None);
                }
            }
            if r.err!=0 {return r;}
        }
        let mut retry=false;

        if !resume { // check for agreement on cipher suite and group - might need to ask for a handshake retry
            let mut scs:[u16;MAX_CIPHER_SUITES]=[0;MAX_CIPHER_SUITES]; // choose a cipher suite
            let nscs=sal::ciphers(&mut scs);
            let mut chosen=false;
            for i in 0..nccs { // start with their favourite
                for j in 0..nscs {
                    if ccs[i]==scs[j] {
                        chosen=true;
                        self.cipher_suite=scs[j];
                        break;
                    }
                }
                if chosen {break;}
            }
            if !chosen { // no shared cipher suite
                r.err=BAD_HELLO;
                return r;
            }
// did we agree a group?
            if !agreed { // but if one of mine is also one of theirs, will try a HRR
                if ncg>0 {
                    for i in 0..ncg {
                        if group_support(cg[i]) { // I do this!
                            alg=cg[i];
                            retry=true;
                            agreed=true;
                            break;
                        }
                    }
                }
            }
            if !agreed { // still no overlap
                r.err=BAD_HANDSHAKE;
                return r;
            }

        } else {
            for i in 0..nccs { // check clients list of favourite suites
                if cipher_support(ccs[i]) { // find the first one I support - this should be the one I issued ticket for
                    self.cipher_suite=ccs[i];
                    break;
                }
            }
            if self.cipher_suite==0 {
                log(IO_DEBUG,"Cannot find any matching cipher suite\n",0,None);
                r.err=BAD_MESSAGE;
                return r;
            }
            //self.cipher_suite=ccs[0];
        }

        log(IO_DEBUG,"Client Hello = ",0,Some(&self.io[0..self.ptr]));
        if !is_retry { // need to know cipher suite before this can be initialised
            self.init_transcript_hash();
        }
        logger::log_cipher_suite(self.cipher_suite);
        let mut ext:[u8;MAX_EXTENSIONS]=[0;MAX_EXTENSIONS];
        sal::random_bytes(32,&mut rn);
        let mut extlen=0;
        if retry {  // can't calculate a shared key as server does not support suggested group
            for i in 0..32 {
                rn[i]=hrr[i];
            }
            extlen=extensions::add_key_no_share(&mut ext,extlen,alg);
            extlen=extensions::add_version(&mut ext,extlen,tls_version);
            self.running_synthetic_hash_io();
        } else {
            let mut spk:[u8;MAX_KEX_CIPHERTEXT]=[0;MAX_KEX_CIPHERTEXT];
            let nonzero=sal::server_shared_secret(self.favourite_group,&cpk[0..cpklen],&mut spk,ss);
            if !nonzero {
                r.err=BAD_HELLO;
                return r;
            }
            let spklen=sal::server_public_key_size(self.favourite_group);
            logger::log_key_exchange(self.favourite_group);
            log(IO_DEBUG,"Server Public Key= ",0,Some(&spk[0..spklen]));
            extlen=extensions::add_key_share(&mut ext,extlen,self.favourite_group,&spk[0..spklen]);
            extlen=extensions::add_version(&mut ext,extlen,tls_version);
            if resume {
                extlen=extensions::add_presharedkey(&mut ext,extlen,0);  // select first (and only) psk
            }
            self.running_hash_io();
        }
        //self.iolen=utils::shift_left(&mut self.io[0..self.iolen],ptr); // rewind io buffer - but beware if it was a resumption there may be binders in there
// now construct server hello (or HRR) + extensions
        let mut ptr=0;
        ptr=utils::append_byte(sh,ptr,SERVER_HELLO,1);
        ptr=utils::append_int(sh,ptr,72+extlen,3);
        ptr=utils::append_int(sh,ptr,TLS1_2,2);
        ptr=utils::append_bytes(sh,ptr,&rn[0..32]);
        if self.session_id[0]==0 {
            ptr=utils::append_byte(sh,ptr,0,1);
        } else {
            ptr=utils::append_bytes(sh,ptr,&self.session_id);
        }
        ptr=utils::append_int(sh,ptr,self.cipher_suite as usize,2);
        ptr=utils::append_int(sh,ptr,0,1); // no compression
        ptr=utils::append_int(sh,ptr,extlen,2);
        ptr=utils::append_bytes(sh,ptr,&ext[0..extlen]);
        *shlen=ptr;


// while we are here construct server extensions to be encrypted
        extlen=0;
        if mfl_mode>0 {
            extlen=extensions::add_mfl(encext,extlen,mfl_mode);
        }
        //extlen=extensions::add_rsl(encext,extlen,MAX_RECORD);   //oops chrome does not like this!
        if sni_ack {
            extlen=extensions::add_server_name(encext,extlen);
        }
        if alplen>0 {
            extlen=extensions::add_alpn(encext,extlen,&mut alpn[0..alplen]);
        }
        if *early_indication {
            extlen=extensions::add_early_data(encext,extlen);
        }
        *enclen=extlen;

        if retry { // try again..
            r.val=HANDSHAKE_RETRY;
            return r;
        }
        if resume { // go for a resumption
            r.val=TRY_RESUMPTION;
        }
        return r; 
    }


/// Process resumption ticket and recover pre-shared key
// But is it a resumption ticket or a PSK label?
    fn process_ticket(&mut self,psk: &mut [u8],psklen: &mut usize) -> RET {
        log(IO_DEBUG,"ticket= ",0,Some(&self.ticket[0..self.tklen]));
        let mut iv:[u8;12]=[0;12];
        let mut tag:[u8;16]=[0;16];
        let mut r:RET=RET{val:0,err:0};

        if self.tklen<=32 { //.. assume its a label, not a ticket
            let ticklen=self.tklen;
            let tick=&self.ticket[0..ticklen];
            if ticklen==2 && (tick[0]==52 && tick[1]==50) { // "42" this is a POC test - should be a database lookup...
                *psklen=16;
                for i in 0..16 {
                    psk[i]=(i+1) as u8;
                }
                if self.cipher_suite != AES_128_GCM_SHA256 {
                    r.err= BAD_TICKET;
                    return r;
                }
                r.val = EXTERNAL_PSK;
                return r;
            }
            r.err= BAD_TICKET;
            return r;
        }

        for i in 0..12 {
            iv[i]=self.ticket[i];
        }
        for i in 0..16 {
            tag[i]=self.ticket[self.tklen-16+i];
        }
        let mut state=&mut self.ticket[12..self.tklen-16]; // extract prior crypto state

        let mut context=keys::CRYPTO::new();
        context.special_init(&iv);

        if !sal::aead_decrypt(&context,&iv,&mut state,&tag) {
            r.err=AUTHENTICATION_FAILURE;
            return r;
        }
        log(IO_DEBUG,"Resumption state received= ",0,Some(&state));

// Now need to decrypt ticket to find psk 
// First check the ticket age
        let mut ptr=0;
        r=utils::parse_int(&state,4,&mut ptr); let birth=r.val; if r.err!=0 {return r;}
        r=utils::parse_int(&state,4,&mut ptr); let age_add=r.val as u32; if r.err!=0 {return r;}

        let obf_age=self.ticket_obf_age;

        if obf_age<age_add {
            r.err=BAD_TICKET;
            return r;
        }
        let age=obf_age-age_add;
        if age>TICKET_LIFETIME*1000 || (millis()-birth) as u32 > TICKET_LIFETIME*1000 {
            log(IO_PROTOCOL,"Ticket is out of date",0,None);
            r.err=BAD_TICKET;
            return r;
        }

        r=utils::parse_int(&state,2,&mut ptr); let tc=r.val as u16; if r.err!=0 {return r;}
        r=utils::parse_int(&state,2,&mut ptr); let tg=r.val as u16; if r.err!=0 {return r;}
        if tc != self.cipher_suite || tg!=self.favourite_group {
            log(IO_DEBUG,"Ticket Crypto Mismatch\n",0,None);
            r.err=BAD_TICKET;
            return r;
        }
        r=utils::parse_int(&state,1,&mut ptr); *psklen=r.val; if r.err!=0 {return r;}
        //let mut psk:[u8;MAX_HASH]=[0;MAX_HASH];
        r=utils::parse_bytes(&mut psk[0..*psklen],&state,&mut ptr); if r.err!=0 {return r;}
        log(IO_DEBUG,"PSK= ",0,Some(&psk[0..*psklen]));
        r=utils::parse_int(&state,2,&mut ptr); self.cidlen=r.val; if r.err!=0 {return r;}
        r=utils::parse_bytes(&mut self.clientid[0..self.cidlen],&state,&mut ptr); 
        r.val=FULL_HANDSHAKE;  // return PSK origin
        return r;
    }

/// Process Binders 
    fn process_binders(&mut self,external_psk: bool,psk: &[u8],es: &mut [u8]) -> RET {
        let hash_type=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(hash_type);
        let mut hh: [u8;MAX_HASH]=[0;MAX_HASH]; let hh_s=&mut hh[0..hlen];
        //self.running_hash_io(); 
        self.transcript_hash(hh_s);
        log(IO_DEBUG,"Hash of Truncated client Hello",0,Some(hh_s));

        let mut bk:[u8;MAX_HASH]=[0;MAX_HASH]; let bk_s=&mut bk[0..hlen];
        if external_psk {
            keys::derive_early_secrets(hash_type,Some(psk),es,Some(bk_s),None);
        } else {
            keys::derive_early_secrets(hash_type,Some(psk),es,None,Some(bk_s));
        }
        log(IO_DEBUG,"Binder Key= ",0,Some(bk_s)); 

        let mut bnd:[u8;MAX_HASH]=[0;MAX_HASH]; let bnd_s=&mut bnd[0..hlen];
        keys::derive_verifier_data(hash_type,bnd_s,bk_s,hh_s); 

        log(IO_DEBUG,"Binder= ",0,Some(bnd_s)); // this is correct

// now receive Binder, that is the rest of the client Hello
        let mut rbnd:[u8;MAX_HASH]=[0;MAX_HASH]; let rbnd_s=&mut rbnd[0..hlen];
        
        let mut r=self.parse_int_pull(2); let tlen=r.val; if r.err!=0 {return r;}
        r=self.parse_int_pull(1); let bnlen=r.val; if r.err!=0 {return r;}

        if bnlen+1 != tlen {
            r.err=BAD_MESSAGE;
            return r;
        }
        r=self.parse_bytes_pull(rbnd_s); if r.err!=0 {return r;}

        log(IO_DEBUG,"Final part (binders) of Client Hello = ",0,Some(&self.io[0..self.ptr]));

        if rbnd_s!=bnd_s { // binders do not match
            r.err=AUTHENTICATION_FAILURE;
            return r;
        }
        self.running_hash_io(); // hashes in remainder of client Hello
        self.transcript_hash(hh_s);
        log(IO_DEBUG,"Hash of Completed client Hello",0,Some(hh_s));

        let mut cets:[u8;MAX_HASH]=[0;MAX_HASH]; let cets_s=&mut cets[0..hlen];
        keys::derive_later_secrets(hash_type,es,hh_s,Some(cets_s),None);   // Get Client Later Traffic Secret from transcript hash and ES
        log(IO_DEBUG,"Client Early Traffic Secret= ",0,Some(cets_s)); 
        self.k_recv.init(self.cipher_suite,cets_s);  // ready for any early data

        return r;
    }

// TLS1.3
/// Connect with a client, and recover early data if any
    pub fn connect(&mut self,early: &mut [u8],edlen: &mut usize) -> usize {
        let mut sh:[u8;MAX_HELLO]=[0;MAX_HELLO];
        let mut ext:[u8;MAX_EXTENSIONS]=[0;MAX_EXTENSIONS];
        let mut sig_algs:[u16;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS];
        let mut ss:[u8;MAX_SHARED_SECRET_SIZE]=[0;MAX_SHARED_SECRET_SIZE];
        let mut ccs_sent=false;
        let mut early_indication=false;
        let mut shlen=0;
        let mut enclen=0;
        let mut nsa=0;
        self.status=HANDSHAKING;
        let mut rtn=self.process_client_hello(&mut sh,&mut shlen,&mut ext,&mut enclen,&mut ss,&mut sig_algs,&mut nsa,&mut early_indication,false);
        if self.bad_response(&rtn) {
            self.clean();
            return TLS_FAILURE;
        }

//
//
//   <---------------------------------------------------------- client Hello received
//
//  Server Hello + extensions prepared in sh, encrpted extensions in ext

        let hash_type=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(hash_type);
        let mut es: [u8;MAX_HASH]=[0;MAX_HASH]; let es_s=&mut es[0..hlen];
        let mut hh: [u8;MAX_HASH]=[0;MAX_HASH]; let hh_s=&mut hh[0..hlen];
        let mut th: [u8;MAX_HASH]=[0;MAX_HASH]; let th_s=&mut th[0..hlen];
        let mut fh: [u8;MAX_HASH]=[0;MAX_HASH]; let fh_s=&mut fh[0..hlen];
        let mut shf: [u8;MAX_HASH]=[0;MAX_HASH]; let shf_s=&mut shf[0..hlen];
        let mut delayed_alert=0;
        let mut resume=false;
        if rtn.val==TRY_RESUMPTION {
            resume=true;
            log(IO_PROTOCOL,"Attempting Resumption Handshake on port ",self.port as isize,None);
            let mut psk:[u8;MAX_HASH]=[0;MAX_HASH];
            let mut psklen=0;
            let mut r=self.process_ticket(&mut psk,&mut psklen);
            if self.bad_response(&r) {
                self.clean();
                return TLS_FAILURE;
            }
            if self.cidlen>0 {
                log(IO_PROTOCOL,"Client Identity is ",-1,Some(&self.clientid[0..self.cidlen]));
            }
            let mut external_psk=false;
            if r.val==EXTERNAL_PSK {
                external_psk=true;
            }
            r=self.process_binders(external_psk,&psk[0..psklen],es_s);
            if self.bad_response(&r) {
                self.clean();
                return TLS_FAILURE;
            }

// Early application data is probably waiting for me in TCP/IP input queue
// It needs to be decrypted using current recv key. So must not update recv key
// until after taking in early data from client
// I will know its OK to accept this data when there is an End-of-Early handshake message received
// But its too early for that yet

            self.send_message(HSHAKE,TLS1_2,&sh[0..shlen],None); // send server hello
            self.send_cccs();
//
//
//   server Hello sent ----------------------------------------------------------> 
//
            self.running_hash(&sh[0..shlen]);         // Hashing Server Hello
            self.transcript_hash(hh_s);     // HH = hash of clientHello+serverHello

            let sslen=sal::shared_secret_size(self.favourite_group);
            let ss_s=&ss[0..sslen];
            self.derive_handshake_secrets(ss_s,es_s,hh_s); 

            self.create_send_crypto_context();

            log(IO_DEBUG,"Shared Secret= ",0,Some(ss_s));
            log(IO_DEBUG,"Handshake Secret= ",0,Some(&self.hs[0..hlen]));
            log(IO_DEBUG,"Server handshake traffic secret= ",0,Some(&self.sts[0..hlen]));

            self.send_encrypted_extensions(&ext[0..enclen]);

//
//   Encrypted extensions sent ----------------------------------------------------------> 
//

// create server verify data
// .... and send it to Server
            self.transcript_hash(th_s);
            log(IO_DEBUG,"Server is sending server Finished\n",0,None);
            keys::derive_verifier_data(hash_type,shf_s,&self.sts[0..hlen],th_s);
            self.send_server_finish(shf_s);                    
            self.transcript_hash(hh_s);

//
//   server Finish sent ----------------------------------------------------------------> 
//
// Now accept early data and wait for End-Of-Early Data H/S message
            if early_indication {
                *edlen=0;
                loop {
                    //self.iolen=0;
                    let kind=self.get_record();  // get first fragment up to iolen to determine type
                    if kind<0 {
                        return TLS_FAILURE;   // its an error
                    }
                    if kind==TIMED_OUT as isize {
                        log(IO_PROTOCOL,"TIME_OUT\n",0,None);
                        return TLS_FAILURE;
                    }
                    if kind==HSHAKE as isize { // its a handshake message - should be end-of-early data
                        let r=self.get_end_of_early_data();
                        if self.bad_response(&r) {
                            self.clean();
                            return TLS_FAILURE;
                        }
                        log(IO_PROTOCOL,"Early Data received\n",0,None);
                        break;
                    }
                    if kind==APPLICATION as isize { // receive some application data
                        self.ptr=self.iolen;   // grab entire record
                        if *edlen+self.ptr>MAX_EARLY_DATA {
                            return TLS_FAILURE;
                        }
                        for i in 0..self.ptr {
                            early[*edlen+i]=self.io[i];
                        }
                        *edlen+=self.ptr;
                        self.rewind();
                        continue;
                    }
                    if kind==ALERT as isize {
                        log(IO_PROTOCOL,"*** Alert received - ",0,None);
                        logger::log_alert(self.io[1]);
                        return TLS_FAILURE;
                    }
                }
            }
            self.transcript_hash(th_s);
            self.create_recv_crypto_context();  // now update handshake keys
        } else {

            log(IO_PROTOCOL,"Attempting Full Handshake on port ",self.port as isize,None);

            if rtn.val==HANDSHAKE_RETRY { // try one more time
                //self.running_synthetic_hash_io();            // contains synthetic hash of client Hello plus extensions
                self.running_hash(&sh[0..shlen]);
                self.transcript_hash(hh_s);                                            //  *********CH+SH********  

                self.send_message(HSHAKE,TLS1_2,&sh[0..shlen],None);
                log(IO_DEBUG,"Hello Retry Request sent\n",0,None);
                self.send_cccs();
                ccs_sent=true;

                shlen=0;
                enclen=0;
                nsa=0;

//
//   <---------------------------------------------------------- receive updated client Hello
//

                let rtn=self.process_client_hello(&mut sh,&mut shlen,&mut ext,&mut enclen,&mut ss,&mut sig_algs,&mut nsa,&mut early_indication,true);
                if self.bad_response(&rtn) {
                    self.clean();
                    return TLS_FAILURE;
                }
                if rtn.val==HANDSHAKE_RETRY {
                    self.send_alert(UNEXPECTED_MESSAGE);
                    log(IO_DEBUG,"Attempted second retry request",0,None);
                    self.clean();
                    return TLS_FAILURE;
                }
                //self.running_hash_io(); // contains client Hello plus extensions
            }
            //self.running_hash_io(); // contains client Hello plus extensions
            self.running_hash(&sh[0..shlen]);
            self.transcript_hash(hh_s);                                   
            //log(IO_DEBUG,"Client Hello = ",0,Some(&self.io[0..self.iolen]));
            log(IO_DEBUG,"Client Hello processed\n",0,None);
            log(IO_DEBUG,"Host= ",-1,Some(&self.hostname[0..self.hlen]));
            let sslen=sal::shared_secret_size(self.favourite_group);
            let ss_s=&mut ss[0..sslen];
            log(IO_DEBUG,"Shared secret= ",0,Some(ss_s));
            log(IO_DEBUG,"Server Hello= ",0,Some(&sh[0..shlen]));

            keys::derive_early_secrets(hash_type,None,es_s,None,None);
            log(IO_DEBUG,"Early secret= ",0,Some(es_s));

            self.send_message(HSHAKE,TLS1_2,&sh[0..shlen],None);
            if !ccs_sent {
                self.send_cccs();
            }

//
//   server Hello sent ----------------------------------------------------------> 
//

    // Extract Handshake secret, Client and Server Handshake Traffic secrets, Client and Server Handshake keys and IVs from Transcript Hash and Shared secret
            self.derive_handshake_secrets(ss_s,es_s,hh_s);

            self.create_send_crypto_context();
            self.create_recv_crypto_context();
            log(IO_DEBUG,"Handshake secret= ",0,Some(&self.hs[0..hlen]));
            log(IO_DEBUG,"Client Handshake Traffic secret= ",0,Some(&self.cts[0..hlen]));
            log(IO_DEBUG,"Server Handshake Traffic secret= ",0,Some(&self.sts[0..hlen]));

    // now send encrypted extensions

            self.send_encrypted_extensions(&ext[0..enclen]);

            if CERTIFICATE_REQUEST {  // request a client certificate?
                log(IO_DEBUG,"Server is sending certificate request\n",0,None);
                self.send_certificate_request();
//
//   Server Certificate request ----------------------------------------------------------> 
//
            }

            let mut server_key:[u8;MAX_SIG_SECRET_KEY]=[0;MAX_SIG_SECRET_KEY];
            let mut server_certchain:[u8;MAX_SERVER_CHAIN_SIZE]=[0;MAX_SERVER_CHAIN_SIZE];   // assume max chain length of 2
            let mut scvsig:[u8;MAX_SIGNATURE_SIZE]=[0;MAX_SIGNATURE_SIZE];
            let mut sclen=0;
            let mut sklen=0;
            let kind=certchain::get_server_credentials(&sig_algs[0..nsa],&mut server_key,&mut sklen,&mut server_certchain,&mut sclen);
            if kind==0 { // No, Client cannot verify this signature
                self.send_alert(BAD_CERTIFICATE);
                log(IO_PROTOCOL,"Handshake failed - client would be unable to verify signature\n",0,None);
                self.clean();
                return TLS_FAILURE;
            }

            log(IO_PROTOCOL,"Server is authenticating\n",0,None);
            logger::log_sig_alg(kind);
            let sc_s=&server_certchain[0..sclen];
            let sk_s=&server_key[0..sklen];
            self.send_server_certificate(sc_s);

    //
    //
    //  {Server Certificate} ---------------------------------------------------->
    //
    //
            log(IO_DEBUG,"Server is sending certificate verifier\n",0,None);
            self.transcript_hash(th_s);
            sclen=keys::create_server_cert_verifier(kind,th_s,sk_s,&mut scvsig);
            self.send_server_cert_verify(kind,&scvsig[0..sclen]);                           
            self.transcript_hash(th_s);
    //
    //
    //  {Certificate Verify} ---------------------------------------------------->
    //
    //
    // create server verify data
    // .... and send it to Server
            log(IO_DEBUG,"Server is sending server Finished\n",0,None);
            keys::derive_verifier_data(hash_type,shf_s,&self.sts[0..hlen],th_s);
            self.send_server_finish(shf_s);             
            self.transcript_hash(hh_s);
            log(IO_DEBUG,"Transcript Hash (CH+SH+EE+CT+SF) YYY = ",0,Some(hh_s));   
    //
    //
    //  {Server Finished} ---------------------------------------------------->
    //
    //
            log(IO_DEBUG,"Server Verify Data= ",0,Some(shf_s)); 
            self.clean_io();
            if CERTIFICATE_REQUEST { // Server now expects to get client certificate chain
    // Server now receives certificate chain and verifier from Client. Need to parse these out, check CA signature on the cert
    // (maybe its self-signed), extract public key from cert, and use this public key to check client's signature 
    // on the "verifier". Note Certificate signature might use old methods, but client will use PSS padding for its signature (or ECC).
                let mut cpk: [u8; MAX_SIG_PUBLIC_KEY]=[0;MAX_SIG_PUBLIC_KEY];
                let mut ccvsig:[u8;MAX_SIGNATURE_SIZE]=[0;MAX_SIGNATURE_SIZE];
                let mut cpklen=0;
                rtn=self.get_check_client_certificatechain(&mut cpk,&mut cpklen);            // get full name
    //
    //
    //  <---------------------------------------------------------- {Client Certificate}
    //
    //
                if rtn.err==EMPTY_CERT_CHAIN { // no certificate received, so nothing to verify, complain later
                    delayed_alert=rtn.err;
                    self.transcript_hash(th_s); 
                } else {
                    if self.bad_response(&rtn) {
                        self.clean();
                        return TLS_FAILURE;
                    }
                
                    log(IO_DEBUG,"Received Client Certificate\n",0,None); 
                    let cpk_s=&cpk[0..cpklen];
                    self.transcript_hash(fh_s);                                            //TH
                    log(IO_DEBUG,"Certificate Chain is valid\n",0,None);
                    log(IO_DEBUG,"Transcript Hash (CH+SH+EE+CT) = ",0,Some(fh_s));         //TH

                    let mut siglen=0;
                    let mut sigalg:u16=0;
                    rtn=self.get_client_cert_verify(&mut ccvsig,&mut siglen,&mut sigalg);
    //
    //
    //  <---------------------------------------------------- {Certificate Verify}
    //
    //
                    if self.bad_response(&rtn) {
                        self.clean();
                        return TLS_FAILURE;
                    }
                    let ccvsig_s=&mut ccvsig[0..siglen];
                    self.transcript_hash(th_s);                                                //FH
                    log(IO_DEBUG,"Transcript Hash (CH+SH+EE+SCT+SCV) = ",0,Some(th_s));        //FH
                    log(IO_DEBUG,"Client Transcript Signature = ",0,Some(ccvsig_s));
                    logger::log_sig_alg(sigalg);
                    if !keys::check_client_cert_verifier(sigalg,ccvsig_s,fh_s,cpk_s) {         //TH
                        delayed_alert=BAD_CERT_CHAIN;
                    //self.send_alert(DECRYPT_ERROR);
                        log(IO_DEBUG,"Client Cert Verification failed\n",0,None);
                        log(IO_PROTOCOL,"Full Handshake will fail\n",0,None);
                    //self.clean();
                    //return TLS_FAILURE;
                    }
                    log(IO_PROTOCOL,"Client Cert Verification OK - ",-1,Some(&self.clientid[0..self.cidlen]));                      // **** output client full name        
                }
            } else {
                for i in 0..hlen {
                    th_s[i]=hh_s[i];                                                        //FH
                }            
            }
        }
        let mut fnlen=0;
        let mut fin:[u8;MAX_HASH]=[0;MAX_HASH];
        rtn=self.get_client_finished(&mut fin,&mut fnlen);   
        if self.bad_response(&rtn) {
            self.clean();
            return TLS_FAILURE;
        }        
    //
    //  <---------------------------------------------------- {Client finished}
    //

        log(IO_DEBUG,"Server receives client finished\n",0,None);
        log(IO_DEBUG,"Client Verify Data= ",0,Some(&fin[0..fnlen])); 
        let fin_s=&fin[0..fnlen];


        if !keys::check_verifier_data(hash_type,fin_s,&self.cts[0..hlen],th_s) {          
            self.send_alert(DECRYPT_ERROR);                              // no point in sending alert - haven't calculated traffic keys yet
            log(IO_DEBUG,"Client Data is NOT verified\n",0,None);
            self.clean();
            return TLS_FAILURE;
        }

        self.transcript_hash(fh_s);
        log(IO_DEBUG,"Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]+CF) = ",0,Some(fh_s));
// calculate traffic and application keys from handshake secret and transcript hashes

        self.derive_application_secrets(hh_s,fh_s,None);
        self.create_send_crypto_context();
        self.create_recv_crypto_context();
        log(IO_DEBUG,"Client application traffic secret= ",0,Some(&self.cts[0..hlen]));
        log(IO_DEBUG,"Server application traffic secret= ",0,Some(&self.sts[0..hlen]));

        if resume {
            log(IO_PROTOCOL,"RESUMPTION handshake succeeded\n",0,None);
        } else {
            log(IO_PROTOCOL,"FULL handshake succeeded\n",0,None);
        }

        if delayed_alert != 0 { // there was a problem..
            self.send_alert(alert_from_cause(delayed_alert));
            return TLS_FAILURE;
        }

        self.status=CONNECTED;
        return TLS_SUCCESS;
    }

/// Send a message post-handshake
    pub fn send(&mut self,mess: &[u8]) {
        self.send_message(APPLICATION,TLS1_2,mess,None);       
    }

/// Process Client records received post-handshake.
/// Should be mostly application data, but could be more handshake data disguised as application data
// Also sending key K_send might be updated.
// returns +ve length of message, or negative error, or 0 for a handshake
    pub fn recv(&mut self,mess: &mut [u8]) -> isize {
        let mut fin=false;
        let mut kind:isize;
        let mut pending=false;
        let mslen:isize;
        loop {
            log(IO_PROTOCOL,"Waiting for Client input \n",0,None);
            self.clean_io();
            kind=self.get_record();  // get first fragment to determine type
            if kind<0 {
                self.send_alert(alert_from_cause(kind));
                return kind;   // its an error
            }
            if kind==TIMED_OUT as isize {
                log(IO_PROTOCOL,"TIME_OUT\n",0,None);
                return TIME_OUT;
            }
            if kind==HSHAKE as isize { // should check here for key update
                loop {
                    let mut r=self.parse_int_pull(1); let nb=r.val; if r.err!=0 {break;}
                    r=self.parse_int_pull(3); let len=r.val; if r.err!=0 {break;}   // message length
                    match nb as u8 {
                        KEY_UPDATE => {
                            if len!=1 {
                                log(IO_PROTOCOL,"Something wrong\n",0,None);
                                self.send_alert(DECODE_ERROR);
                                return BAD_RECORD;
                            } 
                            let htype=sal::hash_type(self.cipher_suite);
                            let hlen=sal::hash_len(htype);
                            r=self.parse_int_pull(1); let kur=r.val; if r.err!=0 {break;}
                            if kur==UPDATE_NOT_REQUESTED {  // reset record number
                                self.k_recv.update(&mut self.sts[0..hlen]);
                                log(IO_PROTOCOL,"RECEIVING KEYS UPDATED\n",0,None);
                            }
                            if kur==UPDATE_REQUESTED {
                                self.k_recv.update(&mut self.sts[0..hlen]);
                                pending=true;
                                log(IO_PROTOCOL,"Key update notified - server should do the same\n",0,None);
                                log(IO_PROTOCOL,"RECEIVING KEYS UPDATED\n",0,None);
                            }
                            if kur!=UPDATE_NOT_REQUESTED && kur!=UPDATE_REQUESTED {
                                log(IO_PROTOCOL,"Bad Request Update value\n",0,None);
                                self.send_alert(ILLEGAL_PARAMETER);
                                return BAD_REQUEST_UPDATE;
                            }
                            if self.ptr==self.iolen {
                                fin=true;
                                self.rewind();
                            }
                            if !fin {continue;}
                        }
                        _ => {
                            log(IO_PROTOCOL,"Unsupported Handshake message type ",nb as isize,None);
                            fin=true;
                        }
                    }
                    if r.err!=0 {
                        self.send_alert(alert_from_cause(r.err));
                        break;
                    }
                    if fin {break;}
                }

            }
            if pending {
                    self.send_key_update(UPDATE_NOT_REQUESTED);  // tell server to update their receiving keys
                    log(IO_PROTOCOL,"SENDING KEYS UPDATED\n",0,None);
            }
            if kind==APPLICATION as isize{ // exit only after we receive some application data
                self.ptr=self.iolen; // grab all of it
                let mut n=mess.len();
                if n>self.ptr {
                    n=self.ptr;
                }
                for i in 0..n {
                    mess[i]=self.io[i];
                }
                mslen=n as isize;
                self.rewind();
                break;
            }
            if kind==ALERT as isize {
                log(IO_PROTOCOL,"*** Alert received - ",0,None);
                logger::log_alert(self.io[1]);
                //if self.io[1]==CLOSE_NOTIFY {
                //    self.send_alert(CLOSE_NOTIFY);
                //}
                return ALERT_RECEIVED;
            }
        }
        return mslen; 
    }

/// Clean up buffers, kill crypto keys
    pub fn clean(&mut self) {
        self.status=DISCONNECTED;
        self.io.zeroize();
        self.cts.zeroize();
        self.sts.zeroize();
        self.hs.zeroize();
        self.rms.zeroize();
        self.k_send.clear();
        self.k_recv.clear();
    }

/// Clean out IO buffer
    fn clean_io(&mut self) {
        for i in 0..self.iolen {
            self.io[i]=0;
        }  
        self.ptr=0;
        self.iolen=0;
    }

    pub fn stop(&mut self) {
        self.send_alert(CLOSE_NOTIFY);
        self.status=DISCONNECTED;
    }
}
