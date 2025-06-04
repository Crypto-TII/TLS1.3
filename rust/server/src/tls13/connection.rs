
//! Main TLS1.3 protocol 

use std::net::{TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};
//use std::time::Duration;
//use std::thread;


use zeroize::Zeroize;

use crate::config::*;
use crate::sal_m::sal;
use crate::tls13::socket;
use crate::tls13::extensions;
use crate::tls13::certchain;
use crate::tls13::servercert;
use crate::tls13::keys;
use crate::tls13::logger;
use crate::tls13::logger::log;
use crate::tls13::utils;
use crate::tls13::utils::RET;

use crate::sal_m::bfibe;
use crate::sal_m::pqibe;


/// Milliseconds since epoch
pub fn millis() -> usize {
    return SystemTime::now().duration_since(UNIX_EPOCH).expect("").as_millis() as usize;    
}

/// TLS1.3 session structure
pub struct SESSION {
    pub port: u16,         // Connection port
    pub status: usize,     // Connection status 
    pub max_output_record_size: usize, // max record size I should send
    pub sockptr: TcpStream,     // Pointer to socket 
    pub iblen: usize,           // Input buffer length - input decrypted data
    pub ptr: usize,             // Input buffer pointer - consumed portion
    pub session_id:[u8;33],     // legacy session ID
    pub hostname: [u8;MAX_SERVER_NAME],     // Server name for connection 
    pub hlen: usize,            // hostname length
    pub cipher_suite: u16,      // agreed cipher suite 
    pub favourite_group: u16,   // favourite key exchange group 
    pub k_send: keys::CRYPTO,   // Sending Key 
    pub k_recv: keys::CRYPTO,   // Receiving Key 
    pub server_cert_type: u8,   // expected server cert type
    pub client_cert_type: u8,   // expected client cert type
    pub hs: [u8;MAX_HASH],      // Handshake secret Secret  
    pub rms: [u8;MAX_HASH],     // Resumption Master Secret         
    pub sts: [u8;MAX_HASH],     // Server Traffic secret             
    pub cts: [u8;MAX_HASH],     // Client Traffic secret   
    pub ctx: [u8;MAX_HASH],     // certificate request context
    pub ctxlen: usize,          // context length
    pub ibuff: [u8;MAX_IBUFF_SIZE],        // Main input buffer for this connection 
    pub obuff: [u8;MAX_OBUFF_SIZE], // output buffer
    pub optr: usize,            // output buffer pointer
    pub tlshash: UNIHASH,       // Transcript hash recorder 
    pub clientid: [u8;MAX_X509_FIELD], // Client identity for this session
    pub cidlen: usize,          // client id length
    pub post_hs_auth: bool,
    pub client_authenticated: bool,

    ticket: [u8;MAX_TICKET_SIZE], //psk identity (resumption ticket)
    tklen: usize,           // psk identity length
    ticket_obf_age: u32,    // psk obfuscated age

    pub expect_heartbeats: bool,    // Am I expecting heartbeats?
    pub allowed_to_heartbeat: bool, // Am I allowed to heartbeat?
    pub heartbeat_req_in_flight: bool // timestamp on outstanding request, otherwise 0
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

/// Do I support this cipher-suite ? Check with SAL..
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

/// check for overlap given client signature capabilities, and my server certificate
fn overlap(client_sig_algs: &[u16],client_cert_sig_algs: &[u16]) -> bool {
    let mut server_cert_reqs:[u16;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS];  
    let nsreq=servercert::get_sig_requirements(&mut server_cert_reqs); 
/*
println!("No of requirements = {}",nsreq);
for i in 0..nsreq {
    println!("{}",server_cert_reqs[i]);
}
println!("No of client sig algs = {}",client_sig_algs.len());
for i in 0..client_sig_algs.len() {
    println!("{}",client_sig_algs[i]);
}
println!("No of client cert sig algs = {}",client_cert_sig_algs.len());
*/
    for i in 0..nsreq {
        let mut itsthere=false;
        let sig=server_cert_reqs[i];
        for j in 0..client_sig_algs.len() {
            if sig==client_sig_algs[j] {
                itsthere=true;
            }
        }
        for j in 0..client_cert_sig_algs.len() {
            if sig==client_cert_sig_algs[j] {
                itsthere=true;
            }
        }
        if !itsthere {
            return false;
        }
    }
    return true;    
}

/// check for malformed length field (should be even, should be less than some limit)
fn malformed(rval: usize,maxm: usize) -> bool {

    if (rval&1) == 1 { // if its odd -> error
        return true;
    }
    if rval/2 > maxm { // if its too big -> error
        return true;
    }
    return false;
}

// IO buffer
// xxxxxxxxxxxxxxxxxxxxxxxxxxxyyyyyyyyyyyyyyyyyyyyyyyyyyy
// -------------ptr---------->----------iblen----------->
//
// when ptr becomes equal to iblen, pull in another record (and maybe decrypt it)

impl SESSION {
    pub fn new(stream: TcpStream,pt: u16) -> SESSION  {
        let this=SESSION {
            port: pt,
            status:DISCONNECTED,
            max_output_record_size: MAX_OUTPUT_RECORD_SIZE,
            sockptr: stream,
            iblen: 0,
            ptr: 0,
            session_id: [0;33],
            hostname: [0; MAX_SERVER_NAME],
            hlen: 0,
            cipher_suite: 0,  //AES_128_GCM_SHA256,
            favourite_group: 0,
            k_send: keys::CRYPTO::new(), 
            k_recv: keys::CRYPTO::new(),
            server_cert_type: X509_CERT,
            client_cert_type: X509_CERT,
            hs: [0;MAX_HASH],
            rms: [0;MAX_HASH],
            sts: [0;MAX_HASH],
            cts: [0;MAX_HASH],  
            ctx: [0;MAX_HASH],
            ctxlen: 0,
            ibuff: [0;MAX_IBUFF_SIZE],
            obuff: [0;MAX_OBUFF_SIZE],
            optr: 0,
            tlshash:{UNIHASH{state:[0;MAX_HASH_STATE],htype:0}},
            clientid:[0;MAX_X509_FIELD],
            cidlen: 0,
            post_hs_auth: false,
            client_authenticated: false,

            ticket: [0;MAX_TICKET_SIZE],
            tklen: 0,
            ticket_obf_age: 0,
            expect_heartbeats: false,
            allowed_to_heartbeat: false,
            heartbeat_req_in_flight: false,
        }; 
        return this;
    }
 
// These functions "pull" data from the input stream. That may require reading in a new record and decrypting it.

/// Get an integer of length len bytes from ibuff stream
    fn parse_int_pull(&mut self,len:usize) -> RET {
        let mut r=utils::parse_int(&self.ibuff[0..self.iblen],len,&mut self.ptr);
        while r.err !=0 { // not enough bytes in IO - pull in another record
            let rtn=self.get_record();  // gets more stuff and increments iblen
            if rtn!=HSHAKE as isize {
                r.err=rtn;
                if rtn==ALERT as isize {
                    r.val=self.ibuff[1] as usize;
                }
                break;
            }
            r=utils::parse_int(&self.ibuff[0..self.iblen],len,&mut self.ptr);
        }
        return r;
    }  
    
/// pull bytes from ibuff into array
    fn parse_bytes_pull(&mut self,e: &mut[u8]) -> RET {
        let mut r=utils::parse_bytes(e,&self.ibuff[0..self.iblen],&mut self.ptr);
        while r.err !=0 { // not enough bytes in IBUFF - pull in another record
            let rtn=self.get_record();  // gets more stuff and increments iblen
            if rtn!=HSHAKE as isize  {
                r.err=rtn;
                if rtn==ALERT as isize {
                    r.val=self.ibuff[1] as usize;    // 0 is alert level, 1 is alert description
                }
                break;
            }
            r=utils::parse_bytes(e,&self.ibuff[0..self.iblen],&mut self.ptr);
        }
        return r;
    }

/// Pull bytes into input buffer, process them there, in place
    fn parse_pull(&mut self,n: usize) -> RET { // get n bytes into self.ibuff
        let mut r=RET{val:0,err:0};
        while self.ptr+n>self.iblen {
            let rtn=self.get_record();
            if rtn!=HSHAKE  as isize  {
                r.err=rtn;
                if rtn==ALERT as isize {
                    r.val=self.ibuff[1] as usize;    // 0 is alert level, 1 is alert description
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

/// Rewind ibuff
    fn rewind(&mut self) {
        self.iblen=utils::shift_left(&mut self.ibuff[0..self.iblen],self.ptr); // rewind
        self.ptr=0;        
    }

/// Add input buffer self.ibuff to transcript hash 
    fn running_hash_io(&mut self) {
        sal::hash_process_array(&mut self.tlshash,&self.ibuff[0..self.ptr]);
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
        sal::hash_process_array(&mut rhash,&self.ibuff[0..self.ptr]);
        sal::hash_output(&rhash,&mut h);
        let t:[u8;4]=[MESSAGE_HASH,0,0,hlen as u8];
        sal::hash_process_array(&mut self.tlshash,&t);
        self.running_hash(&h[0..hlen]);
        self.iblen=utils::shift_left(&mut self.ibuff[0..self.iblen],self.ptr); // rewind
        self.ptr=0;
    }

// Note these are flipped from the client side
/// Create a sending crypto context
    fn create_send_crypto_context(&mut self) {
        self.k_send.init(self.cipher_suite,&self.sts);
    }

/// Create a receiving crypto context
    fn create_recv_crypto_context(&mut self) {
        self.k_recv.init(self.cipher_suite,&self.cts);
    }

/// Only if client has indicated support and client has not already authenticated and server was looking for authentication...
    pub fn requires_post_hs_auth(&mut self) -> bool {
        if self.post_hs_auth && !self.client_authenticated && CERTIFICATE_REQUEST {
            return true;
        } else {
            return false;
        }
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
    fn derive_application_secrets(&mut self,sfh: &[u8],cfh: &[u8],ems: Option<&mut [u8]>) {
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

/// Create a certificate request context. So that each certificate request is unique (and cant be replayed)
    pub fn create_request_context(&mut self) {
        self.ctxlen=32;
        for i in 0..32 { // create a random context
            self.ctx[i]=sal::random_byte();
        }
    }

/// send one or more records, maybe encrypted.
/// respects requests for change in max output record size
    fn send_record(&mut self,rectype: u8,version: usize,data: &[u8],flush: bool) {
        let mut rh:[u8;5]=[0;5];  // record header
        let len=data.len();
        for i in 0..len {
            self.obuff[self.optr+5]=data[i];
            self.optr+=1;
            if self.optr==self.max_output_record_size || (i==len-1 && flush) { // block is full, or its the last one and we want to flush
                let reclen:usize;
                if !self.k_send.active { // no encryption
                    reclen=self.optr;
                    rh[0]=rectype;
                    rh[1]=(version/256) as u8;
                    rh[2]=(version%256) as u8;
                    rh[3]=(reclen/256) as u8;
                    rh[4]=(reclen%256) as u8;
                } else {
                    let mut tag:[u8;MAX_TAG_SIZE]=[0;MAX_TAG_SIZE];
                    let taglen=self.k_send.taglen;
                    self.obuff[self.optr+5]=rectype;
                    let ctlen:usize;
                    if PAD_SHORT_RECORDS {
                        ctlen=self.max_output_record_size+1;    // pad record to max size, so all encrypted records are of same size
                    } else {
                        ctlen=self.optr+1;
                    }
                    reclen=ctlen+taglen;
                    rh[0]=APPLICATION;
                    rh[1]=(TLS1_2/256) as u8;
                    rh[2]=(TLS1_2%256) as u8;
                    rh[3]=(reclen/256) as u8;
                    rh[4]=(reclen%256) as u8;
                    
                    sal::aead_encrypt(&self.k_send,&rh,&mut self.obuff[5..ctlen+5],&mut tag[0..taglen]);
                    self.k_send.increment_crypto_context(); //increment iv
                    for j in 0..taglen { // append tag
                        self.obuff[ctlen+j+5]=tag[j];
                    }
                }
                for j in 0..5 {
                    self.obuff[j]=rh[j];
                }
                socket::send_bytes(&mut self.sockptr,&self.obuff[0..reclen+5]);

                self.optr=0;
                for j in 0..reclen+5 {
                    self.obuff[j]=0; // padding by zeros ensured, kill evidence
                }
            }
        }
    }

/// to bewilder the enemy - send padded zero length application record
#[allow(dead_code)]
    pub fn send_zero_record(&mut self) {
        let mut rh:[u8;5]=[0;5];  // record header
        let mut tag:[u8;MAX_TAG_SIZE]=[0;MAX_TAG_SIZE];
        let taglen=self.k_send.taglen;
        let ctlen=self.max_output_record_size+1;
        let reclen=ctlen+taglen;
        rh[0]=APPLICATION;
        rh[1]=(TLS1_2/256) as u8;
        rh[2]=(TLS1_2%256) as u8;
        rh[3]=(reclen/256) as u8;
        rh[4]=(reclen%256) as u8;
        self.obuff[5]=APPLICATION;
        sal::aead_encrypt(&self.k_send,&rh,&mut self.obuff[5..ctlen+5],&mut tag[0..taglen]);
        self.k_send.increment_crypto_context(); //increment iv
        for j in 0..taglen { // append tag
            self.obuff[ctlen+j+5]=tag[j];
        }
        for j in 0..5 { // prepend record header
            self.obuff[j]=rh[j];
        }
        socket::send_bytes(&mut self.sockptr,&self.obuff[0..reclen+5]);
        self.optr=0;
        for j in 0..reclen+5 {
            self.obuff[j]=0; // padding by zeros ensured, kill evidence
        }
    }

/// Send a message - broken down into multiple records.
/// Message comes in two halves - cm and (optional) ext.
/// flush if end of pass, or change of key
    fn send_message(&mut self,rectype: u8,version: usize,cm: &[u8],ext: Option<&[u8]>,flush: bool) {
        if self.status==DISCONNECTED {
            return;
        }

        let mut choice=flush;
        if !MERGE_MESSAGES {
            choice=true;
        }
        if let Some(sext) = ext {
            self.send_record(rectype,version,cm,false);
            self.send_record(rectype,version,sext,choice);
        } else {
            self.send_record(rectype,version,cm,choice);
        }
    }   

// send a heart-beat request record. Note my payloads are always of length 0
// should it be encrypted? Yes
#[allow(dead_code)]
    pub fn send_heartbeat_request(&mut self) {
        if self.status==DISCONNECTED || !self.allowed_to_heartbeat || self.heartbeat_req_in_flight {
            return;
        }
        let mut hb:[u8;20]=[0;20];
        let mut ptr=0;
        ptr=utils::append_int(&mut hb,ptr,1,1);  // heartbeat request
        ptr=utils::append_int(&mut hb,ptr,0,2);  // zero payload
        for _ in 0..16 {
            ptr=utils::append_byte(&mut hb,ptr,sal::random_byte(),1);
        }
        self.heartbeat_req_in_flight=true;
        self.send_record(HEART_BEAT,TLS1_2,&hb[0..ptr],true);
    }

/// Check for a bad response. If not happy with what received - send alert and close. If alert received from Server, log it and close.
    fn bad_response(&mut self,r: &RET) -> bool {
        logger::log_server_response(r);
        if r.err !=0 {
            log(IO_PROTOCOL,"Handshake Failed\n",-1,None);
        }
        if r.err<0 {
            self.send_alert(alert_from_cause(r.err));
            self.clean();
            return true;
        }
        if r.err == ALERT as isize {
            logger::log_alert(r.val as u8);
            self.clean();
            return true;
        }
        if r.err != 0 {
            self.clean();
            return true;
        }
        return false;
    }

/// Send an alert to the Client
    pub fn send_alert(&mut self,kind: u8) {
        let pt: [u8;2]=[0x02,kind];
        self.clean_io();
        self.send_message(ALERT,TLS1_2,&pt[0..2],None,true);
        if self.status != DISCONNECTED {
            log(IO_PROTOCOL,"Alert sent to Client - ",-1,None);
            logger::log_alert(kind);
        }
        self.status=DISCONNECTED;
    }

/// Send Change Cipher Suite - helps get past middleboxes (?)
    pub fn send_cccs(&mut self) {
        let cccs:[u8;6]=[0x14,0x03,0x03,0x00,0x01,0x01];
        socket::send_bytes(&mut self.sockptr,&cccs);
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
        self.send_message(HSHAKE,TLS1_2,&pt[0..ptr],Some(&certchain[0..len]),false);
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

        self.send_message(HSHAKE,TLS1_2,&pt[0..ptr],Some(ext),false);
    }

/// Send Server Certificate Verify 
    fn send_server_cert_verify(&mut self, sigalg: u16,scvsig: &[u8]) { 
        let mut pt:[u8;8]=[0;8];
        let mut ptr=0;
        ptr=utils::append_byte(&mut pt,ptr,CERT_VERIFY,1);      // indicates handshake message "certificate verify"
        ptr=utils::append_int(&mut pt,ptr,4+scvsig.len(),3);    // .. and its length
        ptr=utils::append_int(&mut pt,ptr,sigalg as usize,2);
        ptr=utils::append_int(&mut pt,ptr,scvsig.len(),2);
        self.running_hash(&pt[0..ptr]);
        self.running_hash(scvsig);
        self.send_message(HSHAKE,TLS1_2,&pt[0..ptr],Some(scvsig),false);
    }

/// Send Server Certificate Request 
    pub fn send_certificate_request(&mut self,flush: bool) { 
        let mut cert_sig_algs:[u16;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS]; 
        let mut pt:[u8;50+4*MAX_SUPPORTED_SIGS]=[0;50+4*MAX_SUPPORTED_SIGS];
        let nsca=sal::sig_certs(&mut cert_sig_algs);  // get supported certifictate sigs

        let nb=self.ctxlen;
        let len=13+nb+2*nsca;

// Certificate Request Message
        let mut ptr=0;
        ptr=utils::append_byte(&mut pt,ptr,CERT_REQUEST,1); // indicates handshake message "certificate request"
        ptr=utils::append_int(&mut pt,ptr,len-4,3); // .. and its length
        ptr=utils::append_int(&mut pt,ptr,nb,1);   // .. Request Context
        if nb>0 {
            ptr=utils::append_bytes(&mut pt,ptr,&self.ctx[0..nb]);
        } 
        ptr=utils::append_int(&mut pt,ptr,len-7-nb,2);

// Send SIG_ALGS extension, which is confusingly actually the Certificate signature algorithms
// Listing signature algorithms allowed in client certificate chain
        ptr=extensions::add_supported_sigs(&mut pt,ptr,nsca,&cert_sig_algs);

// could send seperate SIG_ALGS_CERT as well??

        self.running_hash(&pt[0..ptr]);
        self.send_message(HSHAKE,TLS1_2,&pt[0..ptr],None,flush);
    }

/// Send final server handshake finish
    fn send_server_finish(&mut self,shf: &[u8]) {
        let mut pt:[u8;4]=[0;4];
        let mut ptr=0;
        ptr=utils::append_byte(&mut pt,ptr,FINISHED,1); // indicates handshake message "server finished"
        ptr=utils::append_int(&mut pt,ptr,shf.len(),3); // .. and its length
        self.running_hash(&pt[0..ptr]);
        self.running_hash(shf);
        self.send_message(HSHAKE,TLS1_2,&pt[0..ptr],Some(shf),true);
    }

/// Send Key update demand
    pub fn send_key_update(&mut self,kur: usize) {
        let mut up:[u8;5]=[0;5];
        let mut ptr=0;
        ptr=utils::append_byte(&mut up,ptr,KEY_UPDATE,1);   // message type
        ptr=utils::append_int(&mut up,ptr,1,3);             // message length
        ptr=utils::append_int(&mut up,ptr,kur,1);
        self.clean_io();
        self.send_message(HSHAKE,TLS1_2,&up[0..ptr],None,true);
        let htype=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(htype);
        self.k_send.update(&mut self.sts[0..hlen]);
        log(IO_PROTOCOL,"KEY UPDATE REQUESTED\n",-1,None);
    }

/// Send resumption ticket, encrypted by STEK
    pub fn send_ticket(&mut self,stek:&[u8]) {
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
        sptr=utils::append_bytes(&mut state,sptr,&iv);
        sptr=utils::append_int(&mut state,sptr,millis(),4);
        sptr=utils::append_int(&mut state,sptr,ticket_age_add as usize,4);
        sptr=utils::append_int(&mut state,sptr,self.cipher_suite as usize,2);
        sptr=utils::append_int(&mut state,sptr,self.favourite_group as usize,2);
        sptr=utils::append_byte(&mut state,sptr,hlen as u8,1);
        sptr=utils::append_bytes(&mut state,sptr,&psk[0..hlen]);
        if self.client_authenticated {
            sptr=utils::append_int(&mut state,sptr,self.cidlen as usize,2);
            sptr=utils::append_bytes(&mut state,sptr,&self.clientid[0..self.cidlen]);
        } else {
            sptr=utils::append_int(&mut state,sptr,0,2);
        }
// encrypt state with AES-128-GCM - using random IV and STEK key (see servercert.rs)
        let mut context=keys::CRYPTO::new();
        context.special_init(&iv,stek);
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

        self.send_message(HSHAKE,TLS1_2,&tick[0..ptr],None,true);
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

        let mut r=self.parse_int_pull(3); let left=r.val; if r.err!=0 {return r;}
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
        
        if left!=4+len {
            r.err=BAD_MESSAGE;
            return r;
        }
        *siglen=len;
        self.running_hash_io();
        r.val=CERT_VERIFY as usize;
        return r;
    }

/// Get client certificate chain, and check its validity. Need to get client full Identity
    fn get_check_client_certificatechain(&mut self,cpk:&mut [u8],cpklen: &mut usize) -> RET {
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
        if nb!=self.ctxlen {
                r.err=MISSING_REQUEST_CONTEXT;// wrong Request context
                return r;
        }
        if nb>0 {
            let start=self.ptr;
            r=self.parse_pull(nb); if r.err!=0 {return r;}
            if &self.ibuff[start..start+nb] != &self.ctx[0..nb] {
                r.err=MISSING_REQUEST_CONTEXT;// wrong Request context
                return r;
            }
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
        r=self.parse_pull(tlen); if r.err!=0 {return r;} // get pointer to certificate chain, and pull it all into self.ibuff
// Update Transcript hash
        r.err=certchain::check_certchain(&self.ibuff[start..start+tlen],None,self.client_cert_type,cpk,cpklen,&mut self.clientid,&mut self.cidlen); 
        if self.client_cert_type == RAW_PUBLIC_KEY {
            log(IO_PROTOCOL,"WARNING - client is authenticating with raw public key\n",-1,None);
        } 
        log(IO_DEBUG,"Client Public Key= ",0,Some(&cpk[0..*cpklen]));
        
        self.running_hash_io();
        r.val=CERTIFICATE as usize;
        return r;
    }

/// Get handshake finish verifier data
    fn get_client_finished(&mut self,hfin: &mut [u8],hflen: &mut usize) -> RET {
        //let mut ptr=0;
        let mut r=self.parse_int_pull(1); // get message type
        if r.err!=0 { return r;}
        let nb=r.val as u8;
        if nb != FINISHED {
            r.err=WRONG_MESSAGE;
        }
        if r.err!=0 {return r;}
        let htype=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(htype);
        r=self.parse_int_pull(3); let len=r.val; if r.err!=0 {return r;}
        if len!=hlen {
            r.err=BAD_MESSAGE;
            return r;
        }
        r=self.parse_bytes_pull(&mut hfin[0..len]); if r.err!=0 {return r;}
        *hflen=len;
        self.running_hash_io();
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
        let pos=self.iblen;
        if !socket::get_bytes(&mut self.sockptr,&mut rh[0..3]) {
            return TIMED_OUT as isize;
        }

// Should I check legacy record version?

        if rh[0]==ALERT { // scrub iobuffer, and just leave alert code
            let left=socket::get_int16(&mut self.sockptr);
            if left!=2 {
                return BAD_RECORD;
            }
            if !socket::get_bytes(&mut self.sockptr,&mut self.ibuff[0..left]) {
                return TIMED_OUT as isize;
            }  
            self.iblen=left;
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
            if !socket::get_bytes(&mut self.sockptr,&mut rh[0..3]) {
                return TIMED_OUT as isize;
            }
        }
        if rh[0]!=HSHAKE && rh[0]!=APPLICATION && rh[0]!=HEART_BEAT { // rh[0]=0x80 means SSLv2 connection attempted - reject it
            return WRONG_MESSAGE;
        }
        let left=socket::get_int16(&mut self.sockptr);
        if left>MAX_CIPHER_FRAG {
            return MAX_EXCEEDED;
        }
        utils::append_int(&mut rh,3,left,2);
        if left+pos>self.ibuff.len() { // this commonly happens with big records of application data from other party
            return MEM_OVERFLOW;    // record is too big - memory overflow
        }
        if !self.k_recv.is_active() { // not encrypted

// if not encrypted and rh[0] == APPLICATION, thats an error!
            if rh[0]==APPLICATION || rh[0]==HEART_BEAT {
                return BAD_RECORD;
            }
            if left>MAX_PLAIN_FRAG {
                return MAX_EXCEEDED;
            }
            if left==0 {
                return WRONG_MESSAGE;
            }
            if !socket::get_bytes(&mut self.sockptr,&mut self.ibuff[pos..pos+left]) {  // ignore it and carry on
                return TIMED_OUT as isize;
            } 
            self.iblen+=left; // read in record body
            return HSHAKE as isize;
        }

// if encrypted and rh[0] == HSHAKE, thats an error!
        if rh[0]==HSHAKE {
            return BAD_RECORD;
        }

// OK, its encrypted, so aead decrypt it, check tag
        let taglen=self.k_recv.taglen;
        if left < taglen {
            return BAD_RECORD;
        }
        let mut rlen=left-taglen;

        if !socket::get_bytes(&mut self.sockptr,&mut self.ibuff[pos..pos+rlen]) {  // read in record body
            return TIMED_OUT as isize;
        }
        self.iblen+=rlen;
        if !socket::get_bytes(&mut self.sockptr,&mut tag[0..taglen]){
            return TIMED_OUT as isize;
        }
        let success=sal::aead_decrypt(&self.k_recv,&rh,&mut self.ibuff[pos..pos+rlen],&tag[0..taglen]);
        if !success {
            return AUTHENTICATION_FAILURE;
        }
        self.k_recv.increment_crypto_context();
// get record ending - encodes real (disguised) record type. Could be an Alert.        
        let mut lb=self.ibuff[self.iblen-1];
        self.iblen -= 1; rlen -= 1;// remove it
        while lb==0 && rlen>0 {
            lb=self.ibuff[self.iblen-1];
            self.iblen -= 1; rlen -= 1;// remove it
        }

        if rlen>MAX_PLAIN_FRAG {
            return MAX_EXCEEDED;
        }

// if no non-zero found, lb=0
        if (lb == HSHAKE || lb == ALERT) && rlen==0 {
            return WRONG_MESSAGE; // Implementations MUST NOT send zero-length fragments of Handshake types
        }
        if lb == HSHAKE {
            return HSHAKE as isize;
        }
        if lb == APPLICATION {
            return APPLICATION as isize;
        }
        if lb == HEART_BEAT {
            return HEART_BEAT as isize;
        }

        if lb == ALERT { // Alert record received, delete anything in IO prior to alert, and just leave 2-byte alert
            self.iblen=utils::shift_left(&mut self.ibuff[0..self.iblen],pos); // rewind
            return ALERT as isize;
        }
        return WRONG_MESSAGE;
    }

    /// Get client hello. Output encrypted extensions, client public key, client signature algorithms.
    /// Put together Server Hello response. Also generate extensions that are to be encrypted
    fn process_client_hello(&mut self,sh: &mut [u8],shlen: &mut usize,encext: &mut [u8],enclen: &mut usize,ss: &mut [u8],early_indication: &mut bool,is_retry: bool) -> RET {
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

        let mut client_sig_algs: [u16;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS]; // Client supported signature algs
        let mut ncsa=0;            // Number of client supported sig algs
        let mut client_cert_sig_algs: [u16;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS]; // Client supported certificate signature algs
        let mut nccsa=0;           // Number of client supported cert sig algs

        let tls_version=TLS1_3; // only
        let mut hrr: [u8; HRR.len()/2]=[0;HRR.len()/2];
        utils::decode_hex(&mut hrr,&HRR);

        self.ptr=0;  
        self.iblen=0;

        let mut r=self.parse_int_pull(1); if r.err!=0 {return r;}
        if r.val!=CLIENT_HELLO as usize { // should be Client Hello
            r.err=BAD_HELLO;
            return r;
        }
        r=self.parse_int_pull(3); let mut left=r.val; if r.err!=0 {return r;} // If not enough, pull in another fragment
        r=self.parse_int_pull(2); let svr=r.val; if r.err!=0 {return r;}
        if left<34 {
            r.err=BAD_MESSAGE;
            return r;
        }

        left-=2;                // whats left in message
        if svr!=TLS1_2 { 
            r.err=NOT_TLS1_3;  // don't ask
            return r;
        }

        r= self.parse_bytes_pull(&mut rn); if r.err!=0 {return r;}   // 32 random bytes
        left-=32;

        log(IO_DEBUG,"CLient Random= ",0,Some(&rn[0..32]));

        //log(IO_PROTOCOL,"Fingerprint= ",0,Some(&rn[0..6]));
        r=self.parse_int_pull(1); let cilen=r.val; if r.err!=0 {return r;}  // cilen is length of legacy ID
        if cilen>32 { // could be 0?
            r.err=BAD_HELLO;
            return r;
        }
        self.session_id[0]=cilen as u8;
        if left==0 {
            r.err=BAD_MESSAGE;
            return r;
        }
        left-=1;

// from my reading of the RFC, this should be either 0 or 32.. (but maybe 8 is OK?)
        if cilen>0 {
            let mut legacy_id:[u8;32]=[0;32];
            r=self.parse_bytes_pull(&mut legacy_id[0..cilen]); if r.err!=0 {return r;}
            if left<cilen {
                r.err=BAD_MESSAGE;
                return r;
            }
            left-=cilen;  
            for i in 0..cilen {
                self.session_id[i+1]=legacy_id[i];
            }
        }
        r=self.parse_int_pull(2); nccs=r.val/2; if r.err!=0 {return r;}
        if malformed(r.val,MAX_CIPHER_SUITES) {
            r.err=BAD_HELLO;
            return r;
        }
        for i in 0..nccs {
            r=self.parse_int_pull(2); ccs[i]=r.val as u16; if r.err!=0 {return r;}
        }
        if left<6+2*nccs {
            r.err=BAD_HELLO;
            return r;
        }
        left-=2+2*nccs;
        r=self.parse_int_pull(2); if r.err!=0 {return r;}
        left-=2;
        if r.val!=0x0100 {  // compression
            r.err=BAD_PARAMETER;
            return r;
        }
        r=self.parse_int_pull(2); let extlen=r.val; if r.err!=0 {return r;}
        left-=2;  
        if left!=extlen { // Check space left is size of extensions
            r.err=BAD_HELLO;
            return r;
        }
// Problem is this might time-out rather than send an alert
        let mut resume=false;
        let mut agreed=false;
        let mut mfl_mode=0;
        let mut sni_ack=false;
        let mut alplen=0;
        let mut pskmode=0;
        let mut got_psk_ext=false;
        let mut binder_bytes=0;
        let mut nbndrs=0; // number of binders needed
        let mut got_sig_algs_ext=false;
        let mut got_supported_groups_ext=false;
        let mut got_key_share_ext=false;
//println!("Got here OK 1");
        *early_indication=false;
        while left>0 {
            if resume {
                log(IO_DEBUG,"Preshared Key must be last extension\n",-1,None);
                r.err=BAD_PARAMETER;  
                return r;
            }
            if left<4 {r.err=BAD_HELLO; return r;} // no point in pulling on what should not be there
            r=self.parse_int_pull(2); let ext=r.val; if r.err!=0 {return r;} // get extension type
            r=self.parse_int_pull(2); let extlen=r.val; if r.err!=0 {return r;}  // length of this extension
            if extlen+2>left {r.err=BAD_MESSAGE;return r;} 
            if left<4+extlen {
                r.err=BAD_HELLO;
                return r;
            }
            left-=4+extlen;
            log(IO_DEBUG,"Client Hello Extension = ",ext as isize,None);
            match ext {
                SERVER_NAME => {
                    r=self.parse_int_pull(2); let len=r.val; if r.err!=0 {return r;}
                    r=self.parse_int_pull(1); let etype=r.val; if r.err!=0 {return r;}
                    if etype!=0 || len+2!=extlen {
                        r.err=BAD_MESSAGE;
                        return r;
                    }
                    r=self.parse_int_pull(2); if r.err!=0 {return r;}
                    r=self.parse_bytes_pull(&mut host[0..r.val]); if r.err!=0 {return r;}
                    self.hlen=r.val;
                    for i in 0..self.hlen {
                        self.hostname[i]=host[i];
                    }
                    sni_ack=true;
                }
                SUPPORTED_GROUPS => {
                    r=self.parse_int_pull(2); ncg=r.val/2; if r.err!=0 {return r;}
                    if malformed(r.val,MAX_SUPPORTED_GROUPS) {
                        r.err=BAD_HELLO;
                        return r;
                    }
                    if r.val+2!=extlen {
                        r.err=BAD_MESSAGE;
                        return r;
                    }
                    for i in 0..ncg {
                        r=self.parse_int_pull(2); if r.err!=0 {return r;}
                        cg[i]=r.val as u16;
                    }
                    got_supported_groups_ext=true;
                },
                KEY_SHARE => {
                    r=self.parse_int_pull(2); let len=r.val; if r.err!=0 {return r;}
                    if len+2!=extlen {
                        r.err=BAD_MESSAGE;
                        return r;
                    }
//println!("LEN= {}",len);
                    let mut remain=len;
                    while remain>0 {
                        r=self.parse_int_pull(2); alg=r.val as u16; if r.err!=0 {return r;}     // only accept TLS1.3 groups!
                        r=self.parse_int_pull(2); cpklen=r.val; if r.err!=0 {return r;}
                        if remain<4+cpklen {
                            r.err=BAD_MESSAGE;
                            return r;
                        }
//println!("CPKLEN= {}",cpklen);
                        r=self.parse_bytes_pull(&mut cpk[0..cpklen]); if r.err!=0 {return r;}
                        remain-=4+cpklen;
                        if group_support(alg) { // check here that cpklen is correct length for this algorithm
                            if cpklen!=sal::client_public_key_size(alg) {
                                r.err=BAD_PARAMETER; 
                                return r;
                            }
                            self.favourite_group=alg;
                            agreed=true;
                            r=self.parse_pull(remain); if r.err!=0 {return r;}  // found one I agree with - drain the rest
                            break;
                        }
                    }
                    got_key_share_ext=true;
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
                        if remain<1+alplen {
                            r.err=BAD_MESSAGE;
                            return r;
                        }
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
                    r.err=BAD_MESSAGE;
                    if r.val+1!=extlen {return r;}
                    for _ in 0..len {
                        r=self.parse_int_pull(1); let mode=r.val; if r.err!=0 {return r;}
//println!("pskmode= {}",mode);
                        if mode==PSKWECDHE { // if PSKOK is only option offered, exit
                            pskmode=mode;
                            r.err=0;
                        }
                    }
                },
                TLS_VER => {
                    r=self.parse_int_pull(1); let len=r.val/2; if r.err!=0 {return r;}
                    r.err=BAD_MESSAGE;
                    if (r.val&1)==1 {return r;}
                    if r.val+1!=extlen {return r;}
                    for _ in 0..len {
                        r=self.parse_int_pull(2); let tls=r.val; if r.err!=0 {return r;}
                        if tls==TLS1_3 {
                            r.err=0;
                        }
                    }
                },
                MAX_FRAG_LENGTH => {
                    r=self.parse_int_pull(1); mfl_mode=r.val; if r.err!=0 {return r;}
                    if RESPECT_MAX_FRAQ_REQUEST {
                        self.max_output_record_size=1<<(8+mfl_mode);
                    }    
                },
                HEARTBEAT => {
                    r=self.parse_int_pull(1); let hbmode=r.val; if r.err!=0 {return r;}      
                    if hbmode==0 || hbmode>2 {
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }
                    self.expect_heartbeats=true;
//println!("EXPECTING HEARTBEATs");
                    if hbmode==1 {
//println!("ALLOWED TO HEARTBEAT");
                        self.allowed_to_heartbeat=true;
                    } else {
                        self.allowed_to_heartbeat=false;
                    }
                },
                RECORD_SIZE_LIMIT => {
                    r=self.parse_int_pull(2); self.max_output_record_size=r.val; if r.err!=0 {return r;}
                },
                PADDING => {
                    r=self.parse_pull(extlen); if r.err!=0 {return r;}
                },
                SIG_ALGS => {
                    r=self.parse_int_pull(2);  if r.err!=0 {return r;}
                    if malformed(r.val,MAX_SUPPORTED_SIGS) || r.val+2!=extlen {
                        r.err=BAD_HELLO;
                        return r;
                    }
                    ncsa=r.val/2;
                    for i in 0..ncsa {
                        r=self.parse_int_pull(2); if r.err!=0 {return r;}
                        client_sig_algs[i]=r.val as u16;
                    }    
                    if !utils::check_legacy_priorities(&client_sig_algs[0..ncsa]) {
                        r.err=BAD_PARAMETER;
                        return r;
                    }
                    got_sig_algs_ext=true;
                },
                SIG_ALGS_CERT => {
                    r=self.parse_int_pull(2);  if r.err!=0 {return r;}
                    if malformed(r.val,MAX_SUPPORTED_SIGS) || r.val+2!=extlen {
                        r.err=BAD_HELLO;
                        return r;
                    }
                    nccsa=r.val/2;
                    for i in 0..nccsa {
                        r=self.parse_int_pull(2); if r.err!=0 {return r;}
                        client_cert_sig_algs[i]=r.val as u16;
                    }  
                    if !utils::check_legacy_priorities(&client_cert_sig_algs[0..nccsa]) {
                        r.err=BAD_PARAMETER;
                        return r;
                    }                    
                },
                EARLY_DATA => {
                    if extlen!=0 {
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }
                    *early_indication=true;
                },

                CLIENT_CERT_TYPE => {
                    r=self.parse_int_pull(1); if r.err!=0 {return r;}
                    if r.val==0 || r.val>255 { 
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }
                    let nval=r.val;
// if first preference is for a raw public key
//println!("CLIENT RAW KEY ASKED FOR");

                    r=self.parse_int_pull(1); let cct=r.val as u8; if r.err!=0 {return r;}
                    if cct!=RAW_PUBLIC_KEY  || !ALLOW_RAW_CLIENT_PUBLIC_KEY {
                        self.client_cert_type=X509_CERT;
                    } else {
                        self.client_cert_type=RAW_PUBLIC_KEY;
                    }
                    for _ in 1..nval { // ignore the rest
                        r=self.parse_int_pull(1); if r.err!=0 {return r;}
                    }
                },
                SERVER_CERT_TYPE => {
                    r=self.parse_int_pull(1);  if r.err!=0 {return r;}  
                    if r.val==0 || r.val>255 {
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }   
                    let nval=r.val;

//println!("SERVER RAW KEY ASKED FOR");

                    r=self.parse_int_pull(1); let sct=r.val as u8; if r.err!=0 {return r;}
                    if sct!=RAW_PUBLIC_KEY || !ALLOW_RAW_SERVER_PUBLIC_KEY {
                        self.server_cert_type=X509_CERT;
                    } else {
                        self.server_cert_type=RAW_PUBLIC_KEY;
                    }
                    for _ in 1..nval { // ignore the rest
                        r=self.parse_int_pull(1); if r.err!=0 {return r;}
                    }
                },

                POST_HANDSHAKE_AUTH => {
                    if extlen!=0 {
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }
                    self.post_hs_auth=true;
                },
                PRESHARED_KEY => {  
                    r=self.parse_int_pull(2); let tlen1=r.val; if r.err!=0 {return r;}
                    if extlen <= tlen1+2 {  // no room for binders!
                        r.err=BAD_HELLO;
                        return r;
                    }
                    r=self.parse_int_pull(2); if r.err!=0 {return r;}
                    self.tklen=r.val;
                    if tlen1<self.tklen+6 {
                        r.err=BAD_HELLO;
                        return r;
                    }
                    r=self.parse_bytes_pull(&mut tick[0..self.tklen]); if r.err!=0 {return r;}
                    for i in 0..self.tklen {
                        self.ticket[i]=tick[i];
                    }
                    r=self.parse_int_pull(4); self.ticket_obf_age=r.val as u32; if r.err!=0 {return r;}

                    let mut remain=tlen1-self.tklen-6;
                    nbndrs = 1;
                    while remain>0 { // drain the rest
                        r=self.parse_int_pull(2); if r.err!=0 {return r;} 
                        let tklen=r.val;
                        if remain<tklen+6 {
                            r.err=BAD_HELLO;
                            return r;
                        }
                        r=self.parse_pull(tklen+4); if r.err!=0 {return r;} 
                        remain-=tklen+6;
                        nbndrs += 1;
                    }
                    resume=true;    // proceed as for resumption
                    got_psk_ext=true;
                    binder_bytes=extlen-tlen1-2;
                },
                _ => {
                    r=self.parse_pull(extlen); if r.err!=0 {return r;} // just ignore
                    log(IO_DEBUG,"Unrecognized Extension = ",ext as isize,None);
                }
            }
            if r.err!=0 {return r;}
        }
//println!("PSK 3");
// check for missing extensions
        if !got_psk_ext { // not an attempted resumption
            if !got_sig_algs_ext || !got_supported_groups_ext {
                log(IO_DEBUG,"Missing extensions for FULL handshake\n",-1,None);
                r.err=MISSING_EXTENSIONS;
                return r;
            }
            if !overlap(&client_sig_algs[0..ncsa],&client_cert_sig_algs[0..nccsa]) { // check for overlap between TML requirements and client capabilities
                log(IO_DEBUG,"No overlap in signature capabilities\n",-1,None);
                r.err=BAD_HANDSHAKE;
                return r;
            }
        }
        if got_supported_groups_ext!=got_key_share_ext {  // check this - what if got supported groups, but no key share?
//println!("MISSING {} {}",got_supported_groups_ext,got_key_share_ext);
                r.err=MISSING_EXTENSIONS;
                return r;
        }
//println!("PSK 4 - {}",pskmode);
        if got_psk_ext && pskmode==0 { // If clients offer pre_shared_key without a psk_key_exchange_modes extension, servers MUST abort the handshake. 
            log(IO_DEBUG,"Missing PSK modes extension\n",-1,None);
            r.err=BAD_HANDSHAKE;
            return r;
        }
        let mut retry=false;
        if !resume { // check for agreement on cipher suite and group - might need to ask for a handshake retry
            let mut scs:[u16;MAX_CIPHER_SUITES]=[0;MAX_CIPHER_SUITES]; // choose a cipher suite
            let nscs=sal::ciphers(&mut scs);
            let mut chosen=false;
            let mut cipher_suite=0;
//println!("PSK 5a");
            for i in 0..nccs { // start with their favourite
                for j in 0..nscs {
                    if ccs[i]==scs[j] {
                        chosen=true;
                        cipher_suite=scs[j];
                        break;
                    }
                }
                if chosen {break;}
            }
            if !chosen { // no shared cipher suite
                r.err=BAD_HANDSHAKE;
                return r;
            }
            if is_retry {
                if cipher_suite!=self.cipher_suite {
                    r.err=BAD_HELLO;
                    return r;
                }
            } else {
                self.cipher_suite=cipher_suite;
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
                log(IO_DEBUG,"Cannot find any matching cipher suite\n",-1,None);
                r.err=BAD_MESSAGE;
                return r;
            }
       // Here should attempt HRR if no agreed group! ******
            if pskmode==PSKWECDHE && !agreed { // In this mode, the client and server MUST supply key_share values
//println!("No agreed group, should really do HRR");
                r.err=BAD_HELLO;
                return r;
            }

        }
//println!("PSK 6");
        if !retry { // we are not doing a retry
            let mut supported=false;
            for i in 0..ncg { // better check that the key share from client is also one of clients supported groups, as well as being OK with me
                if self.favourite_group==cg[i] {
                    supported=true;
                }
            }
            if !supported {
                r.err=BAD_HELLO;
                return r;
            }
        }

        log(IO_DEBUG,"Client Hello = ",0,Some(&self.ibuff[0..self.ptr]));
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
                extlen=extensions::add_presharedkey(&mut ext,extlen,0);  // ALWAYS select first psk
            }
            self.running_hash_io();
        }
// println!("Going for HRR");
// now construct server hello (or HRR) + extensions
        let mut ptr=0;
        ptr=utils::append_byte(sh,ptr,SERVER_HELLO,1);
        ptr=utils::append_int(sh,ptr,40+cilen+extlen,3);
        ptr=utils::append_int(sh,ptr,TLS1_2,2);
        ptr=utils::append_bytes(sh,ptr,&rn[0..32]);

        log(IO_DEBUG,"Server Random= ",0,Some(&rn[0..32]));

        if self.session_id[0]==0 {
            ptr=utils::append_byte(sh,ptr,0,1);
        } else {
            ptr=utils::append_bytes(sh,ptr,&self.session_id[0..cilen+1]);
        }
        ptr=utils::append_int(sh,ptr,self.cipher_suite as usize,2);
        ptr=utils::append_int(sh,ptr,0,1); // no compression
        ptr=utils::append_int(sh,ptr,extlen,2);

        ptr=utils::append_bytes(sh,ptr,&ext[0..extlen]);
        *shlen=ptr;


// while we are here construct server extensions to be encrypted
        extlen=0;
        if ENABLE_HEARTBEATS {
            extlen=extensions::add_heartbeat(encext,extlen);
        }
        if mfl_mode>0 {
            extlen=extensions::add_mfl(encext,extlen,mfl_mode);
        }
        if sni_ack {
            extlen=extensions::add_server_name(encext,extlen);
        }
        if alplen>0 {
            extlen=extensions::add_alpn(encext,extlen,&mut alpn[0..alplen]);
        }
        if *early_indication {
            extlen=extensions::add_early_data(encext,extlen);
        }

// if client asked for raw keys, and we are willing, then inform client that that we are sending them. Otherwise, forget it.
        if self.client_cert_type==RAW_PUBLIC_KEY && ALLOW_RAW_CLIENT_PUBLIC_KEY && CERTIFICATE_REQUEST {
            extlen=extensions::add_supported_client_cert_type(encext,extlen,RAW_PUBLIC_KEY);
        } else {
            self.client_cert_type=X509_CERT;
        }
        if self.server_cert_type==RAW_PUBLIC_KEY && ALLOW_RAW_SERVER_PUBLIC_KEY{
            extlen=extensions::add_supported_server_cert_type(encext,extlen,RAW_PUBLIC_KEY);
        } else {
            self.server_cert_type=X509_CERT;
        }
        *enclen=extlen;

        if retry { // try again..
            r.val=HANDSHAKE_RETRY;
            return r;
        }
        if resume { // going for a resumption
            r.val=TRY_RESUMPTION;
            let hash_type=sal::hash_type(self.cipher_suite);
            let hlen=sal::hash_len(hash_type);
            if binder_bytes!=2+(1+hlen)*nbndrs {
                r.err=BAD_HELLO;
                return r;                
            }
        }
        return r; 
    }

/// Process resumption ticket, decrypt using STEK, and recover pre-shared key
// But is it a resumption ticket or a PSK label?
    fn process_ticket(&mut self,psk: &mut [u8],psklen: &mut usize,stek: &[u8]) -> RET {
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

// This is experimental
        if self.ticket_obf_age==0 && ALLOW_IBE_PSKS { // assume its an IBE connection. Slightly dodgy way of identifying an IBE PSK
            log(IO_PROTOCOL,"Its an IBE connection\n",-1,None);
            let ticklen=self.tklen;
            let tick=&self.ticket[0..ticklen];

// process it depending on the active crypto-setting
            match CRYPTO_SETTING {
                TYPICAL | TINY_ECC | EDDSA => {
                    const HAFLEN:usize=servercert::BFSK.len()/2;
                    let mut bfsk: [u8; HAFLEN]=[0;HAFLEN];
                    utils::decode_hex(&mut bfsk,&servercert::BFSK);
                    bfibe::cca_decrypt(&bfsk,tick,psk);
                    *psklen=bfibe::KYLEN;
                },
                POST_QUANTUM => {
                    pqibe::cca_decrypt(&servercert::ID,&servercert::PQSK,tick,psk);
                    *psklen=pqibe::KYLEN;
                },
                HYBRID => {
                    pqibe::cca_decrypt(&servercert::ID,&servercert::PQSK,&tick[0..pqibe::CTLEN],&mut psk[0..32]);
                    const HAFLEN:usize=servercert::BFSK.len()/2;
                    let mut bfsk: [u8; HAFLEN]=[0;HAFLEN];
                    utils::decode_hex(&mut bfsk,&servercert::BFSK);
                    bfibe::cca_decrypt(&bfsk,&tick[pqibe::CTLEN..],&mut psk[32..64]);
                    *psklen=bfibe::KYLEN+pqibe::KYLEN;
                },
                _ => {
                    r.err= BAD_TICKET;
                },
            }

            r.val=EXTERNAL_PSK;
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
        context.special_init(&iv,stek);

        if !sal::aead_decrypt(&context,&iv,&mut state,&tag) {
            r.err=AUTHENTICATION_FAILURE;
            return r;
        }
        log(IO_DEBUG,"Resumption state received= ",0,Some(&state));

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
            log(IO_PROTOCOL,"Ticket is out of date\n",-1,None);
            r.err=BAD_TICKET;
            return r;
        }

        r=utils::parse_int(&state,2,&mut ptr); let tc=r.val as u16; if r.err!=0 {return r;}
        r=utils::parse_int(&state,2,&mut ptr); let tg=r.val as u16; if r.err!=0 {return r;}
        if tc != self.cipher_suite || tg!=self.favourite_group {
            log(IO_DEBUG,"Ticket Crypto Mismatch\n",-1,None);
            r.err=BAD_TICKET;
            return r;
        }
        r=utils::parse_int(&state,1,&mut ptr); *psklen=r.val; if r.err!=0 {return r;}
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

// now receive Binders, that is the rest of the client Hello. Get the first one
        let mut rbnd:[u8;MAX_HASH]=[0;MAX_HASH]; let rbnd_s=&mut rbnd[0..hlen];
        
        let mut r=self.parse_int_pull(2); let tlen=r.val; if r.err!=0 {return r;}
        if tlen<hlen+1 {
            r.err=BAD_MESSAGE;
            return r;
        }
        r=self.parse_int_pull(1); let bnlen=r.val; if r.err!=0 {return r;}
        if bnlen!= hlen{
            r.err=BAD_MESSAGE;
            return r;
        }
        r=self.parse_bytes_pull(rbnd_s); if r.err!=0 {return r;}

        let mut remain=tlen-hlen-1;
        while remain>0 { // drain the remainder
            r=self.parse_int_pull(1); if r.err!=0 {return r;} 
            let len=r.val;
            if len!= hlen{
                r.err=BAD_MESSAGE;
                return r;
            }
            r=self.parse_pull(len); if r.err!=0 {return r;}
            if remain<len+1 {
                r.err=BAD_HELLO;
                return r;
            }
            remain-=len+1;
        }

        log(IO_DEBUG,"Final part (binders) of Client Hello = ",0,Some(&self.ibuff[0..self.ptr]));

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
    pub fn connect(&mut self,early: &mut [u8],edlen: &mut usize,stek: &[u8]) -> usize {
        let mut sh:[u8;MAX_HELLO]=[0;MAX_HELLO];
        let mut ext:[u8;MAX_EXTENSIONS]=[0;MAX_EXTENSIONS];
        let mut ss:[u8;MAX_SHARED_SECRET_SIZE]=[0;MAX_SHARED_SECRET_SIZE];
        let mut ccs_sent=false;
        let mut early_indication=false;
        let mut shlen=0;
        let mut enclen=0;
        self.status=HANDSHAKING;
        let mut rtn=self.process_client_hello(&mut sh,&mut shlen,&mut ext,&mut enclen,&mut ss,&mut early_indication,false);
        if self.bad_response(&rtn) {
            return TLS_FAILURE;
        }
//
//
//   <---------------------------------------------------------- client Hello received
//
//  Server Hello + extensions prepared in sh, encrypted extensions in ext

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
            let mut r=self.process_ticket(&mut psk,&mut psklen,stek);
            if self.bad_response(&r) {
                return TLS_FAILURE;
            }
//println!("Ticket processed");
            let mut external_psk=false;
            if r.val==EXTERNAL_PSK {
                external_psk=true;
            }
//println!("Checking binders");
            r=self.process_binders(external_psk,&psk[0..psklen],es_s);
            if self.bad_response(&r) {
                return TLS_FAILURE;
            }
//println!("Got a good looking ticket");
// Early application data is probably waiting for me in TCP/IP input queue
// It needs to be decrypted using current recv key. So must not update recv key
// until after taking in early data from client
// I will know its OK to accept this data when there is an End-of-Early handshake message received
// But its too early for that yet

            self.send_message(HSHAKE,TLS1_2,&sh[0..shlen],None,true); // send server hello
            self.send_cccs();
//
//
//   server Hello sent ----------------------------------------------------------> 
//
            self.running_hash(&sh[0..shlen]);       // Hashing Server Hello
            self.transcript_hash(hh_s);             // HH = hash of clientHello+serverHello

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
            log(IO_DEBUG,"Server is sending server Finished\n",-1,None);
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
                    //self.iblen=0;
                    let kind=self.get_record();  // get first fragment up to iblen to determine type
                    if kind<0 {
                        self.send_alert(alert_from_cause(kind));
                        return TLS_FAILURE;   // its an error
                    }
                    if kind==TIMED_OUT as isize {
                        log(IO_PROTOCOL,"TIME_OUT\n",-1,None);
                        return TLS_FAILURE;
                    }
                    if kind==HSHAKE as isize { // its a handshake message - should be end-of-early data
                        let r=self.get_end_of_early_data();
                        if self.bad_response(&r) {
                            return TLS_FAILURE;
                        }
                        log(IO_PROTOCOL,"Early Data received\n",-1,None);
                        break;
                    }
                    if kind==APPLICATION as isize { // receive some application data
                        self.ptr=self.iblen;   // grab entire record
                        if *edlen+self.ptr>MAX_EARLY_DATA {
                            return TLS_FAILURE;
                        }
                        for i in 0..self.ptr {
                            early[*edlen+i]=self.ibuff[i];
                        }
                        *edlen+=self.ptr;
                        self.rewind();
                        continue;
                    }
                    if kind==ALERT as isize {
                        log(IO_PROTOCOL,"*** Alert received - ",-1,None);
                        logger::log_alert(self.ibuff[1]);
                        return TLS_FAILURE;
                    }
                }
            }
            self.transcript_hash(th_s);
            self.create_recv_crypto_context();  // now update handshake keys
        } else {
            log(IO_PROTOCOL,"Attempting Full Handshake on port ",self.port as isize,None);
            if rtn.val==HANDSHAKE_RETRY { // try one more time
                self.running_hash(&sh[0..shlen]);
                self.transcript_hash(hh_s);                                            //  *********CH+SH********  
                self.send_message(HSHAKE,TLS1_2,&sh[0..shlen],None,true);
                log(IO_DEBUG,"Hello Retry Request sent\n",-1,None);
                self.send_cccs();
                ccs_sent=true;

                shlen=0;
                enclen=0;
//
//   <---------------------------------------------------------- receive updated client Hello
//
                let rtn=self.process_client_hello(&mut sh,&mut shlen,&mut ext,&mut enclen,&mut ss,&mut early_indication,true);
                if self.bad_response(&rtn) {
                    return TLS_FAILURE;
                }
                if rtn.val==HANDSHAKE_RETRY {
                    self.send_alert(UNEXPECTED_MESSAGE);
                    log(IO_DEBUG,"Attempted second retry request\n",-1,None);
                    self.clean();
                    return TLS_FAILURE;
                }
            }
            self.running_hash(&sh[0..shlen]);
            self.transcript_hash(hh_s);                                   
            log(IO_DEBUG,"Client Hello processed\n",-1,None);
            log(IO_DEBUG,"Host= ",-1,Some(&self.hostname[0..self.hlen]));
            let sslen=sal::shared_secret_size(self.favourite_group);
            let ss_s=&mut ss[0..sslen];
            log(IO_DEBUG,"Shared secret= ",0,Some(ss_s));
            log(IO_DEBUG,"Server Hello= ",0,Some(&sh[0..shlen]));

            keys::derive_early_secrets(hash_type,None,es_s,None,None);
            log(IO_DEBUG,"Early secret= ",0,Some(es_s));

            self.send_message(HSHAKE,TLS1_2,&sh[0..shlen],None,true);
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
                log(IO_DEBUG,"Server is sending certificate request\n",-1,None);
                self.send_certificate_request(false);  // but don't flush - there is more to come
//
//   Server Certificate request ----------------------------------------------------------> 
//
            }

            let mut server_key:[u8;MAX_SIG_SECRET_KEY]=[0;MAX_SIG_SECRET_KEY];
            let mut server_certchain:[u8;MAX_SERVER_CHAIN_SIZE]=[0;MAX_SERVER_CHAIN_SIZE];   // assume max chain length of 2
            let mut scvsig:[u8;MAX_SIGNATURE_SIZE]=[0;MAX_SIGNATURE_SIZE];
            let mut sclen=0;
            let mut sklen=0;
            let kind=servercert::get_server_credentials(&mut server_key,&mut sklen,self.server_cert_type,&mut server_certchain,&mut sclen);
            if kind==0 { // No, Client cannot verify this signature
                self.send_alert(BAD_CERTIFICATE);
                log(IO_PROTOCOL,"Handshake failed - client would be unable to verify signature\n",-1,None);
                self.clean();
                return TLS_FAILURE;
            }

            log(IO_PROTOCOL,"Server is authenticating\n",-1,None);
            logger::log_sig_alg(kind);
            let sc_s=&server_certchain[0..sclen];
            let sk_s=&server_key[0..sklen];
            self.send_server_certificate(sc_s);
    //
    //
    //  {Server Certificate} ---------------------------------------------------->
    //
    //
            log(IO_DEBUG,"Server is sending certificate verifier\n",-1,None);
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
            log(IO_DEBUG,"Server is sending server Finished\n",-1,None);
            keys::derive_verifier_data(hash_type,shf_s,&self.sts[0..hlen],th_s);
            self.send_server_finish(shf_s);             
            self.transcript_hash(hh_s);
            log(IO_DEBUG,"Transcript Hash (CH+SH+EE+CT+SF) = ",0,Some(hh_s));   
    //
    //
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
                    if rtn.err<0 {
                        delayed_alert=rtn.err;
                    } else {
                        if self.bad_response(&rtn) {
                            return TLS_FAILURE;
                        }
                    }
                
                    log(IO_PROTOCOL,"Client is authenticating\n",-1,None); 
                    let cpk_s=&cpk[0..cpklen];
                    self.transcript_hash(fh_s);         
                    log(IO_DEBUG,"Certificate Chain is valid\n",-1,None);
                    log(IO_DEBUG,"Transcript Hash (CH+SH+EE+CT) = ",0,Some(fh_s));

                    let mut siglen=0;
                    let mut sigalg:u16=0;
                    rtn=self.get_client_cert_verify(&mut ccvsig,&mut siglen,&mut sigalg);
    //
    //
    //  <---------------------------------------------------- {Certificate Verify}
    //
    //
                    if rtn.err<0 {
                        if delayed_alert==0 {
                            delayed_alert=rtn.err;
                        }
                    } else {
                        if self.bad_response(&rtn) {
                            return TLS_FAILURE;
                        }
                    }
                    let ccvsig_s=&mut ccvsig[0..siglen];
                    self.transcript_hash(th_s);                                                //FH
                    log(IO_DEBUG,"Transcript Hash (CH+SH+EE+SCT+SCV) = ",0,Some(th_s));        //FH
                    log(IO_DEBUG,"Client Transcript Signature = ",0,Some(ccvsig_s));
                    logger::log_sig_alg(sigalg);
                    if !keys::check_client_cert_verifier(sigalg,ccvsig_s,fh_s,cpk_s) {         //TH
                        if delayed_alert==0 {
                            delayed_alert=BAD_CERT_CHAIN;
                        }
                        log(IO_DEBUG,"Client Cert Verification failed\n",-1,None);
                        log(IO_PROTOCOL,"Full Handshake will fail\n",-1,None);
                    } else {
                        let mut dn:[u8;256]=[0;256];
                        let n=utils::make_dn(&mut dn,&self.clientid[0..self.cidlen]);
                        log(IO_DEBUG,"Client Cert Verification OK - ",-1,Some(&dn[0..n]));   // **** output client full distinguished name     
                    }
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

        if rtn.err<0 {
            if delayed_alert==0 {
                delayed_alert=rtn.err;
            }
        } else {
            if self.bad_response(&rtn) {
                return TLS_FAILURE;
            }
        }      
    //
    //  <---------------------------------------------------- {Client finished}
    //
        log(IO_DEBUG,"Server receives client finished\n",-1,None);
        log(IO_DEBUG,"Client Verify Data= ",0,Some(&fin[0..fnlen])); 
        let fin_s=&fin[0..fnlen];

        let mut verified=false;
        if delayed_alert==0 { // only worth doing if there is no earlier alert
            verified=keys::check_verifier_data(hash_type,fin_s,&self.cts[0..hlen],th_s);
        }
        if !verified {  
            if delayed_alert==0 { // otherwise send earlier alert
                delayed_alert=FINISH_FAIL;
            }
// don't send alert now - haven't calculated traffic keys yet
            log(IO_PROTOCOL,"Client Data is NOT verified\n",-1,None);
        } else {
            if self.cidlen>0 { // got an identity
                let mut dn:[u8;256]=[0;256];
                let n=utils::make_dn(&mut dn,&self.clientid[0..self.cidlen]);
                log(IO_PROTOCOL,"Client Authenticated Identity - ",-1,Some(&dn[0..n]));
                self.client_authenticated=true;
            }
        }

        self.transcript_hash(fh_s);
        log(IO_DEBUG,"Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]+CF) = ",0,Some(fh_s));
// calculate traffic and application keys from handshake secret and transcript hashes

        self.derive_application_secrets(hh_s,fh_s,None);   // CF only impacts fh_s, and fh_s does not impact CTS or STS
        self.create_send_crypto_context();
        self.create_recv_crypto_context();

        log(IO_DEBUG,"Client application traffic secret= ",0,Some(&self.cts[0..hlen]));  // does not depend on CF!
        log(IO_DEBUG,"Server application traffic secret= ",0,Some(&self.sts[0..hlen]));  // does not depend on CF!

        if delayed_alert != 0 { // there was a problem, now send alert using traffic keys
            log(IO_PROTOCOL,"Handshake Failed - earlier alert now sent\n",-1,None);
            self.send_alert(alert_from_cause(delayed_alert));
            return TLS_FAILURE;
        }

        if resume {
            log(IO_PROTOCOL,"RESUMPTION handshake succeeded\n",-1,None);
        } else {
            log(IO_PROTOCOL,"FULL handshake succeeded\n",-1,None);
        }

        self.status=CONNECTED;
        return TLS_SUCCESS;
    }

/// Send a message post-handshake
    pub fn send(&mut self,mess: &[u8]) {
        self.send_message(APPLICATION,TLS1_2,mess,None,true);       
    }

// The recv() function processes records, and then returns control to the calling program only after an application record is received, or an error, or a time-out. 
// Handshake messages are all processed internally, and the function does not return
// Calling program can send closure alert any time it likes. We should wait for a closure response.
// Return value of 0 means we have received nothing and may have timed out. Calling program should send closure alert.
// If its an application record, return the message via a parameter, and its positive length as the return value. Calling program may then send closure alert.
// If its an error alert record, return error. Calling program should exit.
// If its a closure alert, respond with a closure alert and return error. Calling program should exit.
// If its a handshake record.... Need to loop on it until all included messages processed.
// Read in one full record at a time. Each handshake message pulls in more records until it gets to the end of its message. When I get to end of input buffer loop back for 
// whatever is next. For CERTIFICATE keep pulling in until FINISH message received.
// Keep reading until get to end of buffer.
// If its a KEY_UPDATE message,
// check for errors, if any return error code. Calling program exits.
// if its telling me that he has updated his keys, update mine, and loop to expect more input unless end of record reached.
// If its telling me that he has updated his keys, and I am to update mine, send him update request, update my keys, and loop to expect more input unless end of record reached.
// If its a CERTIFICATE message
// check for errors, if any return error code. Loop to expect CERT_VERIFY
// If its a CERT_VERIFY message
// check for errors, if any return error code. Loop to expect FINISH
// If its a FINISH message
// check for errors, if any return error code. Loop to expect more input unless end of record reached.
// Exit handshake loop when we get to end of current record.
// If an error is detected, send alert, return error code. Calling program should exit.
/// Process Client records received post-handshake.
/// Should be mostly application data, but could be more handshake data disguised as application data
// Keys might be updated.
// Could be post-handshake authentication from client
// returns +ve length of message, or negative error, or 0 for a time-out
    pub fn recv(&mut self,mess: &mut [u8]) -> isize {
        let mut fin=false;
        let mut kind:isize;
        let mut mslen:isize; 
        let hash_type=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(hash_type);
        let mut fh: [u8;MAX_HASH]=[0;MAX_HASH]; let fh_s=&mut fh[0..hlen];  // transcript hash
        let mut cpk: [u8; MAX_SIG_PUBLIC_KEY]=[0;MAX_SIG_PUBLIC_KEY];       // client public key
        let mut cpklen=0;
        log(IO_PROTOCOL,"Waiting for Client response\n",-1,None);
        loop {
            //log(IO_PROTOCOL,"Waiting for Client input\n",-1,None);
            self.clean_io();
            kind=self.get_record();  // get first fragment to determine type
            if kind<0 {
                self.send_alert(alert_from_cause(kind));
                return kind;   // its an error
            }
            if kind==TIMED_OUT as isize {
                log(IO_PROTOCOL,"TIME_OUT\n",-1,None);
                return 0;
            }
            if kind==HSHAKE as isize { // should check here for key update or certificate request
                let mut r:RET;
                loop { // get all expected handshake messages - they could all be bundled together
                    r=self.parse_int_pull(1); let nb=r.val; if r.err!=0 {break;}
                    self.ptr -= 1; // peek ahead - put it back
                    match nb as u8 {
                        KEY_UPDATE => {
                            r=self.parse_int_pull(1); if r.err!=0 {break;}
                            r=self.parse_int_pull(3); let len=r.val; if r.err!=0 {break;}   // message length
                            if len!=1 {
                                log(IO_PROTOCOL,"Something wrong\n",-1,None);
                                self.send_alert(DECODE_ERROR);
                                return BAD_RECORD;
                            } 
                            let htype=sal::hash_type(self.cipher_suite);
                            let hlen=sal::hash_len(htype);
                            r=self.parse_int_pull(1); let kur=r.val; if r.err!=0 {break;}
//println!("kur= {}",kur);
                            if kur==UPDATE_NOT_REQUESTED {  // reset record number
                                self.k_recv.update(&mut self.cts[0..hlen]);
                                log(IO_PROTOCOL,"RECEIVING KEYS UPDATED\n",-1,None);
                            }
                            if kur==UPDATE_REQUESTED {
                                self.k_recv.update(&mut self.cts[0..hlen]);
                                self.send_key_update(UPDATE_NOT_REQUESTED);  // tell client to update their receiving keys
                                log(IO_PROTOCOL,"SENDING KEYS UPDATED\n",-1,None);
                                log(IO_PROTOCOL,"Key update notified - client should do the same\n",-1,None);
                                log(IO_PROTOCOL,"RECEIVING KEYS UPDATED\n",-1,None);
                            }
                            if kur!=UPDATE_NOT_REQUESTED && kur!=UPDATE_REQUESTED {
                                log(IO_PROTOCOL,"Bad Request Update value\n",-1,None);
                                self.send_alert(ILLEGAL_PARAMETER);
                                return BAD_REQUEST_UPDATE;
                            }
                            if self.ptr==self.iblen {
                                fin=true;
                                self.rewind();
                            }
                            if !fin {continue;}
                        }
                        CERTIFICATE => {               // these handshake messages should come one after the other
                            if !self.requires_post_hs_auth() {
                                self.send_alert(UNEXPECTED_MESSAGE);
                                return WRONG_MESSAGE;
                            }
                            r=self.get_check_client_certificatechain(&mut cpk,&mut cpklen);            // get full name
    //
    //
    //  <---------------------------------------------------------- {Client Certificate}
    //
    //
                            if self.bad_response(&r) {
                                self.send_alert(DECODE_ERROR);
                                return BAD_MESSAGE;
                            }    
                            log(IO_PROTOCOL,"Client attempting to authenticate post-handshake\n",-1,None);  
                            self.transcript_hash(fh_s);  // get transcript hash following Handshake Context+Certificate
                            // don't exit - wait for cert verify
                        }
                        CERT_VERIFY => {
                            let mut ccvsig:[u8;MAX_SIGNATURE_SIZE]=[0;MAX_SIGNATURE_SIZE];
                            let mut siglen=0;
                            let mut sigalg:u16=0;
                            r=self.get_client_cert_verify(&mut ccvsig,&mut siglen,&mut sigalg);  
                            if self.bad_response(&r) {
                                self.send_alert(DECODE_ERROR);
                                return BAD_MESSAGE;
                            }

                            let ccvsig_s=&mut ccvsig[0..siglen];
                            let cpk_s=&cpk[0..cpklen];
                            if !keys::check_client_cert_verifier(sigalg,ccvsig_s,fh_s,cpk_s) { 
                                self.send_alert(DECRYPT_ERROR);
                                return CERT_VERIFY_FAIL;
                            }
                            self.transcript_hash(fh_s);  // get transcript hash following Handshake Context+Certificate+cert_verify
                            // don't exit - wait for finished
                        }
                        FINISHED => {
                            let mut fnlen=0;
                            let mut finish:[u8;MAX_HASH]=[0;MAX_HASH];
                            r=self.get_client_finished(&mut finish,&mut fnlen);     
                            if self.bad_response(&r) {
                                self.send_alert(DECODE_ERROR);
                                return BAD_MESSAGE;
                            }
                            let fin_s=&finish[0..fnlen];

                            let verified=keys::check_verifier_data(hash_type,fin_s,&self.cts[0..hlen],fh_s);
                            if !verified {  
                                self.send_alert(DECRYPT_ERROR);
                                return FINISH_FAIL;
                            }

                            if self.cidlen>0 {
                                let mut dn:[u8;256]=[0;256];
                                let n=utils::make_dn(&mut dn,&self.clientid[0..self.cidlen]);
                                log(IO_PROTOCOL,"Client Authenticated Identity - ",-1,Some(&dn[0..n])); 
                                self.client_authenticated=true;
                            }

                            if self.ptr==self.iblen { // OK now I can exit if nothing left
                                fin=true;
                                self.rewind();
                            }
                            if !fin {continue;}
                        }
                        _ => {
                            r=self.parse_int_pull(1); if r.err!=0 {break;}
                            r=self.parse_int_pull(3); let _len=r.val; if r.err!=0 {break;}   // message length
                            log(IO_PROTOCOL,"Unsupported Handshake message type ",nb as isize,None);
                            self.send_alert(UNEXPECTED_MESSAGE);
                            return WRONG_MESSAGE;
                        }
                    }
                    if fin {break;}
                }
                if r.err<0 {
                    self.send_alert(alert_from_cause(r.err));
                    return r.err;
                }
            }
            if kind==APPLICATION as isize { // exit only after we receive some application data
                self.ptr=self.iblen; // grab all of it
                let mut n=mess.len();
                if n>self.ptr { // truncate if not enough room for full record
                    n=self.ptr;
                }
                for i in 0..n {
                    mess[i]=self.ibuff[i];
                }
                mslen=n as isize;
                self.rewind();
                if n>0 {  //zero length application records can happen. Just ignore them.
                    break;
                }
            }
            if kind==HEART_BEAT as isize {
                mslen=0;
                let len=self.iblen;
                let mode=self.ibuff[0] as usize;
                let paylen=256*(self.ibuff[1] as usize)+(self.ibuff[2] as usize);
                if len>18+paylen && len<256 { // looks OK - ignore if too large
                    if mode==1 { // request 
                        if self.expect_heartbeats {
                            let mut resp: [u8;256]=[0;256];
                            resp[0]=2; // convert it to a response and bounce it back
                            for i in 1..paylen+3 {
                                resp[i]=self.ibuff[i];
                            }
                            for i in paylen+3..len {
                                resp[i]=sal::random_byte();
                            }
//println!("Received heart-beat request  - sending response");
                            self.send_record(HEART_BEAT,TLS1_2,&resp[0..len],true);
                        }
                    }
                    if mode==2 { // response
                        if self.heartbeat_req_in_flight && paylen==0 { // if I asked for one, and the payload length is zero
                            self.heartbeat_req_in_flight=false; // reset it
                            self.clean_io();
//println!("Received heart-beat response");
                            break; // better exit so link can be tested for liveness
                        }
                    }
                }
                self.clean_io();
            }
            if kind==ALERT as isize {
                log(IO_PROTOCOL,"*** Alert received - ",-1,None);
                logger::log_alert(self.ibuff[1]);
                if self.ibuff[1]==CLOSE_NOTIFY {
                    self.stop();  // send close notify
                    return CLOSURE_ALERT_RECEIVED; 
                } else {
                    return ERROR_ALERT_RECEIVED;
                }
            }
            // will continue to wait for some actual application data before exiting
        }
        return mslen; 
    }

/// Send a heart-beat request, and wait for an immediate response
// if heartbeats not permitted, same as recv()
#[allow(dead_code)]
    pub fn recv_and_check(&mut self,mess: &mut [u8]) -> isize {
        self.send_heartbeat_request();
        let r=self.recv(mess);
        if r!=0 { // its a regular response - line is alive, heartbeat response will come later and be ignored
            return r;
        }
// it may be heart-beat response that has been received, or we may just have timed out
        if self.heartbeat_req_in_flight { 
            self.status=DISCONNECTED;
            return TIME_OUT; // its not been reset, nothing received, line has gone dead
        }
        return 0; // its alive, but nothing has been received, go back and try again later. This parrot is not dead, its just resting.
    }

/// Clean up buffers, kill crypto keys
    pub fn clean(&mut self) {
        self.status=DISCONNECTED;
        self.ibuff.zeroize();
        self.cts.zeroize();
        self.sts.zeroize();
        self.hs.zeroize();
        self.rms.zeroize();
        self.k_send.clear();
        self.k_recv.clear();
    }

/// Clean out IO buffer
    fn clean_io(&mut self) {
        for i in 0..self.iblen {
            self.ibuff[i]=0;
        }  
        self.ptr=0;
        self.iblen=0;
    }
/// controlled stop
    pub fn stop(&mut self) {
        self.send_alert(CLOSE_NOTIFY);
    }
}
