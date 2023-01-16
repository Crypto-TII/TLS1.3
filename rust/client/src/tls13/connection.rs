
//! Main TLS1.3 protocol 

use std::net::{TcpStream};
use zeroize::Zeroize;

use crate::config::*;
use crate::sal_m::sal;
use crate::tls13::socket;
use crate::tls13::utils;
use crate::tls13::utils::RET;
use crate::tls13::utils::EESTATUS;
use crate::tls13::keys;
use crate::tls13::extensions;
use crate::tls13::certchain;
use crate::tls13::clientcert;
use crate::tls13::logger;
use crate::tls13::logger::log;
use crate::tls13::ticket;
use crate::tls13::ticket::TICKET;

/// TLS1.3 session structure
pub struct SESSION {
    pub status: usize,      // Connection status 
    max_record: usize,      // Server's max record size 
    pub sockptr: TcpStream, // Pointer to socket 
    iblen: usize,           // Input buffer length
    ptr: usize,             // Input buffer pointer - consumed portion
    session_id:[u8;32],     // legacy session ID
    pub hostname: [u8;MAX_SERVER_NAME],     // Server name for connection 
    pub hlen: usize,        // hostname length
    cipher_suite: u16,      // agreed cipher suite 
    favourite_group: u16,   // favourite key exchange group 
    k_send: keys::CRYPTO,   // Sending Key 
    k_recv: keys::CRYPTO,   // Receiving Key 
    server_cert_type: u8,   // expected server cert type
    client_cert_type: u8,   // expected client cert type
    hs: [u8;MAX_HASH],      // Handshake secret
    rms: [u8;MAX_HASH],     // Resumption Master Secret         
    sts: [u8;MAX_HASH],     // Server Traffic secret             
    cts: [u8;MAX_HASH],     // Client Traffic secret  
    ctx: [u8;MAX_HASH],     // certificate request context
    ctxlen: usize,          // context length 
    ibuff: [u8;MAX_IBUFF_SIZE], // Main input buffer for this connection 
    obuff: [u8;MAX_OBUFF_SIZE], // output buffer
    optr: usize,            // output buffer pointer
    tlshash: UNIHASH,       // Transcript hash recorder 
    pub t: TICKET           // resumption ticket    
}

/// check for overlap given server signature capabilities, and my client certificate
fn overlap(server_sig_algs: &[u16],server_cert_sig_algs: &[u16]) -> bool {
    let mut client_cert_reqs:[u16;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS];  
    let nsreq=clientcert::get_sig_requirements(&mut client_cert_reqs); 

    for i in 0..nsreq {
        let mut itsthere=false;
        let sig=client_cert_reqs[i];
        for j in 0..server_sig_algs.len() {
            if sig==server_sig_algs[j] {
                itsthere=true;
            }
        }
        for j in 0..server_cert_sig_algs.len() {
            if sig==server_cert_sig_algs[j] {
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
    pub fn new(stream: TcpStream,host: &str) -> SESSION  {
        let mut this=SESSION {
            status:DISCONNECTED,
            max_record: 0,
            sockptr: stream,
            iblen: 0,
            ptr: 0,
            session_id: [0;32],
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
            t: {TICKET{valid: false,tick: [0;MAX_TICKET_SIZE],nonce: [0;256],psk : [0;MAX_HASH],psklen: 0,tklen: 0,nnlen: 0,age_obfuscator: 0,max_early_data: 0,birth: 0,lifetime: 0,cipher_suite: 0,favourite_group: 0,origin: 0}}
        }; 
        let dst=host.as_bytes();
        this.hlen=dst.len();
        for i in 0..this.hlen {
            this.hostname[i]=dst[i];
        }
        return this;
    }

/// Get an integer of length len bytes from io stream
    fn parse_int_pull(&mut self,len:usize) -> RET {
        let mut r=utils::parse_int(&self.ibuff[0..self.iblen],len,&mut self.ptr);
        while r.err !=0 { // not enough bytes in IO - pull in another record
            let rtn=self.get_record();  // gets more stuff and increments iblen
            if rtn!=HSHAKE as isize {
                r.err=rtn;
                if rtn==ALERT as isize {
                    r.val=self.ibuff[1] as usize;
                }
                if rtn==APPLICATION as isize {
                    r.err=WRONG_MESSAGE;
                }
                break;
            }
            r=utils::parse_int(&self.ibuff[0..self.iblen],len,&mut self.ptr);
        }
        return r;
    }  
    
/// Pull bytes from io into array
    fn parse_bytes_pull(&mut self,e: &mut[u8]) -> RET {
        let mut r=utils::parse_bytes(e,&self.ibuff[0..self.iblen],&mut self.ptr);
        while r.err !=0 { // not enough bytes in IO - pull in another record
            let rtn=self.get_record();  // gets more stuff and increments iblen
            if rtn!=HSHAKE as isize  {
                r.err=rtn;
                if rtn==ALERT as isize {
                    r.val=self.ibuff[1] as usize;    // 0 is alert level, 1 is alert description
                }
                if rtn==APPLICATION as isize {
                    r.err=WRONG_MESSAGE;
                }
                break;
            }
            r=utils::parse_bytes(e,&self.ibuff[0..self.iblen],&mut self.ptr);
        }
        return r;
    }

/// Pull bytes into input buffer, process them there, in place
    fn parse_pull(&mut self,n: usize) -> RET { // get n bytes into self.io
        let mut r=RET{val:0,err:0};
        while self.ptr+n>self.iblen {
            let rtn=self.get_record();
            if rtn!=HSHAKE  as isize  {
                r.err=rtn;
                if rtn==ALERT as isize {
                    r.val=self.ibuff[1] as usize;    // 0 is alert level, 1 is alert description
                }
                if rtn==APPLICATION as isize {
                    r.err=WRONG_MESSAGE;
                }
                break;
            }
        }
        self.ptr += n;
        return r;
    }

/// Rewind iobuffer
    fn rewind(&mut self) {
        self.iblen=utils::shift_left(&mut self.ibuff[0..self.iblen],self.ptr); // rewind
        self.ptr=0;        
    }

/// Add I/O buffer self.io to transcript hash 
    fn running_hash_io(&mut self) {
        sal::hash_process_array(&mut self.tlshash,&self.ibuff[0..self.ptr]);
        self.rewind();
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

/// Special case handling for first clientHello after retry request
    fn running_synthetic_hash(&mut self,o: &[u8],e: &[u8]) {
        let htype=self.tlshash.htype; 
        let hlen=sal::hash_len(htype);
        let mut rhash=UNIHASH{state:[0;MAX_HASH_STATE],htype:0};
        let mut h:[u8;MAX_HASH]=[0;MAX_HASH];
        sal::hash_init(htype,&mut rhash);
// RFC 8446 - "special synthetic message"
        sal::hash_process_array(&mut rhash,o);
        sal::hash_process_array(&mut rhash,e);
        sal::hash_output(&rhash,&mut h);
        let t:[u8;4]=[MESSAGE_HASH,0,0,hlen as u8];
        sal::hash_process_array(&mut self.tlshash,&t);
        self.running_hash(&h[0..hlen]);
//        self.iblen=utils::shift_left(&mut self.ibuff[0..self.iblen],self.ptr); // rewind
//        self.ptr=0;
    }

/// Create a sending crypto context
    pub fn create_send_crypto_context(&mut self) {
        self.k_send.init(self.cipher_suite,&self.cts);
    }

/// Create a receiving crypto context
    pub fn create_recv_crypto_context(&mut self) {
        self.k_recv.init(self.cipher_suite,&self.sts);
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
        keys::hkdf_expand_label(htype,&mut ds[0..hlen],&mut self.hs[0..hlen],dr.as_bytes(),Some(&emh[0..hlen]));
        sal::hkdf_extract(htype,&mut ms[0..hlen],Some(&ds[0..hlen]),&zk[0..hlen]);
        keys::hkdf_expand_label(htype,&mut self.cts[0..hlen],&ms[0..hlen],ch.as_bytes(),Some(sfh));
        keys::hkdf_expand_label(htype,&mut self.sts[0..hlen],&ms[0..hlen],sh.as_bytes(),Some(sfh));

        if let Some(sems) = ems {
            let eh="exp master";
            keys::hkdf_expand_label(htype,&mut sems[0..hlen],&ms[0..hlen],eh.as_bytes(),Some(sfh));
        }
        keys::hkdf_expand_label(htype,&mut self.rms[0..hlen],&ms[0..hlen],rh.as_bytes(),Some(cfh));
    }

/// Recover Pre-Shared-Key from Resumption Master Secret
    fn recover_psk(&mut self) { 
        let rs="resumption";
        let htype=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(htype);
        keys::hkdf_expand_label(htype,&mut self.t.psk[0..hlen],&self.rms[0..hlen],rs.as_bytes(),Some(&self.t.nonce[0..self.t.nnlen]));
        self.t.psklen=hlen;
    }

    /// send one or more records, maybe encrypted.
    fn send_record(&mut self,rectype: u8,version: usize,data: &[u8],flush: bool) {
        let mut rh:[u8;5]=[0;5];  // record header
        for i in 0..data.len() {
            self.obuff[self.optr+5]=data[i];
            self.optr+=1;
            if self.optr==MAX_OUTPUT_RECORD_SIZE || (i==data.len()-1 && flush) { // block is full, or its the last one and we want to flush
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
                        ctlen=MAX_OUTPUT_RECORD_SIZE+1; // pad ciphertext to full length
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
                //for j in (0..reclen).rev() {
                //    self.obuff[j+5]=self.obuff[j];
                //}
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

/// Send a message - broken down into multiple records.
/// Message comes in two halves - cm and (optional) ext.
/// flush if end of pass, or change of key
    fn send_message(&mut self,rectype: u8,version: usize,cm: &[u8],ext: Option<&[u8]>,flush: bool) {
        if self.status==DISCONNECTED {
            return;
        }

        if let Some(sext) = ext {
            self.send_record(rectype,version,cm,false);
            self.send_record(rectype,version,sext,flush);
        } else {
            self.send_record(rectype,version,cm,flush);
        }

    }   

/// Send Client Hello
    pub fn send_client_hello(&mut self,version:usize,ch: &mut [u8],crn: &[u8],already_agreed: bool,ext: &[u8],extra: usize,resume: bool,flush: bool) -> usize {
        //let mut rn: [u8;32]=[0;32];
        let mut cs: [u8;2+2*MAX_CIPHER_SUITES]=[0;2+2*MAX_CIPHER_SUITES];
        let mut total=8;
        let mut ptr=0;
        let cm=0x0100;
        let extlen=ext.len()+extra;
        let mut ciphers: [u16;MAX_CIPHER_SUITES] = [0;MAX_CIPHER_SUITES];
        let mut nsc=sal::ciphers(&mut ciphers);
        if already_agreed { // cipher suite already agreed
            nsc=1;
            ciphers[0]=self.cipher_suite;
        }
        //sal::random_bytes(32,&mut rn);
        total+=32;
        if !resume {
            sal::random_bytes(32,&mut self.session_id);
        }   
        total+=33;
        let clen=extensions::cipher_suites(&mut cs,nsc,&ciphers);
        total+=clen;
        ptr=utils::append_byte(ch,ptr,CLIENT_HELLO,1);
        ptr=utils::append_int(ch,ptr,total+extlen-2,3);
        ptr=utils::append_int(ch,ptr,TLS1_2,2);
        ptr=utils::append_bytes(ch,ptr,crn);
        ptr=utils::append_int(ch,ptr,32,1);
        ptr=utils::append_bytes(ch,ptr,&self.session_id);
        ptr=utils::append_bytes(ch,ptr,&cs[0..clen]);
        ptr=utils::append_int(ch,ptr,cm,2);
        ptr=utils::append_int(ch,ptr,extlen,2);

        self.send_message(HSHAKE,version,&ch[0..ptr],Some(&ext),flush);
        return ptr;
    }

/// Send "binder",
    pub fn send_binder(&mut self,bnd: &[u8]) -> usize {
        let mut b:[u8;MAX_HASH+3]=[0;MAX_HASH+3];
        let tlen2=bnd.len()+1;  
        let mut ptr=0;
        ptr=utils::append_int(&mut b,ptr,tlen2,2);
        ptr=utils::append_int(&mut b,ptr,bnd.len(),1);
        ptr=utils::append_bytes(&mut b,ptr,bnd);
        self.running_hash(&b[0..ptr]);
        self.send_message(HSHAKE,TLS1_2,&b[0..ptr],None,true);
        return ptr;
    }

/// check for a bad response. If not happy with what received - send alert and close. If alert received from Server, log it and close.
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
            //if r.val==CLOSE_NOTIFY as usize {
		    //    self.send_alert(CLOSE_NOTIFY);  // I'm closing down, and so are you
            //}
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

/// Send an alert to the Server
    pub fn send_alert(&mut self,kind: u8) {
        let pt: [u8;2]=[0x02,kind];
        self.clean_io();
        self.send_message(ALERT,TLS1_2,&pt[0..2],None,true);
        if self.status != DISCONNECTED {
            log(IO_PROTOCOL,"Alert sent to Server - ",-1,None);
            logger::log_alert(kind);
        }
        self.status=DISCONNECTED;
    }

/// Send Change Cipher Suite - helps get past middleboxes (?)
    pub fn send_cccs(&mut self) {
        let cccs:[u8;6]=[0x14,0x03,0x03,0x00,0x01,0x01];
        //self.sockptr.write(&cccs).unwrap();
        socket::send_bytes(&mut self.sockptr,&cccs);
    }

/// Send Early Data
    pub fn send_end_early_data(&mut self) {
        let mut ed:[u8;4]=[0;4];
        let mut ptr=0;
        ptr=utils::append_byte(&mut ed,ptr,END_OF_EARLY_DATA,1);
        ptr=utils::append_int(&mut ed,ptr,0,3);
        self.running_hash(&ed[0..ptr]);
        self.send_message(HSHAKE,TLS1_2,&ed[0..ptr],None,true); // flush, because a change of key is about to happen
    }

/// Send Client Certificate
    fn send_client_certificate(&mut self,certchain: Option<&[u8]> ) {
        let mut pt:[u8;50]=[0;50];
        let mut ptr=0;
        ptr=utils::append_byte(&mut pt,ptr,CERTIFICATE,1);
        if let Some(chain) = certchain {
            ptr=utils::append_int(&mut pt,ptr,4+chain.len(),3);
            let nb=self.ctxlen;
            ptr=utils::append_int(&mut pt,ptr,nb,1);
            if nb>0 { // certificate context
                ptr=utils::append_bytes(&mut pt,ptr,&self.ctx[0..nb]);
            }
            ptr=utils::append_int(&mut pt,ptr,chain.len(),3);
            self.running_hash(&pt[0..ptr]);
            self.running_hash(chain);
        } else {
            ptr=utils::append_int(&mut pt,ptr,4,3);  
            let nb=self.ctxlen;
            ptr=utils::append_int(&mut pt,ptr,nb,1);
            if nb>0 { // certificate context
                ptr=utils::append_bytes(&mut pt,ptr,&self.ctx[0..nb]);
            }
            ptr=utils::append_int(&mut pt,ptr,0,3);
            self.running_hash(&pt[0..ptr]);
        }
        self.send_message(HSHAKE,TLS1_2,&pt[0..ptr],certchain,false); // don't flush, more to come
    }

/// Send Client Certificate Verify 
    fn send_client_cert_verify(&mut self, sigalg: u16,ccvsig: &[u8]) { 
        let mut pt:[u8;8]=[0;8];
        let mut ptr=0;
        ptr=utils::append_byte(&mut pt,ptr,CERT_VERIFY,1); // indicates handshake message "certificate verify"
        ptr=utils::append_int(&mut pt,ptr,4+ccvsig.len(),3); // .. and its length
        ptr=utils::append_int(&mut pt,ptr,sigalg as usize,2);
        ptr=utils::append_int(&mut pt,ptr,ccvsig.len(),2);
        self.running_hash(&pt[0..ptr]);
        self.running_hash(ccvsig);
        self.send_message(HSHAKE,TLS1_2,&pt[0..ptr],Some(ccvsig),false);  // don't flush, more to come
}

/// Send final client handshake verification data
    fn send_client_finish(&mut self,chf: &[u8]) {
        let mut pt:[u8;4]=[0;4];
        let mut ptr=0;
        ptr=utils::append_byte(&mut pt,ptr,FINISHED,1); // indicates handshake message "client finished"
        ptr=utils::append_int(&mut pt,ptr,chf.len(),3); // .. and its length
        self.running_hash(&pt[0..ptr]);
        self.running_hash(chf);
        self.send_message(HSHAKE,TLS1_2,&pt[0..ptr],Some(chf),true); // flush, client is finished
    }

/// Send Key update demand
    pub fn send_key_update(&mut self,kur: usize) {
        let mut up:[u8;5]=[0;5];
        let mut ptr=0;
        ptr=utils::append_byte(&mut up,ptr,KEY_UPDATE,1);  // message type
        ptr=utils::append_int(&mut up,ptr,1,3);      // message length
        ptr=utils::append_int(&mut up,ptr,kur,1);
        self.clean_io();
        self.send_message(HSHAKE,TLS1_2,&up[0..ptr],None,true);
        let htype=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(htype);
        self.k_send.update(&mut self.sts[0..hlen]);
        log(IO_PROTOCOL,"KEY UPDATE REQUESTED\n",-1,None);
    }

/// Build client's chosen set of extensions, and assert expectation of server responses.
/// The User may want to change the mix of optional extensions.
// mode=0 - full handshake
// mode=1 - resumption handshake
// mode=2 = External PSK handshake
    pub fn build_extensions(&self,ext: &mut [u8],pk: &[u8],expected: &mut EESTATUS,mode: usize) -> usize {
        let psk_mode=PSKWECDHE;
        let tls_version=TLS1_3;
        let protocol=APPLICATION_PROTOCOL;
        let alpn=protocol.as_bytes();
        let mut groups:[u16;MAX_SUPPORTED_GROUPS]=[0;MAX_SUPPORTED_GROUPS];
        let mut sig_algs:[u16;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS];
        let mut sig_alg_certs:[u16;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS];
        let mut nsg=sal::groups(&mut groups);
        let nsa=sal::sigs(&mut sig_algs);
        let nsac=sal::sig_certs(&mut sig_alg_certs);
        let mut extlen=0;
        if mode!=0 { // group already agreed
            nsg=1;
            groups[0]=self.favourite_group;
        }
        extlen=extensions::add_server_name(ext,extlen,&self.hostname,self.hlen); expected.server_name=true;
        extlen=extensions::add_supported_groups(ext,extlen,nsg,&groups);
        extlen=extensions::add_key_share(ext,extlen,self.favourite_group,pk);
        if TLS_PROTOCOL {
            extlen=extensions::add_alpn(ext,extlen,&alpn); expected.alpn=true;
        }
        extlen=extensions::add_psk(ext,extlen,psk_mode);
        extlen=extensions::add_version(ext,extlen,tls_version);
        if SET_RECORD_LIMIT {
            extensions::add_rsl(ext,extlen,MAX_INPUT_RECORD_SIZE);
        } else {
            if mode!=2 { // PSK mode has a problem with this (?)
                extlen=extensions::add_mfl(ext,extlen,MAX_FRAG); expected.max_frag_len=true;
            }
        }
        extlen=extensions::add_padding(ext,extlen,(sal::random_byte()%16) as usize);

        if mode==0 { // need some signature related extensions only for full handshake
            extlen=extensions::add_supported_sigs(ext,extlen,nsa,&sig_algs);
            extlen=extensions::add_supported_sigcerts(ext,extlen,nsac,&sig_alg_certs);        
            if PREFER_RAW_SERVER_PUBLIC_KEY {
                extlen=extensions::add_supported_server_cert_type(ext,extlen,RAW_PUBLIC_KEY);
            }
            if PREFER_RAW_CLIENT_PUBLIC_KEY {
                extlen=extensions::add_supported_client_cert_type(ext,extlen,RAW_PUBLIC_KEY);
            }
        }
        return extlen;
    }

/// Receive Server Certificate Verifier
    fn get_server_cert_verify(&mut self,scvsig: &mut [u8],siglen: &mut usize,sigalg: &mut u16) -> RET {
        //let mut ptr=0;

        let mut r=self.parse_int_pull(1); // get message type
        if r.err!=0 {return r;}
        let nb=r.val as u8;
        if nb != CERT_VERIFY {
            r.err=WRONG_MESSAGE;
            return r;
        }

        r=self.parse_int_pull(3); let left=r.val; if r.err!=0 {return r;} // find message length
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
        //left-=4+len;
        if left!=4+len {
            r.err=BAD_MESSAGE;
            return r;
        }
        *siglen=len;
        self.running_hash_io();
        //sal::hash_process_array(&mut self.tlshash,&self.ibuff[0..ptr]);
        //self.iblen=utils::shift_left(&mut self.ibuff[0..self.iblen],ptr);
        r.val=CERT_VERIFY as usize;
        return r;
    }

/// Receive Certificate Request - the Server wants the client to supply a certificate chain
// context is true if expecting a context
    fn get_certificate_request(&mut self,context: bool) -> RET {
        //let mut ptr=0;
        let mut unexp=0;
        let mut sigalgs:[u16;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS];
        let mut certsigalgs:[u16;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS];

        let mut r=self.parse_int_pull(1); // get message type
        if r.err!=0 {return r;}
        let nb=r.val as u8;
        if nb != CERT_REQUEST {
            r.err=WRONG_MESSAGE;
            return r;
        }

        r=self.parse_int_pull(3); let left=r.val; if r.err!=0 {return r;}
        r=self.parse_int_pull(1); let nb=r.val; if r.err!=0 {return r;}
        if context { // expecting a context
            let start=self.ptr;
            r=self.parse_pull(nb); if r.err!=0 {return r;}
            if nb==0 {
                r.err=MISSING_REQUEST_CONTEXT;// expecting a Request context
                return r;
            }
            for i in 0..nb {
                self.ctx[i]=self.ibuff[start+i];
            }
            self.ctxlen=nb;
        } else {
            if nb!=0 {
                r.err=MISSING_REQUEST_CONTEXT;// expecting 0x00 Request context
                return r;
            }
        }

        r=self.parse_int_pull(2); let mut len=r.val; if r.err!=0 {return r;} // length of extensions
 
        if left!=len+3 {
            r.err=BAD_MESSAGE;
            return r;
        }
       
        let mut nssa=0;
        let mut nscsa=0;
        while len>0 {
            r=self.parse_int_pull(2); let ext=r.val; if r.err!=0 {return r;}
            r=self.parse_int_pull(2); let tlen=r.val; if r.err!=0 {return r;}
            if len<tlen+4 {
                r.err=BAD_MESSAGE;
                return r;
            }
            len-=4+tlen;
            match ext {
                SIG_ALGS => {
                    r=self.parse_int_pull(2);  if r.err!=0 {return r;}
                    if malformed(r.val,MAX_SUPPORTED_SIGS) || tlen!=2+r.val {
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }
                    nssa=r.val/2;
                    for i in 0..nssa {
                        r=self.parse_int_pull(2); if r.err!=0 {return r;}
                        sigalgs[i]=r.val as u16;
                    }

                }

                SIG_ALGS_CERT => {
                    r=self.parse_int_pull(2);  if r.err!=0 {return r;}
                    if malformed(r.val,MAX_SUPPORTED_SIGS) || tlen!=2+r.val {
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }
                    nscsa=r.val/2;
                    for i in 0..nscsa {
                        r=self.parse_int_pull(2); if r.err!=0 {return r;}
                        certsigalgs[i]=r.val as u16;
                    }
                }

                _ => {
                    self.ptr+=tlen;
                    unexp+=1;
                }
            }
            if r.err!=0 {return r;}
        }
        self.running_hash_io();
        r.val=CERT_REQUEST as usize;
        if nssa==0 {
            r.err= MISSING_EXTENSIONS;
            return r;
        }
        if !overlap(&sigalgs[0..nssa],&certsigalgs[0..nscsa]) {
            log(IO_DEBUG,"Server cannot verify client certificate\n",-1,None);
            r.err=BAD_HANDSHAKE;
            return r;
        }
        if unexp>0 {
            log(IO_DEBUG,"Unrecognized extensions received\n",-1,None);
        }
        return r;
    }

/// Get handshake finish verifier data in hfin
    fn get_server_finished(&mut self,hfin: &mut [u8],hflen: &mut usize) -> RET {
        //let mut ptr=0;

        let mut r=self.parse_int_pull(1); // get message type
        if r.err!=0 {return r;}
        let nb=r.val as u8;
        if nb != FINISHED {
            r.err=WRONG_MESSAGE;
            return r;
        }

        let htype=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(htype);

        r=self.parse_int_pull(3); let len=r.val; if r.err!=0 {return r;}
        r=self.parse_bytes_pull(&mut hfin[0..hlen]); if r.err!=0 {return r;}
        *hflen=hlen;
        if len!=hlen {
            r.err=BAD_MESSAGE;
        }
        self.running_hash_io();
        r.val=FINISHED as usize;
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
        if rh[0]==ALERT {
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
            if !socket::get_bytes(&mut self.sockptr,&mut rh[0..3]) {  // ignore it and carry on
                return TIMED_OUT as isize;
            }
        }
        if rh[0]!=HSHAKE && rh[0]!=APPLICATION {
            return WRONG_MESSAGE;
        }
        let left=socket::get_int16(&mut self.sockptr);
        if left>MAX_CIPHER_FRAG {
            return MAX_EXCEEDED;
        }
        utils::append_int(&mut rh,3,left,2);
        if left+pos>self.ibuff.len() { // this commonly happens with big records of application data from server
            return MEM_OVERFLOW;    // record is too big - memory overflow
        }
        if !self.k_recv.is_active() { // not encrypted

// if not encrypted and rh[0] == APPLICATION, thats an error!

            if rh[0]==APPLICATION {
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
        if !socket::get_bytes(&mut self.sockptr,&mut tag[0..taglen]) {
            return TIMED_OUT as isize;
        }
        let success=sal::aead_decrypt(&self.k_recv,&rh,&mut self.ibuff[pos..pos+rlen],&tag[0..taglen]);
        if !success {
            return AUTHENTICATION_FAILURE;
        }
        self.k_recv.increment_crypto_context();
// get record ending - encodes real (disguised) record type. Could be an Alert.        
        let mut lb=self.ibuff[self.iblen-1];
        self.iblen -= 1; rlen -=1; // remove it
        while lb==0 && rlen>0 {
            lb=self.ibuff[self.iblen-1];
            self.iblen -= 1; rlen -= 1;// remove it
        }

        if rlen>MAX_PLAIN_FRAG {
            return MAX_EXCEEDED;
        }
        if (lb == HSHAKE || lb == ALERT) && rlen==0 {
            return WRONG_MESSAGE; // Implementations MUST NOT send zero-length fragments of Handshake types
        }
        if lb == HSHAKE {
            return HSHAKE as isize;
        }
        if lb == APPLICATION {
            return APPLICATION as isize;
        }
        if lb==ALERT { // Alert record received, delete anything in IO prior to alert, and just return 2-byte alert
            self.iblen=utils::shift_left(&mut self.ibuff[0..self.iblen],pos); // rewind
            return ALERT as isize;
        }
        return WRONG_MESSAGE;
    }

/// Get (unencrypted) Server Hello
    fn get_server_hello(&mut self,kex: &mut u16,cookie: &mut [u8],cklen:&mut usize,pk: &mut [u8],pskid: &mut isize) -> RET {
        let mut srn: [u8;32]=[0;32];
        let mut sid: [u8;32]=[0;32];
        let mut hrr: [u8; HRR.len()/2]=[0;HRR.len()/2];
        utils::decode_hex(&mut hrr,&HRR);
        //let mut ptr=0;

        self.ptr=0;  
        self.iblen=0;
        let mut r=self.parse_int_pull(1);  if r.err!=0 {return r;} 
        if r.val!=SERVER_HELLO as usize { // should be Server Hello

            r.err=BAD_HELLO;
            return r;
        }

        r=self.parse_int_pull(3); let mut left=r.val; if r.err!=0 {return r;} // If not enough, pull in another fragment
        r=self.parse_int_pull(2); /*let svr=r.val;*/ if r.err!=0 {return r;}
   
        if left<72 {
            r.err=BAD_HELLO;
            return r;
        }

        left-=2;                // whats left in message
        r= self.parse_bytes_pull(&mut srn); if r.err!=0 {return r;}
        left-=32;
        let mut retry=false;
        if srn==hrr {
            retry=true;
        }
        r=self.parse_int_pull(1); if r.err!=0 {return r;}
        let silen=r.val; 
        if silen!=32 { 
            r.err=BAD_HELLO;
            return r;
        }
 
        left-=1;
        r=self.parse_bytes_pull(&mut sid[0..silen]); if r.err!=0 {return r;}
        left-=silen;  
        if self.session_id!=sid {
            r.err=ID_MISMATCH;
            return r;
        }
        r=self.parse_int_pull(2); let cipher=r.val as u16; if r.err!=0 {return r;}
        left-=2;
	    if self.cipher_suite!=0 { // don't allow a change after initial assignment
		    if cipher!=self.cipher_suite
		    {
			    r.err=BAD_HELLO;
			    return r;
		    }
	    }
	    self.cipher_suite=cipher;
        r=self.parse_int_pull(1); let cmp=r.val; if r.err!=0 {return r;}
        left-=1; // Compression not used in TLS1.3
        if cmp!=0  { 
            r.err=NOT_TLS1_3;  // don't ask
            return r;
        }
        r=self.parse_int_pull(2); let extlen=r.val; if r.err!=0 {return r;}
        left-=2;  
        if left!=extlen { // Check space left is size of extensions
            r.err=BAD_HELLO;
            return r;
        }

        let mut supported_version=0;
        while left>0 {
            r=self.parse_int_pull(2); let ext=r.val; if r.err!=0 {return r;} 
            r=self.parse_int_pull(2); let extlen=r.val; if r.err!=0 {return r;} 
            if extlen+2>left {r.err=BAD_MESSAGE;return r;}
            if left<4+extlen {
                r.err=BAD_HELLO;
                return r;
            }
            left-=4+extlen;
            match ext {
                KEY_SHARE => {
                    let mut glen=2;
                    r=self.parse_int_pull(2); *kex=r.val as u16; if r.err!=0 {return r;}
                    if !retry { // its not a retry request
                        r=self.parse_int_pull(2); let pklen=r.val; if r.err!=0 {return r;}
                        if pklen!=pk.len() {
                            r.err=BAD_HELLO;
                            return r;
                        }
                        r=self.parse_bytes_pull(pk);
                        glen+=2+pklen;
                    }
                    if extlen!=glen {
                        r.err=BAD_HELLO;
                        return r;
                    }
                },
                PRESHARED_KEY => {
                    if extlen!=2 {
                        r.err=BAD_HELLO;
                        return r;
                    }
                    r=self.parse_int_pull(2); *pskid=r.val as isize;
                },
                COOKIE => {
                    r=self.parse_bytes_pull(&mut cookie[0..extlen]); *cklen=extlen;
                },
                TLS_VER => {
                    if extlen!=2 {
                        r.err=BAD_HELLO;
                        return r;
                    }
                    r=self.parse_int_pull(2); let tls=r.val; if r.err!=0 {return r;}
                    supported_version=tls;
                },
                _ => {
                    r.err=UNRECOGNIZED_EXT;
                }
            }
            if r.err!=0 {return r;}
        }
        if supported_version==0 || supported_version!=TLS1_3 {
            r.err=NOT_TLS1_3;
        }
        if retry {
            r.val=HANDSHAKE_RETRY;
        } else {
            r.val=SERVER_HELLO as usize;
        }
        return r;
    }

// Handshake Messages start with TYPE|<- LEN -> where TYPE is a byte, and LEN is 24 bits
/// Peek ahead for the type of message in order to decide what to do next
// Important to include TYPE in the transcript hash
// See whats coming next
    fn see_whats_next(&mut self) -> RET {
        //let mut ptr=0;
        let mut r=self.parse_int_pull(1);
        if r.err!=0 {return r;}
        self.ptr -= 1;  // put it back
        let nb=r.val as u8;
        if nb==END_OF_EARLY_DATA || nb==KEY_UPDATE { // Servers MUST NOT send this.... KEY_UPDATE should not happen at this stage
            r.err=WRONG_MESSAGE;
            return r;
        }
        return r;
    }

/// Process server's encrypted extensions
    pub fn get_server_encrypted_extensions(&mut self,expected: &EESTATUS,response: &mut EESTATUS) -> RET {
        let mut unexp=0;

        let mut r=self.parse_int_pull(1); // get message type
        if r.err!=0 {return r;}
        let nb=r.val as u8;
        if nb != ENCRYPTED_EXTENSIONS {
            r.err=WRONG_MESSAGE;
            return r;
        }

        r=self.parse_int_pull(3); let left=r.val;  if r.err!=0 {return r;}  // get message length
        response.early_data=false;
        response.alpn=false;
        response.server_name=false;
        response.max_frag_len=false;

        r=self.parse_int_pull(2); let mut len=r.val; if r.err!=0 {return r;}

        if left!=len+2 {
            r.err=BAD_MESSAGE;
            return r;
        }
        //left-=2;
// extension could include Servers preference for supported groups, which could be
// taken into account by the client for later connections. Here we will ignore it. From RFC:
// "Clients MUST NOT act upon any information found in "supported_groups" prior to successful completion of the handshake"
        
        while len!=0 {
            r=self.parse_int_pull(2); let ext=r.val; if r.err!=0 {return r;}
            r=self.parse_int_pull(2); let tlen=r.val; if r.err!=0 {return r;}
            if len<tlen+4 {
                r.err=BAD_MESSAGE;
                return r;
            }
            len-=tlen+4;
            match ext {
                EARLY_DATA => {
                    if tlen!=0 {
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }
                    response.early_data=true;
                    if !expected.early_data {
                        r.err=NOT_EXPECTED;
                        return r;
                    }
                },
                MAX_FRAG_LENGTH => {
                    r=self.parse_int_pull(1); let mfl=r.val; if r.err!=0 {return r;}
                    if tlen !=1 || mfl!=MAX_FRAG {
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }
                    response.max_frag_len=true;
                    if !expected.max_frag_len {
                        r.err=NOT_EXPECTED;
                    }
                },
                CLIENT_CERT_TYPE => {
                    r=self.parse_int_pull(1); let cct=r.val as u8; if r.err!=0 {return r;}
                    if tlen!=1 { 
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }
                    if cct!=RAW_PUBLIC_KEY || !PREFER_RAW_CLIENT_PUBLIC_KEY { 
                        self.client_cert_type=X509_CERT;
                    } else { 
                        self.client_cert_type=RAW_PUBLIC_KEY;
                    }
                },
                SERVER_CERT_TYPE => {
                    r=self.parse_int_pull(1); let sct=r.val as u8; if r.err!=0 {return r;}
                    if tlen!=1 { 
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }    
                    if sct!=RAW_PUBLIC_KEY || !PREFER_RAW_SERVER_PUBLIC_KEY { 
                        self.server_cert_type=X509_CERT;
                    } else {
                        self.server_cert_type=RAW_PUBLIC_KEY;
                    }
                },
                RECORD_SIZE_LIMIT => {
                    r=self.parse_int_pull(2); let mfl=r.val; if r.err!=0 {return r;}
                    if tlen!=2 || mfl<64 {
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }
                    self.max_record=mfl;
                },
                APP_PROTOCOL => {
                    let mut name:[u8;256]=[0;256];
                    r=self.parse_int_pull(2); let xlen=r.val; if r.err!=0 {return r;}
                    r=self.parse_int_pull(1); let mfl=r.val; if r.err!=0 {return r;}
			        if tlen!=xlen+2 || xlen!=mfl+1 {
                        r.err=UNRECOGNIZED_EXT;
                        return r;
			        }
                    r=self.parse_bytes_pull(&mut name[0..mfl]); if r.err!=0 {return r;}
                    response.alpn=true;
                    if !expected.alpn {
                        r.err=NOT_EXPECTED;
                        return r;
                    }
                },
                SERVER_NAME => {
                    response.server_name=true;
                    if tlen!=0 {
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }
                    if !expected.server_name {
                        r.err=NOT_EXPECTED;
                        return r;
                    }
                },
                SIG_ALGS | SIG_ALGS_CERT | KEY_SHARE | PSK_MODE |  PRESHARED_KEY | TLS_VER | COOKIE | PADDING => {
                    self.ptr +=tlen; // skip over it
                    r.err=FORBIDDEN_EXTENSION;
                    return r;
                },
                _ => {
                    self.ptr +=tlen; // skip over it
                    unexp+=1;
                }
            }
            if r.err!=0 {return r;}
        }
// Update Transcript hash and rewind IO buffer
        self.running_hash_io();

        if unexp>0 {
            r.err=UNRECOGNIZED_EXT;
        }
        r.val=nb as usize;

        return r;
    }

/// Get certificate chain, and check its validity 
    pub fn get_check_server_certificatechain(&mut self,spk:&mut [u8],spklen: &mut usize) -> RET {
        let mut r=self.parse_int_pull(1); // get message type
        if r.err!=0 {return r;}
        let nb=r.val as u8;
        if nb != CERTIFICATE {
            r.err=WRONG_MESSAGE;
            return r;
        }

        r=self.parse_int_pull(3); let len=r.val; if r.err!=0 {return r;}         // message length   
	    if len==0 {
		    r.err=EMPTY_CERT_CHAIN;
		    return r;
	    }
        log(IO_DEBUG,"Certificate Chain Length= ",len as isize,None);
        r=self.parse_int_pull(1); let rc=r.val; if r.err!=0 {return r;} 
        if rc!=0x00 {
            r.err=MISSING_REQUEST_CONTEXT;// expecting 0x00 Request context
            return r;
        }
        r=self.parse_int_pull(3); let tlen=r.val; if r.err!=0 {return r;}   // get length of certificate chain

	    if tlen==0 {
		    r.err=EMPTY_CERT_CHAIN;
		    return r;
	    }
	    if tlen+4!=len {
		    r.err=BAD_CERT_CHAIN;
		    return r;
	    }
        let start=self.ptr;
        r=self.parse_pull(tlen); if r.err!=0 {return r;} // get pointer to certificate chain, and pull it all into self.ibuff
// Update Transcript hash

        let mut identity:[u8;MAX_X509_FIELD]=[0;MAX_X509_FIELD];    // extracting cert identity - but not sure what to do with it!
        let mut idlen=0;

        r.err=certchain::check_certchain(&self.ibuff[start..start+tlen],Some(&self.hostname[0..self.hlen]),self.server_cert_type,spk,spklen,&mut identity,&mut idlen);

        if self.server_cert_type == RAW_PUBLIC_KEY {
            log(IO_DEBUG,"WARNING - server is authenticating with raw public key\n",-1,None);
        } 
        log(IO_DEBUG,"Server Public Key= ",0,Some(&spk[0..*spklen]));

        if NO_CERT_CHECKS {
            r.err=0;
        }
        self.running_hash_io();

        r.val=CERTIFICATE as usize;
        return r;
    }

/// Clean up buffers, kill crypto keys
    pub fn clean(&mut self) {

        self.status=DISCONNECTED;
        self.ibuff.zeroize();
        self.hs.zeroize();
        self.cts.zeroize();
        self.sts.zeroize();
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

/// TLS1.3 RESUMPTION handshake. Can optionally start with some early data
    pub fn tls_resume(&mut self,early: Option<&[u8]>) -> usize {
        let mut expected=EESTATUS{early_data:false,alpn:false,server_name:false,max_frag_len:false};
        let mut response=EESTATUS{early_data:false,alpn:false,server_name:false,max_frag_len:false};
        let mut have_early_data=false;
        log(IO_PROTOCOL,"Attempting Resumption Handshake\n",-1,None);
        logger::log_ticket(&self.t); 

        let mut ext:[u8;MAX_EXTENSIONS]=[0;MAX_EXTENSIONS];
        let mut ch: [u8; MAX_HELLO] = [0; MAX_HELLO]; 
        let mut csk: [u8;MAX_KEX_SECRET_KEY]=[0;MAX_KEX_SECRET_KEY];  // client key exchange secret key
        let mut cpk: [u8;MAX_KEX_PUBLIC_KEY]=[0;MAX_KEX_PUBLIC_KEY];  // client key exchange public key
        let mut spk: [u8; MAX_KEX_CIPHERTEXT]=[0;MAX_KEX_CIPHERTEXT]; // server key exchange public key/ciphertext
        let mut ss: [u8;MAX_SHARED_SECRET_SIZE]=[0;MAX_SHARED_SECRET_SIZE];
        let mut cookie: [u8;MAX_COOKIE]=[0;MAX_COOKIE];
        let mut crn: [u8;32]=[0;32];

// Extract Ticket parameters
        let age_obfuscator=self.t.age_obfuscator;
        let max_early_data=self.t.max_early_data;
        let time_ticket_received=self.t.birth;
        self.cipher_suite=self.t.cipher_suite;
        self.favourite_group=self.t.favourite_group;
        let origin=self.t.origin;

        if TRY_EARLY_DATA && max_early_data>0 {
            if let Some(_) = early {
                have_early_data=true; // early data allowed - and I have some
            }
        }

        let htype=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(htype);

// extract slices.. Depends on cipher suite
        let mut hh: [u8;MAX_HASH]=[0;MAX_HASH]; let hh_s=&mut hh[0..hlen];
        let mut fh: [u8;MAX_HASH]=[0;MAX_HASH]; let fh_s=&mut fh[0..hlen];
        let mut th: [u8;MAX_HASH]=[0;MAX_HASH]; let th_s=&mut th[0..hlen];
        let mut bk:[u8;MAX_HASH]=[0;MAX_HASH]; let bk_s=&mut bk[0..hlen];
        let mut es:[u8;MAX_HASH]=[0;MAX_HASH]; let es_s=&mut es[0..hlen];
        let mut bnd:[u8;MAX_HASH]=[0;MAX_HASH]; let bnd_s=&mut bnd[0..hlen];
        let mut cets:[u8;MAX_HASH]=[0;MAX_HASH]; let cets_s=&mut cets[0..hlen];
        let mut chf:[u8;MAX_HASH]=[0;MAX_HASH]; let chf_s=&mut chf[0..hlen];
        let mut psk:[u8;MAX_HASH]=[0;MAX_HASH]; 
 
        for i in 0..self.t.psklen {
            psk[i]=self.t.psk[i];
        }
        let psk_s=&mut psk[0..self.t.psklen];

        self.init_transcript_hash();
        let external_psk:bool;
        if origin==EXTERNAL_PSK { //time_ticket_received==0 && age_obfuscator==0 { // its an external PSK
            external_psk=true;
            keys::derive_early_secrets(htype,Some(psk_s),es_s,Some(bk_s),None);
        } else {
            external_psk=false;
            keys::derive_early_secrets(htype,Some(psk_s),es_s,None,Some(bk_s));   // compute early secret and Binder Key from PSK
        }
        log(IO_DEBUG,"PSK= ",0,Some(psk_s)); 
        log(IO_DEBUG,"Binder Key= ",0,Some(bk_s)); 
        log(IO_DEBUG,"Early Secret= ",0,Some(es_s));

// Generate key pair in favourite group - use same favourite group that worked before for this server - so should be no HRR
        let sklen=sal::secret_key_size(self.favourite_group);   // may change on a handshake retry
        let sslen=sal::shared_secret_size(self.favourite_group);
        let mut pklen=sal::client_public_key_size(self.favourite_group);
        let mut pk_s=&mut cpk[0..pklen];
        let csk_s=&mut csk[0..sklen];
        let ss_s=&mut ss[0..sslen];
        sal::generate_key_pair(self.favourite_group,csk_s,pk_s);
        log(IO_DEBUG,"Private Key= ",0,Some(csk_s));
        log(IO_DEBUG,"Client Public Key= ",0,Some(pk_s));

// Client Hello
        sal::random_bytes(32,&mut crn);
// First build standard client Hello extensions
        let mut resmode=1;
        if origin==EXTERNAL_PSK {
            resmode=2;
        }
	    let mut extlen=self.build_extensions(&mut ext,pk_s,&mut expected,resmode);
        if have_early_data {
            extlen=extensions::add_early_data(&mut ext,extlen); expected.early_data=true;                 // try sending client message as early data if allowed
        }
        if POST_HS_AUTH {
            extlen=extensions::add_post_handshake_auth(&mut ext, extlen); // willing to do post handshake authentication
        }
        let mut age=0;
        if !external_psk { // Its NOT an external pre-shared key
            let time_ticket_used=ticket::millis();
            age=time_ticket_used-time_ticket_received; // age of ticket in milliseconds - problem for some sites which work for age=0 ??
            log(IO_DEBUG,"Ticket age= ",age as isize,None);
            age+=age_obfuscator;
            log(IO_DEBUG,"obfuscated age = ",age as isize,None);
        }
        let mut extra=0;
        extlen=extensions::add_presharedkey(&mut ext,extlen,age,&self.t.tick[0..self.t.tklen],hlen,&mut extra);

// create and send Client Hello octad
        let chlen=self.send_client_hello(TLS1_2,&mut ch,&crn,true,&ext[0..extlen],extra,false,false);  // don't transmit just yet - wait for binders
//
//
//   ----------------------------------------------------------> client Hello
//
//
        self.running_hash(&ch[0..chlen]); 
        self.running_hash(&ext[0..extlen]);
        self.transcript_hash(hh_s); // hh = hash of Truncated clientHello
        log(IO_DEBUG,"Hash of Truncated client Hello",0,Some(hh_s));
        
        keys::derive_verifier_data(htype,bnd_s,bk_s,hh_s);  
        self.send_binder(bnd_s);
        log(IO_DEBUG,"Client Hello + Binder sent\n",-1,None);
//  -----------------------------------------------------------> rest of client Hello
        self.transcript_hash(hh_s); // hh = hash of complete clientHello
        log(IO_DEBUG,"Hash of Completed client Hello",0,Some(hh_s));
        log(IO_DEBUG,"Binder= ",0,Some(bnd_s));

        if have_early_data {
            self.send_cccs();
        }

        keys::derive_later_secrets(htype,es_s,hh_s,Some(cets_s),None);   // Get Client Later Traffic Secret from transcript hash and ES
        log(IO_DEBUG,"Client Early Traffic Secret= ",0,Some(cets_s)); 
        self.k_send.init(self.cipher_suite,cets_s);

// if its allowed, send client message as (encrypted!) early data
        if have_early_data {
            if let Some(searly) = early {
                log(IO_APPLICATION,"Sending some early data\n",-1,None);
                self.send_message(APPLICATION,TLS1_2,searly,None,true);
//
//
//   ----------------------------------------------------------> (Early Data)
//
//
            }
        }
// Process Server Hello
        pklen=sal::server_public_key_size(self.favourite_group);
        pk_s=&mut spk[0..pklen];
        let mut kex=0;
        let mut pskid:isize=-1;
        let mut cklen=0;
        let mut rtn = self.get_server_hello(&mut kex,&mut cookie,&mut cklen,pk_s,&mut pskid);

        if self.bad_response(&rtn) {
            return TLS_FAILURE;
        }   
//
//
//  <---------------------------------------------------------- server Hello
//
//
        self.running_hash_io();         // Hashing Server Hello
        self.transcript_hash(hh_s);     // HH = hash of clientHello+serverHello
        if pskid<0 { // Ticket rejected by Server (as out of date??)
            log(IO_PROTOCOL,"Ticket rejected by server\n",-1,None);
            log(IO_PROTOCOL,"Resumption Handshake failed\n",-1,None);
            self.clean();
            return TLS_FAILURE;
        }

	    if pskid>0 { // pskid out-of-range (only one allowed)
            self.send_alert(ILLEGAL_PARAMETER);
            log(IO_PROTOCOL,"Resumption Handshake failed\n",-1,None);
            self.clean();
            return TLS_FAILURE;
	    }

        logger::log_server_hello(self.cipher_suite,pskid,pk_s,&cookie[0..cklen]);
        logger::log_key_exchange(IO_PROTOCOL,kex);

        if rtn.val==HANDSHAKE_RETRY || kex!=self.favourite_group { // should not happen
            self.send_alert(UNEXPECTED_MESSAGE);
            log(IO_DEBUG,"No change possible as result of HRR\n",-1,None); 
            log(IO_PROTOCOL,"Resumption Handshake failed\n",-1,None);
            self.clean();
            return TLS_FAILURE;
        }

// Generate Shared secret SS from Client Secret Key and Server's Public Key
        let nonzero=sal::generate_shared_secret(kex,csk_s,pk_s,ss_s); 
        if !nonzero {
            self.send_alert(ILLEGAL_PARAMETER);
            self.clean();
            return TLS_FAILURE;
        }
        log(IO_DEBUG,"Shared Secret= ",0,Some(ss_s));

        self.derive_handshake_secrets(ss_s,es_s,hh_s); 
        self.create_recv_crypto_context();

        log(IO_DEBUG,"Handshake Secret= ",0,Some(&self.hs[0..hlen]));
        log(IO_DEBUG,"Client handshake traffic secret= ",0,Some(&self.cts[0..hlen]));
        log(IO_DEBUG,"Server handshake traffic secret= ",0,Some(&self.sts[0..hlen]));

        rtn=self.get_server_encrypted_extensions(&expected,&mut response);
//
//
//  <------------------------------------------------- {Encrypted Extensions}
//
//
        if self.bad_response(&rtn) {
            return TLS_FAILURE;
        }
        logger::log_enc_ext(&expected,&response);
        self.transcript_hash(fh_s);
        log(IO_DEBUG,"Encrypted extensions processed\n",-1,None);

        let mut fnlen=0;
        let mut fin:[u8;MAX_HASH]=[0;MAX_HASH];
        rtn=self.get_server_finished(&mut fin,&mut fnlen);
//
//
//  <------------------------------------------------------ {Server Finished}
//
//
        let fin_s=&fin[0..fnlen];
        if self.bad_response(&rtn) {
            return TLS_FAILURE;
        }
        log(IO_DEBUG,"Server Finished Message Received - ",0,Some(fin_s));
// Now indicate End of Early Data, encrypted with 0-RTT keys
        self.transcript_hash(hh_s); // hash of clientHello+serverHello+encryptedExtension+serverFinish
        if response.early_data {
            self.send_end_early_data();     // Should only be sent if server has accepted Early data - see encrypted extensions!
            log(IO_DEBUG,"Send End of Early Data \n",-1,None);
        }
        self.transcript_hash(th_s); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData
        log(IO_DEBUG,"Transcript Hash (CH+SH+EE+SF+ED) = ",0,Some(th_s)); 

// Switch to handshake keys
        self.create_send_crypto_context();
        if !keys::check_verifier_data(htype,fin_s,&self.sts[0..hlen],fh_s) {
            self.send_alert(DECRYPT_ERROR);
            log(IO_DEBUG,"Server Data is NOT verified\n",-1,None);
            log(IO_PROTOCOL,"Resumption Handshake failed\n",-1,None);
            self.clean();
            return TLS_FAILURE;
        }

        keys::derive_verifier_data(htype,chf_s,&self.cts[0..hlen],th_s);
        self.send_client_finish(chf_s);
//
//
//  {client Finished} ----------------------------------------------------->
//
//
        log(IO_DEBUG,"Server Data is verified\n",-1,None);
        log(IO_DEBUG,"Client Verify Data= ",0,Some(chf_s)); 

        self.transcript_hash(fh_s); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData+clientFinish

// calculate traffic and application keys from handshake secret and transcript hashes, and store in session

        self.derive_application_secrets(hh_s,fh_s,None);
        self.create_send_crypto_context();
        self.create_recv_crypto_context();

        log(IO_DEBUG,"Client application traffic secret= ",0,Some(&self.cts[0..hlen]));
        log(IO_DEBUG,"Server application traffic secret= ",0,Some(&self.sts[0..hlen]));
        log(IO_PROTOCOL,"RESUMPTION Handshake succeeded\n",-1,None);
        self.clean_io();

        if response.early_data {
            log(IO_PROTOCOL,"Application Message accepted as Early Data\n\n",-1,early);
            return TLS_EARLY_DATA_ACCEPTED;
        }
        return TLS_SUCCESS;
    }

/// Exchange Client/Server "Hellos"
    fn exchange_hellos(&mut self) -> usize {
        let mut groups:[u16;MAX_SUPPORTED_GROUPS]=[0;MAX_SUPPORTED_GROUPS];
        let mut ciphers:[u16;MAX_CIPHER_SUITES]=[0;MAX_CIPHER_SUITES];
        let nsg=sal::groups(&mut groups);
        let nsc=sal::ciphers(&mut ciphers);
        let mut resumption_required=false;
        let mut expected=EESTATUS{early_data:false,alpn:false,server_name:false,max_frag_len:false};
        let mut response=EESTATUS{early_data:false,alpn:false,server_name:false,max_frag_len:false};
        let mut ch: [u8; MAX_HELLO] = [0; MAX_HELLO]; 
        let mut csk: [u8;MAX_KEX_SECRET_KEY]=[0;MAX_KEX_SECRET_KEY];
        let mut cpk: [u8;MAX_KEX_PUBLIC_KEY]=[0;MAX_KEX_PUBLIC_KEY];
        let mut spk: [u8; MAX_KEX_CIPHERTEXT]=[0;MAX_KEX_CIPHERTEXT];
        let mut ss: [u8;MAX_SHARED_SECRET_SIZE]=[0;MAX_SHARED_SECRET_SIZE];
        let mut crn: [u8;32]=[0;32];

        log(IO_PROTOCOL,"Attempting Full Handshake\n",-1,None);
        self.favourite_group=groups[0];   // start out with first one. May change on a handshake retry

        let mut sklen=sal::secret_key_size(self.favourite_group);   
        let mut sslen=sal::shared_secret_size(self.favourite_group);
        let mut pklen=sal::client_public_key_size(self.favourite_group);
        let mut pk_s=&mut cpk[0..pklen];
        sal::generate_key_pair(self.favourite_group,&mut csk[0..sklen],pk_s);
        log(IO_DEBUG,"Private Key= ",0,Some(&csk[0..sklen]));
        log(IO_DEBUG,"Client Public Key= ",0,Some(pk_s));
        let mut ext: [u8;MAX_EXTENSIONS]=[0;MAX_EXTENSIONS];
        let mut cookie: [u8;MAX_COOKIE]=[0;MAX_COOKIE];
// build client hello
        sal::random_bytes(32,&mut crn);
// add chosen extensions
        let mut extlen=self.build_extensions(&mut ext,pk_s,&mut expected,0);
// build and transmit client hello
        let mut chlen=self.send_client_hello(TLS1_0,&mut ch,&crn,false,&ext[0..extlen],0,false,true);
//
//
//   ----------------------------------------------------------> client Hello
//
//   
        log(IO_DEBUG,"Client Hello sent\n",-1,None);
// process server hello
        pklen=sal::server_public_key_size(self.favourite_group);
        pk_s=&mut spk[0..pklen];
        let mut kex=0;
        let mut pskid:isize=-1;
        let mut cklen=0;
        let mut rtn = self.get_server_hello(&mut kex,&mut cookie,&mut cklen,pk_s,&mut pskid);
//
//
//  <--------------------------------- server Hello (or helloRetryRequest?)
//
//
        if self.bad_response(&rtn) {
            return TLS_FAILURE;
        }
// Find cipher-suite chosen by Server
        let mut hash_type=0;
        for i in 0..nsc {
            if self.cipher_suite==ciphers[i] {
                hash_type=sal::hash_type(self.cipher_suite);
            }
        }
        let hlen=sal::hash_len(hash_type);
        if hlen == 0 {
            self.send_alert(ILLEGAL_PARAMETER);
            logger::log_cipher_suite(self.cipher_suite);
            log(IO_DEBUG,"Cipher Suite not valid\n",-1,None);
            log(IO_PROTOCOL,"Full Handshake failed\n",-1,None);
            return TLS_FAILURE;
        }
        logger::log_cipher_suite(self.cipher_suite);

// For Transcript hash we must use cipher-suite hash function
        self.init_transcript_hash();

// extract slices.. Depends on cipher suite
        let mut hh: [u8;MAX_HASH]=[0;MAX_HASH]; let hh_s=&mut hh[0..hlen];
        let mut es: [u8;MAX_HASH]=[0;MAX_HASH]; let es_s=&mut es[0..hlen];
        keys::derive_early_secrets(hash_type,None,es_s,None,None);
        log(IO_DEBUG,"Early secret= ",0,Some(es_s));

        if rtn.val==HANDSHAKE_RETRY { // Was server hello actually an Hello Retry Request?
            log(IO_DEBUG,"Server Hello Retry Request= ",0,Some(&self.ibuff[0..self.iblen]));
            self.running_synthetic_hash(&ch[0..chlen],&ext[0..extlen]);
            self.running_hash_io();

            let mut supported=false;
            for i in 0..nsg {
                if kex==groups[i] {
                    supported=true;
                }
            }

            if !supported || kex==self.favourite_group { // Its the same again
                self.send_alert(ILLEGAL_PARAMETER);
                log(IO_DEBUG,"Group not supported, or no change as result of HRR\n",-1,None);
                log(IO_PROTOCOL,"Full Handshake failed\n",-1,None);
                return TLS_FAILURE;
            }

            self.favourite_group=kex;
            sklen=sal::secret_key_size(self.favourite_group);   // probably changed on a handshake retry
            sslen=sal::shared_secret_size(self.favourite_group);
            pklen=sal::client_public_key_size(self.favourite_group);
            pk_s=&mut cpk[0..pklen];
            sal::generate_key_pair(self.favourite_group,&mut csk[0..sklen],pk_s);
            extlen=self.build_extensions(&mut ext,pk_s,&mut expected,0);
            if cklen!=0 { // there was a cookie in the HRR ... so send it back in an extension
                extlen=extensions::add_cookie(&mut ext,extlen,&cookie[0..cklen]);
            }
            self.send_cccs();
// send new client hello
            chlen=self.send_client_hello(TLS1_2,&mut ch,&crn,false,&ext[0..extlen],0,true,true);
//
//
//  ---------------------------------------------------> Resend Client Hello
//
//
            log(IO_DEBUG,"Client Hello re-sent\n",-1,None);
// get new server hello
            pklen=sal::server_public_key_size(self.favourite_group);
            pk_s=&mut spk[0..pklen];

            let mut skex=0;
            rtn=self.get_server_hello(&mut skex,&mut cookie,&mut cklen,pk_s,&mut pskid);
            if self.bad_response(&rtn) {
                return TLS_FAILURE;
            }
            if rtn.val==HANDSHAKE_RETRY {
                log(IO_DEBUG,"A second Handshake Retry Request?\n",-1,None);
                self.send_alert(UNEXPECTED_MESSAGE);
                log(IO_PROTOCOL,"Full Handshake failed\n",-1,None);
                return TLS_FAILURE;
            }
            if kex!=skex {
                log(IO_DEBUG,"Server came back with wrong group\n",-1,None);
                self.send_alert(ILLEGAL_PARAMETER);
                log(IO_PROTOCOL,"Full Handshake failed\n",-1,None);
                return TLS_FAILURE;
            }
//
//
//  <---------------------------------------------------------- server Hello
//
//
            resumption_required=true;
        }
        log(IO_DEBUG,"Server Hello= ",0,Some(&self.ibuff[0..self.iblen]));
        logger::log_server_hello(self.cipher_suite,pskid,pk_s,&cookie[0..cklen]);
        logger::log_key_exchange(IO_PROTOCOL,self.favourite_group);
// Transcript hash the Hellos 
        self.running_hash(&ch[0..chlen]);
        self.running_hash(&ext[0..extlen]);
        self.running_hash_io();      // Server Hello
        self.transcript_hash(hh_s);
//log(IO_DEBUG,"hh_s= ",0,Some(hh_s));
        let csk_s=&csk[0..sklen];
        let ss_s=&mut ss[0..sslen];

// Generate Shared secret SS from Client Secret Key and Server's Public Key
        let nonzero=sal::generate_shared_secret(self.favourite_group,csk_s,pk_s,ss_s);
        if !nonzero {
            self.send_alert(ILLEGAL_PARAMETER);
            self.clean();
            return TLS_FAILURE;
        }
        log(IO_DEBUG,"Shared Secret= ",0,Some(ss_s));

// Extract Handshake secret, Client and Server Handshake Traffic secrets, Client and Server Handshake keys and IVs from Transcript Hash and Shared secret
        self.derive_handshake_secrets(ss_s,es_s,hh_s);
        self.create_send_crypto_context();
        self.create_recv_crypto_context();
        log(IO_DEBUG,"Handshake secret= ",0,Some(&self.hs[0..hlen]));
        log(IO_DEBUG,"Client Handshake Traffic secret= ",0,Some(&self.cts[0..hlen]));
        log(IO_DEBUG,"Server Handshake Traffic secret= ",0,Some(&self.sts[0..hlen]));

// get encrypted extensions
        rtn=self.get_server_encrypted_extensions(&expected,&mut response);
//
//
//  <------------------------------------------------- {Encrypted Extensions}
//
//
        if self.bad_response(&rtn) {
            return TLS_FAILURE;
        }
        logger::log_enc_ext(&expected,&response);
        log(IO_DEBUG,"Encrypted extensions processed\n",-1,None);

        if resumption_required {
            return TLS_RESUMPTION_REQUIRED;
        }
        return TLS_SUCCESS;
    }

/// Check that the server is trusted
    fn server_trust(&mut self) -> usize {
// Client now receives certificate chain and verifier from Server. Need to parse these out, check CA signature on the cert
// (maybe its self-signed), extract public key from cert, and use this public key to check server's signature 
// on the "verifier". Note Certificate signature might use old methods, but server will use PSS padding for its signature (or ECC).
        let mut scvsig:[u8;MAX_SIGNATURE_SIZE]=[0;MAX_SIGNATURE_SIZE];
        let mut server_pk: [u8; MAX_SIG_PUBLIC_KEY]=[0;MAX_SIG_PUBLIC_KEY];

        let hash_type=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(hash_type);
// extract slices.. Depends on cipher suite
        let mut hh: [u8;MAX_HASH]=[0;MAX_HASH]; let hh_s=&mut hh[0..hlen];
        let mut fh: [u8;MAX_HASH]=[0;MAX_HASH]; let fh_s=&mut fh[0..hlen];

        let mut spklen=0;
        let mut rtn=self.get_check_server_certificatechain(&mut server_pk,&mut spklen); // public key type is inferred from sig type
//
//
//  <---------------------------------------------------------- {Certificate}
//
//
        if self.bad_response(&rtn) {
            return TLS_FAILURE;
        }
        let spk_s=&server_pk[0..spklen];
        self.transcript_hash(hh_s);
        log(IO_DEBUG,"Server Certificate Chain is valid\n",-1,None);
        log(IO_DEBUG,"Transcript Hash (CH+SH+EE+CT) = ",0,Some(hh_s));  

        let mut siglen=0;
        let mut sigalg:u16=0;
        rtn=self.get_server_cert_verify(&mut scvsig,&mut siglen,&mut sigalg);
//
//
//  <---------------------------------------------------- {Certificate Verify}
//
//
        if self.bad_response(&rtn) {
            return TLS_FAILURE;
        }
        let scvsig_s=&mut scvsig[0..siglen];
        self.transcript_hash(fh_s);
        log(IO_DEBUG,"Transcript Hash (CH+SH+EE+SCT+SCV) = ",0,Some(fh_s));
        log(IO_DEBUG,"Server Transcript Signature = ",0,Some(scvsig_s));
        logger::log_sig_alg(IO_PROTOCOL,sigalg);
        if !keys::check_server_cert_verifier(sigalg,scvsig_s,hh_s,spk_s) {
            self.send_alert(DECRYPT_ERROR);
            log(IO_DEBUG,"Server Cert Verification failed\n",-1,None);
            log(IO_PROTOCOL,"Full Handshake failed\n",-1,None);
            return TLS_FAILURE;
        }
        log(IO_PROTOCOL,"Server Cert Verification OK - ",-1,Some(&self.hostname[0..self.hlen]));

// get server finished
        let mut fnlen=0;
        let mut fin:[u8;MAX_HASH]=[0;MAX_HASH];
        rtn=self.get_server_finished(&mut fin,&mut fnlen);
//
//
//  <------------------------------------------------------ {Server Finished}
//
//
        let fin_s=&fin[0..fnlen];
        if self.bad_response(&rtn) {
            return TLS_FAILURE;
        }
        if !keys::check_verifier_data(hash_type,fin_s,&self.sts[0..hlen],fh_s) {
            self.send_alert(DECRYPT_ERROR);
            log(IO_DEBUG,"Server Data is NOT verified\n",-1,None);
            log(IO_DEBUG,"Full Handshake failed\n",-1,None);
            return TLS_FAILURE;
        }
        log(IO_DEBUG,"\nServer Data is verified\n",-1,None);
        return TLS_SUCCESS;
    }

/// Client proves trustworthyness to server, given servers list of acceptable signature types
    fn client_trust(&mut self) {
        let mut client_key:[u8;MAX_SIG_SECRET_KEY]=[0;MAX_SIG_SECRET_KEY];
        let mut client_certchain:[u8;MAX_CLIENT_CHAIN_SIZE]=[0;MAX_CLIENT_CHAIN_SIZE];
        let mut ccvsig:[u8;MAX_SIGNATURE_SIZE]=[0;MAX_SIGNATURE_SIZE];

        let hash_type=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(hash_type);
// extract slice.. Depends on cipher suite
        let mut fh: [u8;MAX_HASH]=[0;MAX_HASH]; let fh_s=&mut fh[0..hlen];
        log(IO_PROTOCOL,"Client is authenticating\n",-1,None);
        let mut cclen=0;
        let mut cklen=0;
        let kind=clientcert::get_client_credentials(&mut client_key,&mut cklen,self.client_cert_type,&mut client_certchain,&mut cclen);
        if kind!=0 { // Yes, I can do that signature
            let cc_s=&client_certchain[0..cclen];
            let ck_s=&client_key[0..cklen];
            self.send_client_certificate(Some(cc_s));
//
//
//  {client Certificate} ---------------------------------------------------->
//
//
            self.transcript_hash(fh_s);
            log(IO_DEBUG,"Transcript Hash (CH+SH+EE+CT) = ",0,Some(fh_s)); 
            cclen=keys::create_client_cert_verifier(kind,fh_s,ck_s,&mut ccvsig);
            log(IO_DEBUG,"Client Transcript Signature = ",0,Some(&ccvsig[0..cclen]));
            self.send_client_cert_verify(kind,&ccvsig[0..cclen]);
//
//
//  {Certificate Verify} ---------------------------------------------------->
//
//
        } else { // No, I can't - send a null cert
            self.send_client_certificate(None);
        }
    }

/// TLS1.3 FULL handshake
    pub fn tls_full(&mut self) -> usize {
        let mut resumption_required=false;

// exchange client/server hellos
        let rval=self.exchange_hellos();
        if rval==TLS_FAILURE {
            self.clean();
            return rval;
        }
        if rval==TLS_RESUMPTION_REQUIRED {
            resumption_required=true;
        }
        let hash_type=sal::hash_type(self.cipher_suite); // agreed cipher suite
        let hlen=sal::hash_len(hash_type);
// extract slices.. Depends on cipher suite
        let mut hh: [u8;MAX_HASH]=[0;MAX_HASH]; let hh_s=&mut hh[0..hlen];
        let mut fh: [u8;MAX_HASH]=[0;MAX_HASH]; let fh_s=&mut fh[0..hlen];
        let mut th: [u8;MAX_HASH]=[0;MAX_HASH]; let th_s=&mut th[0..hlen];
        let mut chf: [u8;MAX_HASH]=[0;MAX_HASH]; let chf_s=&mut chf[0..hlen];

        let mut rtn=self.see_whats_next();
        if self.bad_response(&rtn) {
            self.clean();
            return TLS_FAILURE;
        }

        let mut gotacertrequest=false;

// Maybe Server is requesting certificate from Client
        if rtn.val == CERT_REQUEST as usize { 
            gotacertrequest=true;
            rtn=self.get_certificate_request(false);
//
//
//  <---------------------------------------------------- {Certificate Request}
//
//
            if self.bad_response(&rtn) {
                self.clean();
                return TLS_FAILURE;
            }
            log(IO_PROTOCOL,"Certificate Request received\n",-1,None);
        }

// Check that server has authenticated
        let rval=self.server_trust();
        if rval==TLS_FAILURE {
            self.clean();
            return rval;
        }
        self.send_cccs();
        self.transcript_hash(hh_s);

// Now its the clients turn to respond
// Send Certificate (if it was asked for, and if I have one) & Certificate Verify.
        if gotacertrequest { // Server wants a client certificate
            if HAVE_CLIENT_CERT { // do I have one?
                self.client_trust();
            } else {
                self.send_client_certificate(None);
            }
        }
        self.transcript_hash(th_s);
        log(IO_DEBUG,"Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]) = ",0,Some(th_s));

// create client verify data
// .... and send it to Server
        keys::derive_verifier_data(hash_type,chf_s,&self.cts[0..hlen],th_s);
        self.send_client_finish(chf_s);
//
//
//  {client Finished} ----------------------------------------------------->
//
//
        log(IO_DEBUG,"Client Verify Data= ",0,Some(chf_s)); 
        self.transcript_hash(fh_s);
        log(IO_DEBUG,"Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]+CF) = ",0,Some(fh_s));

// calculate traffic and application keys from handshake secret and transcript hashes
        self.derive_application_secrets(hh_s,fh_s,None);
        self.create_send_crypto_context();
        self.create_recv_crypto_context();
        log(IO_DEBUG,"Client application traffic secret= ",0,Some(&self.cts[0..hlen]));
        log(IO_DEBUG,"Server application traffic secret= ",0,Some(&self.sts[0..hlen]));
        log(IO_PROTOCOL,"FULL Handshake succeeded\n",-1,None);
        self.clean_io();
        if resumption_required { 
            log(IO_PROTOCOL,"... after handshake resumption\n",-1,None);
            return TLS_RESUMPTION_REQUIRED;
        }
        return TLS_SUCCESS;
    }

/// Connect to server. First try resumption if session has a good ticket attached
    pub fn connect(&mut self,early: Option<&[u8]>) -> bool {
        let rtn:usize;
        let mut early_went=false;
        self.status=HANDSHAKING;
        if self.t.still_good() { // have a good ticket? Try it.
            rtn=self.tls_resume(early);
            if rtn==TLS_EARLY_DATA_ACCEPTED { 
                early_went=true;
            }
        } else {
            log(IO_PROTOCOL,"Resumption Ticket not found or invalid\n",-1,None);
            rtn=self.tls_full();
        }
        self.t.clear(); // clear out any ticket
    
        if rtn==0 {  // failed to connect
            //self.status=DISCONNECTED;
            return false;
        }
        if !early_went {
            if  let Some(searly) = early {
                self.send(searly);  // didn't go early, so send it now
            }
        }
        self.status=CONNECTED;
        return true;   // exiting with live session, ready to receive fresh ticket
    }

/// Send a message post-handshake
    pub fn send(&mut self,mess: &[u8]) {
        log(IO_APPLICATION,"Sending Application Message \n\n",-1,Some(mess));
        self.send_message(APPLICATION,TLS1_2,mess,None,true);       
    }

/// Process Server records received post-handshake. Should be mostly application data, but could be more handshake data disguised as application data
// For example could include a ticket. Also receiving key K_recv might be updated.
// returns +ve length of message, or negative error
// Stay inside looping on Handshake messages. Exit on (a) received an application message, or (b) nothing to read 
    pub fn recv(&mut self,mess: Option<&mut [u8]>) -> isize {
        let mut fin=false;
        let mut kind:isize;
        let mut pending_update=false;
        let mut pending_authentication=false;
        let mut mslen:isize=0;
        loop {
            log(IO_PROTOCOL,"Waiting for Server input\n",-1,None);
            self.clean_io();
            kind=self.get_record();  // get first fragment to determine type
            if kind<0 {
                self.send_alert(alert_from_cause(kind));
                return kind;   // its an error
            }
            if kind==TIMED_OUT as isize {
                log(IO_PROTOCOL,"TIME_OUT\n",-1,None);
                return TIME_OUT;
            }
            if kind==HSHAKE as isize {
                let mut r:RET;
                loop {
                    r=self.parse_int_pull(1); let nb=r.val; if r.err!=0 {break;}
                    self.ptr -= 1; // peek ahead - put it back
                    match nb as u8 {
                        TICKET => {
                            r=self.parse_int_pull(1); if r.err!=0 {break;}
                            r=self.parse_int_pull(3); let len=r.val; if r.err!=0 {break;}   // message length
                            let start=self.ptr;
                            r=self.parse_pull(len);
                            let ticket=&self.ibuff[start..start+len];
                            let rtn=self.t.create(ticket::millis(),ticket);  // extract into ticket structure T, and keep for later use
                            if rtn==BAD_TICKET {
                                self.t.valid=false;
                                log(IO_PROTOCOL,"Got a bad ticket \n",-1,None);
                            } else {
                                self.t.cipher_suite=self.cipher_suite;
                                self.t.favourite_group=self.favourite_group;
                                self.t.valid=true;
                                log(IO_PROTOCOL,"Got a ticket with lifetime (minutes)= ",(self.t.lifetime/60) as isize,None);
                            }
                            if self.ptr==self.iblen { // nothing left
                                fin=true;
                                self.rewind();
                            }
                            if !fin {continue;}
                        }
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
                            if kur==UPDATE_NOT_REQUESTED {  // reset record number
                                self.k_recv.update(&mut self.sts[0..hlen]);
                                log(IO_PROTOCOL,"RECEIVING KEYS UPDATED\n",-1,None);
                            }
                            if kur==UPDATE_REQUESTED {
                                self.k_recv.update(&mut self.sts[0..hlen]);
                                pending_update=true;
                                log(IO_PROTOCOL,"Key update notified - client should do the same  \n",-1,None);
                                log(IO_PROTOCOL,"RECEIVING KEYS UPDATED\n",-1,None);
                            }
                            if kur!=UPDATE_NOT_REQUESTED && kur!=UPDATE_REQUESTED {
                                log(IO_PROTOCOL,"Bad Request Update value\n",-1,None);
                                self.send_alert(ILLEGAL_PARAMETER);
                                return BAD_REQUEST_UPDATE;
                            }
                            if self.ptr==self.iblen { // nothing left
                                fin=true;
                                self.rewind();
                            }
                            if !fin {continue;}
                        }
                        CERT_REQUEST => {
                            if !POST_HS_AUTH {  // not unless I agreed to it in the first place
                                self.send_alert(UNEXPECTED_MESSAGE);
                                return WRONG_MESSAGE;
                            }
                            r=self.get_certificate_request(true);  // 
                            if self.bad_response(&r) {
                                self.send_alert(DECODE_ERROR);
                                return BAD_MESSAGE;
                            }
                            pending_authentication=true;

                            if self.ptr==self.iblen { // nothing left
                                fin=true;
                                self.rewind();
                            }
                            if !fin {continue;}
                        }
                        _ => {
                            r=self.parse_int_pull(1); if r.err!=0 {break;}
                            r=self.parse_int_pull(3); let _len=r.val; if r.err!=0 {break;}   // message length
                            log(IO_PROTOCOL,"Unsupported Handshake message type \n",nb as isize,None);
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

            if pending_authentication { // send certificate chain, cert_verify and client finish
                let hash_type=sal::hash_type(self.cipher_suite);
                let hlen=sal::hash_len(hash_type);
                let mut fh: [u8;MAX_HASH]=[0;MAX_HASH]; let fh_s=&mut fh[0..hlen];
                let mut chf: [u8;MAX_HASH]=[0;MAX_HASH]; let chf_s=&mut chf[0..hlen];
// send client credentials
                self.client_trust();
// get transcript hash following Handshake Context+Certificate
                self.transcript_hash(fh_s);  
                // create client verify data and send it to Server
                keys::derive_verifier_data(hash_type,chf_s,&self.cts[0..hlen],fh_s);
                self.send_client_finish(chf_s);
                pending_authentication=false;
            }

            if pending_update { // tell server to update their receiving keys
                self.send_key_update(UPDATE_NOT_REQUESTED);  
                log(IO_PROTOCOL,"SENDING KEYS UPDATED\n",-1,None);
                pending_update=false;
                // dont exit yet, wait for some data
            }
            if kind==APPLICATION as isize{ // exit only after we receive some application data
                self.ptr=self.iblen;
                if let Some(mymess) = mess {
                    let mut n=mymess.len();
                    if n>self.ptr {
                        n=self.ptr;
                    }
                    for i in 0..n {
                        mymess[i]=self.ibuff[i];
                    }
                    mslen=n as isize;
                }
                self.rewind();
                break;
            }
            if kind==ALERT as isize {
                log(IO_PROTOCOL,"*** Alert received - ",-1,None);
                logger::log_alert(self.ibuff[1]);
                if self.ibuff[1]==CLOSE_NOTIFY {
                    return CLOSURE_ALERT_RECEIVED; 
                } else {
                    return ERROR_ALERT_RECEIVED;
                }
            }
        }
        if self.t.valid {
            self.recover_psk();
            self.t.origin=FULL_HANDSHAKE;
        } else {
            log(IO_PROTOCOL,"No ticket provided \n",-1,None);
        }
        return mslen; 
    }
/// controlled stop
    pub fn stop(&mut self) {
        self.send_alert(CLOSE_NOTIFY);
    }
}
