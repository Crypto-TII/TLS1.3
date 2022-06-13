//
// Main TLS1.3 protocol 
//

use std::net::{TcpStream};
use std::io::{Write};

use zeroize::Zeroize;

use crate::config::*;
use crate::tls13::sal;
use crate::tls13::socket;
use crate::tls13::utils;
use crate::tls13::utils::RET;
use crate::tls13::utils::EESTATUS;
use crate::tls13::keys;
use crate::tls13::extensions;
use crate::tls13::certchain;
use crate::tls13::logger;
use crate::tls13::logger::log;
use crate::tls13::ticket;
use crate::tls13::ticket::TICKET;

pub struct SESSION {
    status: usize,     // Connection status 
    max_record: usize, // Server's max record size 
    pub sockptr: TcpStream,   // Pointer to socket 
    iolen: usize,           // IO buffer length
    ptr: usize,             // IO buffer pointer - consumed portion
    session_id:[u8;32],  // legacy session ID
    pub hostname: [u8;MAX_SERVER_NAME],     // Server name for connection 
    pub hlen: usize,        // hostname length
    cipher_suite: u16,      // agreed cipher suite 
    favourite_group: u16,   // favourite key exchange group 
    k_send: keys::CRYPTO,   // Sending Key 
    k_recv: keys::CRYPTO,   // Receiving Key 
    hs: [u8;MAX_HASH],      // Handshake secret
    rms: [u8;MAX_HASH],     // Resumption Master Secret         
    sts: [u8;MAX_HASH],     // Server Traffic secret             
    cts: [u8;MAX_HASH],     // Client Traffic secret                
    io: [u8;MAX_IO],        // Main IO buffer for this connection 
    tlshash: UNIHASH,       // Transcript hash recorder 
    pub t: TICKET           // resumption ticket    
}

// IO buffer
// xxxxxxxxxxxxxxxxxxxxxxxxxxxyyyyyyyyyyyyyyyyyyyyyyyyyyy
// -------------ptr---------->----------iolen----------->
//
// when ptr becomes equal to iolen, pull in another record (and maybe decrypt it)
impl SESSION {
    pub fn new(stream: TcpStream,host: &str) -> SESSION  {
        let mut this=SESSION {
            status:DISCONNECTED,
            max_record: 0,
            sockptr: stream,
            iolen: 0,
            ptr: 0,
            session_id: [0;32],
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
            t: {TICKET{valid: false,tick: [0;MAX_TICKET_SIZE],nonce: [0;MAX_KEY],psk : [0;MAX_HASH],psklen: 0,tklen: 0,nnlen: 0,age_obfuscator: 0,max_early_data: 0,birth: 0,lifetime: 0,cipher_suite: 0,favourite_group: 0,origin: 0}}
        }; 
        let dst=host.as_bytes();
        this.hlen=dst.len();
        for i in 0..this.hlen {
            this.hostname[i]=dst[i];
        }
        return this;
    }

// get an integer of length len bytes from io stream
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
    
// pull bytes into array
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

// pull bytes into input buffer
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

// rewind iobuffer
    fn rewind(&mut self) {
        self.iolen=utils::shift_left(&mut self.io[0..self.iolen],self.ptr); // rewind
        self.ptr=0;        
    }

// Add I/O buffer self.io to transcript hash 
    fn running_hash_io(&mut self) {
        sal::hash_process_array(&mut self.tlshash,&self.io[0..self.ptr]);
        self.rewind();
    }


// Initialise transcript hash
    fn init_transcript_hash(&mut self) {
        let htype=sal::hash_type(self.cipher_suite);
        sal::hash_init(htype,&mut self.tlshash);
    }

// Add octad to transcript hash 
    fn running_hash(&mut self,o: &[u8]) {
        sal::hash_process_array(&mut self.tlshash,o);
    }

// Output transcript hash 
    fn transcript_hash(&self,o: &mut [u8]) {
        sal::hash_output(&self.tlshash,o); 
    }

// special case handling for first clientHello after retry request
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
//        self.iolen=utils::shift_left(&mut self.io[0..self.iolen],self.ptr); // rewind
//        self.ptr=0;
    }

    pub fn create_send_crypto_context(&mut self) {
        self.k_send.init(self.cipher_suite,&self.cts);
    }

    pub fn create_recv_crypto_context(&mut self) {
        self.k_recv.init(self.cipher_suite,&self.sts);
    }
    
// get Client and Server Handshake secrets for encrypting rest of handshake, from Shared secret SS and early secret ES
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

// Extract Client and Server Application Traffic secrets from Transcript Hashes, Handshake secret 
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

// recover Pre-Shared-Key from Resumption Master Secret
    fn recover_psk(&mut self) { 
        let rs="resumption";
        let htype=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(htype);
        keys::hkdf_expand_label(htype,&mut self.t.psk[0..hlen],&self.rms[0..hlen],rs.as_bytes(),Some(&self.t.nonce[0..self.t.nnlen]));
        self.t.psklen=hlen;
    }

// send a message - could/should be broken down into multiple records
// message comes in two halves - cm and (optional) ext
// message is constructed in IO buffer, and finally written to the socket
// note that IO buffer is overwritten
    fn send_message(&mut self,rectype: u8,version: usize,cm: &[u8],ext: Option<&[u8]>) {
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
        self.sockptr.write(&self.io[0..ptr]).unwrap();
        self.clean_io();
    }   

// Send Client Hello
    pub fn send_client_hello(&mut self,version:usize,ch: &mut [u8],already_agreed: bool,ext: &[u8],extra: usize,resume: bool) -> usize {
        let mut rn: [u8;32]=[0;32];
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
        sal::random_bytes(32,&mut rn);
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
        ptr=utils::append_bytes(ch,ptr,&rn[0..32]);
        ptr=utils::append_int(ch,ptr,32,1);
        ptr=utils::append_bytes(ch,ptr,&self.session_id);
        ptr=utils::append_bytes(ch,ptr,&cs[0..clen]);
        ptr=utils::append_int(ch,ptr,cm,2);
        ptr=utils::append_int(ch,ptr,extlen,2);

        self.send_message(HSHAKE,version,&ch[0..ptr],Some(&ext));
        return ptr
    }

// Send "binder",
    pub fn send_binder(&mut self,b:&mut [u8],bnd: &[u8]) -> usize {
        let tlen2=bnd.len()+1;  
        let mut ptr=0;
        ptr=utils::append_int(b,ptr,tlen2,2);
        ptr=utils::append_int(b,ptr,bnd.len(),1);
        ptr=utils::append_bytes(b,ptr,bnd);
        self.send_message(HSHAKE,TLS1_2,&b[0..ptr],None);
        return ptr;
    }

// check for a bad response. If not happy with what received - send alert and close. If alert received from Server, log it and close.
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
            logger::log_alert(r.val as u8);
            return true;
        }
        if r.err != 0 {
            return true;
        }
        return false;
    }

// Send an alert to the Server
    pub fn send_alert(&mut self,kind: u8) {
        let pt: [u8;2]=[0x02,kind];
        self.send_message(ALERT,TLS1_2,&pt[0..2],None);
        log(IO_PROTOCOL,"Alert sent to Server - ",0,None);
        logger::log_alert(kind);
    }

// send Change Cipher Suite - helps get past middleboxes (?)
    pub fn send_cccs(&mut self) {
        let cccs:[u8;6]=[0x14,0x03,0x03,0x00,0x01,0x01];
        self.sockptr.write(&cccs).unwrap();
    }

// Send Early Data
    pub fn send_end_early_data(&mut self) {
        let mut ed:[u8;4]=[0;4];
        let mut ptr=0;
        ptr=utils::append_byte(&mut ed,ptr,END_OF_EARLY_DATA,1);
        ptr=utils::append_int(&mut ed,ptr,0,3);
        self.running_hash(&ed[0..ptr]);
        self.send_message(HSHAKE,TLS1_2,&ed[0..ptr],None);
    }

// Send Client Certificate
    fn send_client_certificate(&mut self,certchain: Option<&[u8]>) {
        let mut pt:[u8;8]=[0;8];
        let mut ptr=0;
        ptr=utils::append_byte(&mut pt,ptr,CERTIFICATE,1);
        if let Some(chain) = certchain {
            ptr=utils::append_int(&mut pt,ptr,4+chain.len(),3);
            ptr=utils::append_byte(&mut pt,ptr,0,1);
            ptr=utils::append_int(&mut pt,ptr,chain.len(),3);
            self.running_hash(&pt[0..ptr]);
            self.running_hash(chain);
        } else {
            ptr=utils::append_int(&mut pt,ptr,4,3);
            ptr=utils::append_byte(&mut pt,ptr,0,1);
            ptr=utils::append_int(&mut pt,ptr,0,3);
            self.running_hash(&pt[0..ptr]);
        }
        self.send_message(HSHAKE,TLS1_2,&pt[0..ptr],certchain);
    }

// Send Client Certificate Verify 
    fn send_client_cert_verify(&mut self, sigalg: u16,ccvsig: &[u8]) { 
        let mut pt:[u8;8]=[0;8];
        let mut ptr=0;
        ptr=utils::append_byte(&mut pt,ptr,CERT_VERIFY,1); // indicates handshake message "certificate verify"
        ptr=utils::append_int(&mut pt,ptr,4+ccvsig.len(),3); // .. and its length
        ptr=utils::append_int(&mut pt,ptr,sigalg as usize,2);
        ptr=utils::append_int(&mut pt,ptr,ccvsig.len(),2);
        self.running_hash(&pt[0..ptr]);
        self.running_hash(ccvsig);
        self.send_message(HSHAKE,TLS1_2,&pt[0..ptr],Some(ccvsig));
}

// Send final client handshake verification data
    fn send_client_finish(&mut self,chf: &[u8]) {
        let mut pt:[u8;4]=[0;4];
        let mut ptr=0;
        ptr=utils::append_byte(&mut pt,ptr,FINISHED,1); // indicates handshake message "client finished"
        ptr=utils::append_int(&mut pt,ptr,chf.len(),3); // .. and its length
        self.running_hash(&pt[0..ptr]);
        self.running_hash(chf);
        self.send_message(HSHAKE,TLS1_2,&pt[0..ptr],Some(chf));
    }

// build client's chosen set of extensions, and assert expectation of server responses
// The User may want to change the mix of optional extensions
// mode=0 - full handshake
// mode=1 - resumption handshake
// mode=2 = External PSK handshake
    pub fn build_extensions(&self,ext: &mut [u8],pk: &[u8],expected: &mut EESTATUS,mode: usize) -> usize {
        let psk_mode=PSKWECDHE;
        let tls_version=TLS1_3;
        let protocol=APPLICATION_PROTOCOL;
        let alpn=protocol.as_bytes();
        let mut groups:[u16;MAX_CIPHER_SUITES]=[0;MAX_CIPHER_SUITES];
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
            extensions::add_rsl(ext,extlen,MAX_RECORD);
        } else {
            if mode!=2 { // PSK mode has a problem with this (?)
                extlen=extensions::add_mfl(ext,extlen,MAX_FRAG); expected.max_frag_len=true;
            }
        }
        extlen=extensions::add_padding(ext,extlen,(sal::random_byte()%16) as usize);

        if mode==0 { // need some signature related extensions only for full handshake
            extlen=extensions::add_supported_sigs(ext,extlen,nsa,&sig_algs);
            extlen=extensions::add_supported_sigcerts(ext,extlen,nsac,&sig_alg_certs);            
        }
        return extlen;
    }

// Receive Server Certificate Verifier
    fn get_server_cert_verify(&mut self,scvsig: &mut [u8],siglen: &mut usize,sigalg: &mut u16) -> RET {
        //let mut ptr=0;

        let mut r=self.parse_int_pull(1); // get message type
        if r.err!=0 {return r;}
        let nb=r.val as u8;
        if nb != CERT_VERIFY {
            r.err=WRONG_MESSAGE;
            return r;
        }

        r=self.parse_int_pull(3); let mut left=r.val; if r.err!=0 {return r;} // find message length

        r=self.parse_int_pull(2); *sigalg=r.val as u16; if r.err!=0 {return r;}
        r=self.parse_int_pull(2); let len=r.val; if r.err!=0 {return r;}
        r=self.parse_bytes_pull(&mut scvsig[0..len]); if r.err!=0 {return r;}
        left-=4+len;
        if left!=0 {
            r.err=BAD_MESSAGE;
            return r;
        }
        *siglen=len;
        self.running_hash_io();
        //sal::hash_process_array(&mut self.tlshash,&self.io[0..ptr]);
        //self.iolen=utils::shift_left(&mut self.io[0..self.iolen],ptr);
        r.val=CERT_VERIFY as usize;
        return r;
    }

// Receive Certificate Request - the Server wants the client to supply a certificate chain
    fn get_certificate_request(&mut self, nalgs: &mut usize,sigalgs: &mut [u16]) -> RET {
        //let mut ptr=0;
        let mut unexp=0;


        let mut r=self.parse_int_pull(1); // get message type
        if r.err!=0 {return r;}
        let nb=r.val as u8;
        if nb != CERT_REQUEST {
            r.err=WRONG_MESSAGE;
            return r;
        }

        r=self.parse_int_pull(3); let mut left=r.val; if r.err!=0 {return r;}
        r=self.parse_int_pull(1); let nb=r.val; if r.err!=0 {return r;}
        if nb!=0 {
            r.err=MISSING_REQUEST_CONTEXT;// expecting 0x00 Request context
            return r;
        }
        r=self.parse_int_pull(2); let mut len=r.val; if r.err!=0 {return r;} // length of extensions
        left-=3;
        if left!=len {
            r.err=BAD_MESSAGE;
            return r;
        }
        let mut algs=0;
        while len>0 {
            r=self.parse_int_pull(2); let ext=r.val; if r.err!=0 {return r;}
            len-=2;
            match ext {
                SIG_ALGS => {
                    r=self.parse_int_pull(2); let tlen=r.val; if r.err!=0 {return r;}
                    len-=2;
                    r=self.parse_int_pull(2); algs=r.val/2; if r.err!=0 {return r;}
                    len-=2;
                    for i in 0..algs {
                        r=self.parse_int_pull(2); if r.err!=0 {return r;}
                        if i<MAX_SUPPORTED_SIGS {
                            sigalgs[i]=r.val as u16;
                        }
                        len-=2;
                    }
                    if tlen!=2+2*algs {
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }
                    if algs>MAX_SUPPORTED_SIGS {
                        algs=MAX_SUPPORTED_SIGS;
                    }
                }
                _ => {
                    r=self.parse_int_pull(2); let tlen=r.val;
                    len-=2;
                    len-=tlen; self.ptr+=tlen;
                    unexp+=1;
                }
            }
            if r.err!=0 {return r;}
        }
        self.running_hash_io();
        //sal::hash_process_array(&mut self.tlshash,&self.io[0..ptr]);
        //self.iolen=utils::shift_left(&mut self.io[0..self.iolen],ptr);
        r.val=CERT_REQUEST as usize;
        if algs==0 {
            r.err=UNRECOGNIZED_EXT;
            return r;
        }
        if unexp>0 {
            log(IO_DEBUG,"Unrecognized extensions received\n",0,None);
        }
        *nalgs=algs;
        return r;
    }

// Get handshake finish verifier data in hfin
    fn get_server_finished(&mut self,hfin: &mut [u8],hflen: &mut usize) -> RET {
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

// Receive a single record. Could be fragment of a full message. Could be encrypted.
// returns +ve type of record, or negative error
// should I check version? RFC - "MUST be ignored for all purposes"
    pub fn get_record(&mut self) -> isize {
        let mut rh:[u8;5]=[0;5];
        let mut tag:[u8;MAX_TAG_SIZE]=[0;MAX_TAG_SIZE];
        let pos=self.iolen;
        if !socket::get_bytes(&mut self.sockptr,&mut rh[0..3]) {
            return TIMED_OUT as isize;
        }
        if rh[0]==ALERT {
            let left=socket::get_int16(&mut self.sockptr);
            socket::get_bytes(&mut self.sockptr,&mut self.io[0..left]); self.iolen=left;
            return ALERT as isize;
        }
        if rh[0]==CHANGE_CIPHER { // read it, and ignore it
            let mut sccs:[u8;10]=[0;10];
            let left=socket::get_int16(&mut self.sockptr);
            socket::get_bytes(&mut self.sockptr,&mut sccs[0..left]);
            socket::get_bytes(&mut self.sockptr,&mut rh[0..3]);
        }
        if rh[0]!=HSHAKE && rh[0]!=APPLICATION {
            return WRONG_MESSAGE;
        }
        let left=socket::get_int16(&mut self.sockptr);
        utils::append_int(&mut rh,3,left,2);
        if left+pos>self.io.len() { // this commonly happens with big records of application data from server
            return MEM_OVERFLOW;    // record is too big - memory overflow
        }
        if !self.k_recv.is_active() { // not encrypted
            if left>MAX_PLAIN_FRAG {
                return MAX_EXCEEDED;
            }
            socket::get_bytes(&mut self.sockptr,&mut self.io[pos..pos+left]); 
            self.iolen+=left; // read in record body
            return HSHAKE as isize;
        }
// OK, its encrypted, so aead decrypt it, check tag
        let taglen=self.k_recv.taglen;
        let rlen=left-taglen;
        if left>MAX_CIPHER_FRAG {
            return MAX_EXCEEDED;
        }
        socket::get_bytes(&mut self.sockptr,&mut self.io[pos..pos+rlen]); // read in record body
        self.iolen+=rlen;
        socket::get_bytes(&mut self.sockptr,&mut tag[0..taglen]);
        let success=sal::aead_decrypt(&self.k_recv,&rh,&mut self.io[pos..pos+rlen],&tag[0..taglen]);
        self.k_recv.increment_crypto_context();
        if !success {
            return AUTHENTICATION_FAILURE;
        }
// get record ending - encodes real (disguised) record type. Could be an Alert.        
        let mut lb=self.io[self.iolen-1];
        self.iolen -= 1; // remove it
        while lb==0 && self.iolen>0 {
            lb=self.io[self.iolen-1];
            self.iolen -= 1; // remove it
        }
        if (lb == HSHAKE || lb == ALERT) && rlen==0 {
            return WRONG_MESSAGE;
        }
        if lb == HSHAKE {
            return HSHAKE as isize;
        }
        if lb == APPLICATION {
            return APPLICATION as isize;
        }
        if lb==ALERT { // Alert record received, delete anything in IO prior to alert, and just return 2-byte alert
            self.iolen=utils::shift_left(&mut self.io[0..self.iolen],pos); // rewind
            return ALERT as isize;
        }
        return APPLICATION as isize;
    }

// Get (unencrypted) Server Hello
    fn get_server_hello(&mut self,kex: &mut u16,cookie: &mut [u8],cklen:&mut usize,pk: &mut [u8],pskid: &mut isize) -> RET {
        let mut srn: [u8;32]=[0;32];
        let mut sid: [u8;32]=[0;32];
        let mut hrr: [u8; HRR.len()/2]=[0;HRR.len()/2];
        utils::decode_hex(&mut hrr,&HRR);
        //let mut ptr=0;

        self.ptr=0;  
        self.iolen=0;

        let mut r=self.parse_int_pull(1);  if r.err!=0 {return r;}
        if r.val!=SERVER_HELLO as usize { // should be Server Hello
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

        while left>0 {
            r=self.parse_int_pull(2); let ext=r.val; if r.err!=0 {return r;} 
            r=self.parse_int_pull(2); let extlen=r.val; if r.err!=0 {return r;} 
            if extlen+2>left {r.err=BAD_MESSAGE;return r;}
            left-=4+extlen;
            match ext {
                KEY_SHARE => {
                    r=self.parse_int_pull(2); *kex=r.val as u16; if r.err!=0 {return r;}
                    if !retry { // its not a retry request
                        r=self.parse_int_pull(2); let pklen=r.val; if r.err!=0 {return r;}
                        if pklen!=pk.len() {
                            r.err=BAD_HELLO;
                            return r;
                        }
                        r=self.parse_bytes_pull(pk);
                    }
                },
                PRESHARED_KEY => {
                    r=self.parse_int_pull(2); *pskid=r.val as isize;
                },
                COOKIE => {
                    r=self.parse_bytes_pull(&mut cookie[0..extlen]); *cklen=extlen;
                },
                TLS_VER => {
                    r=self.parse_int_pull(2); let tls=r.val; if r.err!=0 {return r;}
                    if tls!=TLS1_3 {
                        r.err=NOT_TLS1_3;
                    }
                },
                _ => {
                    r.err=UNRECOGNIZED_EXT;
                    //break;
                }
            }
            if r.err!=0 {return r;}
        }
        if retry {
            r.val=HANDSHAKE_RETRY;
        } else {
            r.val=SERVER_HELLO as usize;
        }
        return r;
    }

// Handshake Messages start with TYPE|<- LEN -> where TYPE is a byte, and LEN is 24 bits
// Here we peek ahead for the TYPE in order to decide what to do next
// Important to include TYPE in the transcript hash
// See whats coming next
    fn see_whats_next(&mut self) -> RET {
        //let mut ptr=0;
        let mut r=self.parse_int_pull(1);
        self.ptr -= 1;  // put it back
        if r.err!=0 {return r;}
        let nb=r.val as u8;
        if nb==END_OF_EARLY_DATA || nb==KEY_UPDATE { // Servers MUST NOT send this.... KEY_UPDATE should not happen at this stage
            r.err=WRONG_MESSAGE;
            return r;
        }
        return r;
    }

// Process server's encrypted extensions
    pub fn get_server_encrypted_extensions(&mut self,expected: &EESTATUS,response: &mut EESTATUS) -> RET {
        let mut _unexp=0;

        let mut r=self.parse_int_pull(1); // get message type
        if r.err!=0 {return r;}
        let nb=r.val as u8;

        r=self.parse_int_pull(3); let mut left=r.val;  if r.err!=0 {return r;}  // get message length
        response.early_data=false;
        response.alpn=false;
        response.server_name=false;
        response.max_frag_len=false;
        if nb != ENCRYPTED_EXTENSIONS {
            r.err=WRONG_MESSAGE;
            return r;
        }

        r=self.parse_int_pull(2); let mut len=r.val; if r.err!=0 {return r;}
        left-=2;

        if left!=len {
            r.err=BAD_MESSAGE;
            return r;
        }

// extension could include Servers preference for supported groups, which could be
// taken into account by the client for later connections. Here we will ignore it. From RFC:
// "Clients MUST NOT act upon any information found in "supported_groups" prior to successful completion of the handshake"

        while len!=0 {
            r=self.parse_int_pull(2); let ext=r.val; if r.err!=0 {return r;}
            len-=2;
            r=self.parse_int_pull(2); let tlen=r.val; if r.err!=0 {return r;}
            len -= 2;
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
                    r=self.parse_int_pull(1); if r.err!=0 {return r;}
                    len-=tlen;
                    if tlen !=1 {
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }
                    response.max_frag_len=true;
                    if !expected.max_frag_len {
                        r.err=NOT_EXPECTED;
                    }
                },
                RECORD_SIZE_LIMIT => {
                    r=self.parse_int_pull(2); let mfl=r.val; if r.err!=0 {return r;}
                    len-=tlen;
                    if tlen!=2 || mfl<64 {
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }
                    self.max_record=mfl;
                },
                APP_PROTOCOL => {
                    let mut name:[u8;256]=[0;256];
                    r=self.parse_int_pull(2); if r.err!=0 {return r;}
                    r=self.parse_int_pull(1); let mfl=r.val; if r.err!=0 {return r;}
                    r=self.parse_bytes_pull(&mut name[0..mfl]); if r.err!=0 {return r;}
                    len-=tlen;
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
                    //len-=tlen; ptr +=tlen; // skip over it
                    r.err=FORBIDDEN_EXTENSION;
                    return r;
                },
                _ => {
                    len-=tlen; self.ptr +=tlen; // skip over it
                    _unexp+=1;
                }
            }
            if r.err!=0 {return r;}
        }
// Update Transcript hash and rewind IO buffer
        self.running_hash_io();
        r.val=nb as usize;

        return r;
    }

// Get certificate chain, and check its validity 
    pub fn get_check_server_certificatechain(&mut self,spk:&mut [u8],spklen: &mut usize) -> RET {
        let mut r=self.parse_int_pull(1); // get message type
        if r.err!=0 {return r;}
        let nb=r.val as u8;
        if nb != CERTIFICATE {
            r.err=WRONG_MESSAGE;
            return r;
        }

        r=self.parse_int_pull(3); let mut len=r.val; if r.err!=0 {return r;}         // message length   
        log(IO_DEBUG,"Certificate Chain Length= ",len as isize,None);
        r=self.parse_int_pull(1); let rc=r.val; if r.err!=0 {return r;} 
        if rc!=0x00 {
            r.err=MISSING_REQUEST_CONTEXT;// expecting 0x00 Request context
            return r;
        }
        r=self.parse_int_pull(3); len=r.val; if r.err!=0 {return r;}   // get length of certificate chain
	    if len==0 {
		    r.err=EMPTY_CERT_CHAIN;
		    return r;
	    }
        let start=self.ptr;
        r=self.parse_pull(len); if r.err!=0 {return r;} // get pointer to certificate chain, and pull it all into self.io
// Update Transcript hash

        let mut identity:[u8;MAX_X509_FIELD]=[0;MAX_X509_FIELD];    // extracting cert identity - but not sure what to dowith it!
        let mut idlen=0;
        r.err=certchain::check_certchain(&self.io[start..start+len],Some(&self.hostname[0..self.hlen]),spk,spklen,&mut identity,&mut idlen);
        self.running_hash_io();

        r.val=CERTIFICATE as usize;
        return r;
    }

// clean up buffers, kill crypto keys
    pub fn clean(&mut self) {
        self.status=DISCONNECTED;
        self.io.zeroize();
        self.hs.zeroize();
        self.cts.zeroize();
        self.sts.zeroize();
        self.rms.zeroize();
        self.k_send.clear();
        self.k_recv.clear();
    }

// clean out IO buffer
    fn clean_io(&mut self) {
        for i in 0..self.iolen {
            self.io[i]=0;
        } 
        self.ptr=0;
        self.iolen=0;
    }

// TLS1.3
// RESUMPTION handshake. Can optionally start with some early data
    pub fn tls_resume(&mut self,early: Option<&[u8]>) -> usize {
        let mut expected=EESTATUS{early_data:false,alpn:false,server_name:false,max_frag_len:false};
        let mut response=EESTATUS{early_data:false,alpn:false,server_name:false,max_frag_len:false};
        let mut have_early_data=false;
        log(IO_PROTOCOL,"Attempting Resumption Handshake\n",0,None);
        logger::log_ticket(&self.t); 

        let mut ext:[u8;MAX_EXTENSIONS]=[0;MAX_EXTENSIONS];
        let mut ch: [u8; MAX_HELLO] = [0; MAX_HELLO]; 
        let mut csk: [u8;MAX_KEX_SECRET_KEY]=[0;MAX_KEX_SECRET_KEY];  // client key exchange secret key
        let mut cpk: [u8;MAX_KEX_PUBLIC_KEY]=[0;MAX_KEX_PUBLIC_KEY];  // client key exchange public key
        let mut spk: [u8; MAX_KEX_CIPHERTEXT]=[0;MAX_KEX_CIPHERTEXT]; // server key exchange public key/ciphertext
        let mut ss: [u8;MAX_SHARED_SECRET_SIZE]=[0;MAX_SHARED_SECRET_SIZE];
        let mut cookie: [u8;MAX_COOKIE]=[0;MAX_COOKIE];

// Extract Ticket parameters
        //let lifetime=self.t.lifetime;
        let age_obfuscator=self.t.age_obfuscator;
        let max_early_data=self.t.max_early_data;
        let time_ticket_received=self.t.birth;
        self.cipher_suite=self.t.cipher_suite;
        self.favourite_group=self.t.favourite_group;
        let origin=self.t.origin;

        if max_early_data>0 {
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
        let mut bl:[u8;MAX_HASH+3]=[0;MAX_HASH+3];

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
// First build standard client Hello extensions
        let mut resmode=1;
        if origin==EXTERNAL_PSK {
            resmode=2;
        }
	    let mut extlen=self.build_extensions(&mut ext,pk_s,&mut expected,resmode);
        if have_early_data {
            extlen=extensions::add_early_data(&mut ext,extlen); expected.early_data=true;                 // try sending client message as early data if allowed
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
        let chlen=self.send_client_hello(TLS1_2,&mut ch,true,&ext[0..extlen],extra,false);  
//
//
//   ----------------------------------------------------------> client Hello
//
//
        self.running_hash(&ch[0..chlen]); 
        self.running_hash(&ext[0..extlen]);
        self.transcript_hash(hh_s); // hh = hash of Truncated clientHello
        log(IO_DEBUG,"Hash of Truncated client Hello",0,Some(hh_s));
        log(IO_DEBUG,"Client Hello sent\n",0,None);
        keys::derive_verifier_data(htype,bnd_s,bk_s,hh_s);  
        let blen=self.send_binder(&mut bl,bnd_s);
//  -----------------------------------------------------------> Send rest of client Hello
        self.running_hash(&bl[0..blen]);
        self.transcript_hash(hh_s); // hh = hash of complete clientHello
        log(IO_DEBUG,"Hash of Completed client Hello",0,Some(hh_s));
        log(IO_DEBUG,"BND= ",0,Some(bnd_s));
        log(IO_DEBUG,"Sending Binders\n",0,None);   // only sending one

        if have_early_data {
            self.send_cccs();
        }

        keys::derive_later_secrets(htype,es_s,hh_s,Some(cets_s),None);   // Get Client Later Traffic Secret from transcript hash and ES
        log(IO_DEBUG,"Client Early Traffic Secret= ",0,Some(cets_s)); 
        self.k_send.init(self.cipher_suite,cets_s);

// if its allowed, send client message as (encrypted!) early data
        if have_early_data {
            if let Some(searly) = early {
                log(IO_APPLICATION,"Sending some early data\n",0,None);
                self.send_message(APPLICATION,TLS1_2,searly,None);
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
//
//
//  <---------------------------------------------------------- server Hello
//
//
        self.running_hash_io();         // Hashing Server Hello
        self.transcript_hash(hh_s);     // HH = hash of clientHello+serverHello

        if pskid<0 { // Ticket rejected by Server (as out of date??)
            log(IO_PROTOCOL,"Ticket rejected by server\n",0,None);
            self.send_alert(CLOSE_NOTIFY);
            log(IO_PROTOCOL,"Resumption Handshake failed\n",0,None);
            self.clean();
            return TLS_FAILURE;
        }

	    if pskid>0 { // pskid out-of-range (only one allowed)
            self.send_alert(ILLEGAL_PARAMETER);
            log(IO_PROTOCOL,"Resumption Handshake failed\n",0,None);
            self.clean();
            return TLS_FAILURE;
	    }
        if self.bad_response(&rtn) {
            self.send_alert(CLOSE_NOTIFY);
            self.clean();
            return TLS_FAILURE;
        }   
        logger::log_server_hello(self.cipher_suite,pskid,pk_s,&cookie[0..cklen]);
        logger::log_key_exchange(IO_PROTOCOL,kex);

        if rtn.val==HANDSHAKE_RETRY || kex!=self.favourite_group { // should not happen
            self.send_alert(UNEXPECTED_MESSAGE);
            log(IO_DEBUG,"No change possible as result of HRR\n",0,None); 
            log(IO_PROTOCOL,"Resumption Handshake failed\n",0,None);
            self.clean();
            return TLS_FAILURE;
        }
        log(IO_DEBUG,"serverHello= ",0,Some(&self.io[0..self.iolen])); 

// Generate Shared secret SS from Client Secret Key and Server's Public Key
        sal::generate_shared_secret(kex,csk_s,pk_s,ss_s); 
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
            self.clean();
            return TLS_FAILURE;
        }
        logger::log_enc_ext(&expected,&response);
        self.transcript_hash(fh_s);
        log(IO_DEBUG,"Encrypted extensions processed\n",0,None);

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
            self.clean();
            return TLS_FAILURE;
        }
        log(IO_DEBUG,"Server Finished Message Received - ",0,Some(fin_s));
// Now indicate End of Early Data, encrypted with 0-RTT keys
        self.transcript_hash(hh_s); // hash of clientHello+serverHello+encryptedExtension+serverFinish
        if response.early_data {
            self.send_end_early_data();     // Should only be sent if server has accepted Early data - see encrypted extensions!
            log(IO_DEBUG,"Send End of Early Data \n",0,None);
        }
        self.transcript_hash(th_s); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData
        log(IO_DEBUG,"Transcript Hash (CH+SH+EE+SF+ED) = ",0,Some(th_s)); 

// Switch to handshake keys
        self.create_send_crypto_context();
        if !keys::check_verifier_data(htype,fin_s,&self.sts[0..hlen],fh_s) {
            self.send_alert(DECRYPT_ERROR);
            log(IO_DEBUG,"Server Data is NOT verified\n",0,None);
            log(IO_PROTOCOL,"Resumption Handshake failed\n",0,None);
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
        log(IO_DEBUG,"Server Data is verified\n",0,None);
        log(IO_DEBUG,"Client Verify Data= ",0,Some(chf_s)); 

        self.transcript_hash(fh_s); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData+clientFinish

// calculate traffic and application keys from handshake secret and transcript hashes, and store in session

        self.derive_application_secrets(hh_s,fh_s,None);
        self.create_send_crypto_context();
        self.create_recv_crypto_context();

        log(IO_DEBUG,"Client application traffic secret= ",0,Some(&self.cts[0..hlen]));
        log(IO_DEBUG,"Server application traffic secret= ",0,Some(&self.sts[0..hlen]));
        log(IO_PROTOCOL,"RESUMPTION Handshake succeeded\n",0,None);
        self.clean_io();

        if response.early_data {
            log(IO_PROTOCOL,"Application Message accepted as Early Data\n\n",-1,early);
            return TLS_EARLY_DATA_ACCEPTED;
        }
        return TLS_SUCCESS;
    }

// Exchange Client/Server "Hellos"
    fn exchange_hellos(&mut self) -> usize {
        let mut groups:[u16;MAX_CIPHER_SUITES]=[0;MAX_CIPHER_SUITES];
        let mut ciphers:[u16;MAX_SUPPORTED_GROUPS]=[0;MAX_SUPPORTED_GROUPS];
        let _nsg=sal::groups(&mut groups);
        let nsc=sal::ciphers(&mut ciphers);
        let mut resumption_required=false;
        let mut expected=EESTATUS{early_data:false,alpn:false,server_name:false,max_frag_len:false};
        let mut response=EESTATUS{early_data:false,alpn:false,server_name:false,max_frag_len:false};
        let mut ch: [u8; MAX_HELLO] = [0; MAX_HELLO]; 
        let mut csk: [u8;MAX_KEX_SECRET_KEY]=[0;MAX_KEX_SECRET_KEY];
        let mut cpk: [u8;MAX_KEX_PUBLIC_KEY]=[0;MAX_KEX_PUBLIC_KEY];
        let mut spk: [u8; MAX_KEX_CIPHERTEXT]=[0;MAX_KEX_CIPHERTEXT];
        let mut ss: [u8;MAX_SHARED_SECRET_SIZE]=[0;MAX_SHARED_SECRET_SIZE];

        log(IO_PROTOCOL,"Attempting Full Handshake\n",0,None);
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

// add chosen extensions
        let mut extlen=self.build_extensions(&mut ext,pk_s,&mut expected,0);
// build and transmit client hello
        let mut chlen=self.send_client_hello(TLS1_0,&mut ch,false,&ext[0..extlen],0,false);
//
//
//   ----------------------------------------------------------> client Hello
//
//   
        log(IO_DEBUG,"Client Hello sent\n",0,None);
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
            log(IO_DEBUG,"Cipher Suite not valid\n",0,None);
            log(IO_PROTOCOL,"Full Handshake failed\n",0,None);
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
            log(IO_DEBUG,"Server Hello Retry Request= ",0,Some(&self.io[0..self.iolen]));
            self.running_synthetic_hash(&ch[0..chlen],&ext[0..extlen]);
            self.running_hash_io();

            if kex==self.favourite_group { // Its the same again
                self.send_alert(ILLEGAL_PARAMETER);
                log(IO_DEBUG,"No change as result of HRR\n",0,None);
                log(IO_PROTOCOL,"Full Handshake failed\n",0,None);
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
            chlen=self.send_client_hello(TLS1_2,&mut ch,true,&ext[0..extlen],0,true);
//
//
//  ---------------------------------------------------> Resend Client Hello
//
//
            log(IO_DEBUG,"Client Hello re-sent\n",0,None);
// get new server hello
            pklen=sal::server_public_key_size(self.favourite_group);
            pk_s=&mut spk[0..pklen];
            rtn=self.get_server_hello(&mut kex,&mut cookie,&mut cklen,pk_s,&mut pskid);
//
//
//  <---------------------------------------------------------- server Hello
//
//
            if self.bad_response(&rtn) {
                return TLS_FAILURE;
            }
            if rtn.val==HANDSHAKE_RETRY {
                log(IO_DEBUG,"A second Handshake Retry Request?\n",0,None);
                self.send_alert(UNEXPECTED_MESSAGE);
                log(IO_PROTOCOL,"Full Handshake failed\n",0,None);
                return TLS_FAILURE;
            }
            resumption_required=true;
        }
        log(IO_DEBUG,"Server Hello= ",0,Some(&self.io[0..self.iolen]));
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
        sal::generate_shared_secret(self.favourite_group,csk_s,pk_s,ss_s);
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
        log(IO_DEBUG,"Encrypted extensions processed\n",0,None);

        if resumption_required {
            return TLS_RESUMPTION_REQUIRED;
        }
        return TLS_SUCCESS;
    }

// check that the server is trusted
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
        let mut rtn=self.get_check_server_certificatechain(&mut server_pk,&mut spklen);
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
        log(IO_DEBUG,"Certificate Chain is valid\n",0,None);
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
            log(IO_DEBUG,"Server Cert Verification failed\n",0,None);
            log(IO_PROTOCOL,"Full Handshake failed\n",0,None);
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
            log(IO_DEBUG,"Server Data is NOT verified\n",0,None);
            log(IO_DEBUG,"Full Handshake failed\n",0,None);
            return TLS_FAILURE;
        }
        log(IO_DEBUG,"\nServer Data is verified\n",0,None);
        return TLS_SUCCESS;
    }

// client supplies trust to server, given servers list of acceptable signature types
    fn client_trust(&mut self,csigalgs: &[u16] ) {
        let mut client_key:[u8;MAX_SIG_SECRET_KEY]=[0;MAX_SIG_SECRET_KEY];
        let mut client_certchain:[u8;MAX_CHAIN_SIZE]=[0;MAX_CHAIN_SIZE];
        let mut ccvsig:[u8;MAX_SIGNATURE_SIZE]=[0;MAX_SIGNATURE_SIZE];

        let hash_type=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(hash_type);
// extract slices.. Depends on cipher suite
        let mut th: [u8;MAX_HASH]=[0;MAX_HASH]; let th_s=&mut th[0..hlen];
        let mut fh: [u8;MAX_HASH]=[0;MAX_HASH]; let fh_s=&mut fh[0..hlen];

        let mut cclen=0;
        let mut cklen=0;
        let kind=certchain::get_client_credentials(csigalgs,&mut client_key,&mut cklen,&mut client_certchain,&mut cclen);
        if kind!=0 { // Yes, I can do that signature
            log(IO_PROTOCOL,"Client is authenticating\n",0,None);
            let cc_s=&client_certchain[0..cclen];
            let ck_s=&client_key[0..cklen];
            self.send_client_certificate(Some(cc_s));
//
//
//  {client Certificate} ---------------------------------------------------->
//
//
            self.transcript_hash(th_s);
            log(IO_DEBUG,"Transcript Hash (CH+SH+EE+CT) = ",0,Some(th_s)); 
            cclen=keys::create_client_cert_verifier(kind,th_s,ck_s,&mut ccvsig);
            self.send_client_cert_verify(kind,&ccvsig[0..cclen]);
            self.transcript_hash(fh_s);
            log(IO_DEBUG,"Transcript Hash (CH+SH+EE+SCT+SCV) = ",0,Some(fh_s));
            log(IO_DEBUG,"Client Transcript Signature = ",0,Some(&ccvsig[0..cclen]));
//
//
//  {Certificate Verify} ---------------------------------------------------->
//
//
        } else { // No, I can't - send a null cert
            self.send_client_certificate(None);
        }
    }

// TLS1.3
// FULL handshake
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
        let mut nccsalgs=0;
        let mut csigalgs:[u16;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS];
        let mut gotacertrequest=false;

// Maybe Server is requesting certificate from Client
        if rtn.val == CERT_REQUEST as usize { 
            gotacertrequest=true;
            rtn=self.get_certificate_request(&mut nccsalgs,&mut csigalgs);
//
//
//  <---------------------------------------------------- {Certificate Request}
//
//
            if self.bad_response(&rtn) {
                self.clean();
                return TLS_FAILURE;
            }
            log(IO_PROTOCOL,"Certificate Request received\n",0,None);
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
                self.client_trust(&csigalgs[0..nccsalgs]);
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
        log(IO_PROTOCOL,"FULL Handshake succeeded\n",0,None);
        self.clean_io();
        if resumption_required { 
            log(IO_PROTOCOL,"... after handshake resumption\n",0,None);
            return TLS_RESUMPTION_REQUIRED;
        }
        return TLS_SUCCESS;
    }

// connect to server
// first try resumption if session has a good ticket attached
    pub fn connect(&mut self,early: Option<&[u8]>) -> bool {
        let rtn:usize;
        let mut early_went=false;
        if self.t.still_good() { // have a good ticket? Try it.
            rtn=self.tls_resume(early);
            if rtn==TLS_EARLY_DATA_ACCEPTED { 
                early_went=true;
            }
        } else {
            log(IO_PROTOCOL,"Resumption Ticket not found or invalid\n",0,None);
            rtn=self.tls_full();
        }
        self.t.clear(); // clear out any ticket
    
        if rtn==0 {  // failed to connect
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

// send a message post-handshake
    pub fn send(&mut self,mess: &[u8]) {
        log(IO_APPLICATION,"Sending Application Message \n\n",-1,Some(mess));
        self.send_message(APPLICATION,TLS1_2,mess,None);       
    }

// Process Server records received post-handshake
// Should be mostly application data, but..
// could be more handshake data disguised as application data
// For example could include a ticket. Also receiving key K_recv might be updated.
// returns +ve length of message, or negative error
    pub fn recv(&mut self,mess: &mut [u8]) -> isize {
        let mut fin=false;
        let mut kind:isize;
        let mslen:isize;
        loop {
            log(IO_PROTOCOL,"Waiting for Server input \n",0,None);
            //let mut ptr=0;
//println!("self.iolen= {}",self.iolen);
            //self.iolen=0;
            kind=self.get_record();  // get first fragment to determine type
            if kind<0 {
                return kind;   // its an error
            }
            if kind==TIMED_OUT as isize {
                log(IO_PROTOCOL,"TIME_OUT\n",0,None);
                return TIME_OUT;
            }
            if kind==HSHAKE as isize {
                loop {
                    let mut r=self.parse_int_pull(1); let nb=r.val; if r.err!=0 {return BAD_RECORD;}
                    r=self.parse_int_pull(3); let len=r.val; if r.err!=0 {return BAD_RECORD;}   // message length
                    match nb as u8 {
                        TICKET => {
                            let start=self.ptr;
                            r=self.parse_pull(len);
                            let ticket=&self.io[start..start+len];
                            let rtn=self.t.create(ticket::millis(),ticket);  // extract into ticket structure T, and keep for later use
                            if rtn==BAD_TICKET {
                                self.t.valid=false;
                                log(IO_PROTOCOL,"Got a bad ticket ",0,None);
                            } else {
                                self.t.cipher_suite=self.cipher_suite;
                                self.t.favourite_group=self.favourite_group;
                                self.t.valid=true;
                                log(IO_PROTOCOL,"Got a ticket with lifetime (minutes)= ",(self.t.lifetime/60) as isize,None);
                            }
                            if self.ptr==self.iolen {
                                fin=true;
                                self.rewind();
                            }
                            if !fin {continue;}
                        }
                        KEY_UPDATE => {
                            if len!=1 {
                                log(IO_PROTOCOL,"Something wrong\n",0,None);
                                return BAD_RECORD;
                            } 
                            let htype=sal::hash_type(self.cipher_suite);
                            let hlen=sal::hash_len(htype);
                            r=self.parse_int_pull(1); let kur=r.val; if r.err!=0 {return BAD_RECORD;}
                            if kur==UPDATE_NOT_REQUESTED {  // reset record number
                                self.k_recv.update(&mut self.sts[0..hlen]);
                                log(IO_PROTOCOL,"KEYS UPDATED\n",0,None);
                            }
                            if kur==UPDATE_REQUESTED {
                                self.k_recv.update(&mut self.sts[0..hlen]);
                                log(IO_PROTOCOL,"Key update notified - client should do the same (?) \n",0,None);
                                log(IO_PROTOCOL,"KEYS UPDATED\n",0,None);
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
                    if r.err!=0 {return BAD_RECORD;}
                    if fin {break;}
                }
            }
            if kind==APPLICATION as isize{ // exit only after we receive some application data
                self.ptr=self.iolen;
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
                return ALERT_RECEIVED;
            }
        }
        if self.t.valid {
            self.recover_psk();
            self.t.origin=FULL_HANDSHAKE;
        } else {
            log(IO_PROTOCOL,"No ticket provided \n",0,None);
        }
        return mslen; 
    }
}
