//extern crate resize_slice;
extern crate mcore;

use std::net::{TcpStream};
use std::io::{Write};
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
use crate::tls13::ticket;
use crate::tls13::ticket::TICKET;

pub struct SESSION {
    status: usize,     // Connection status 
    server_max_record: usize,  // Server's max record size 
    sockptr: TcpStream,        // Pointer to socket 
    pub hlen: usize,
    iolen: usize,
    pub hostname: [u8;MAX_SERVER_NAME],     // Server name for connection 
    cipher_suite: usize,       // agreed cipher suite 
    favourite_group: usize,    // favourite key exchange group 
    k_send: keys::CRYPTO,          // Sending Key 
    k_recv: keys::CRYPTO,          // Receiving Key 
    rms: [u8;MAX_HASH], // Resumption Master Secret         
    sts: [u8;MAX_HASH], // Server Traffic secret             
    cts: [u8;MAX_HASH], // Client Traffic secret                
    io: [u8;MAX_IO],    // Main IO buffer for this connection 
    tlshash: UNIHASH,         // Transcript hash recorder 
    pub t: TICKET                 // resumption ticket    
}

impl SESSION {
    pub fn new(stream: TcpStream,host: &str) -> SESSION  {
        let mut this=SESSION {
            status:DISCONNECTED,
            server_max_record: 0,
            sockptr: stream,
            hlen: 0,
            iolen: 0,
            hostname: [0; MAX_SERVER_NAME],
            cipher_suite: 0,  //AES_128_GCM_SHA256,
            favourite_group: 0,
            k_send: keys::CRYPTO::new(), 
            k_recv: keys::CRYPTO::new(),
            rms: [0;MAX_HASH],
            sts: [0;MAX_HASH],
            cts: [0;MAX_HASH],   
            io: [0;MAX_IO],
            tlshash:{UNIHASH{state:[0;MAX_HASH_STATE],htype:0}},
            t: {TICKET{valid: false,tick: [0;MAX_TICKET_SIZE],nonce: [0;MAX_KEY],psk : [0;MAX_HASH],tklen: 0,nnlen: 0,age_obfuscator: 0,max_early_data: 0,birth: 0,lifetime: 0,cipher_suite: 0,favourite_group: 0,origin: 0}}
        }; 
        let dst=host.as_bytes();
        this.hlen=dst.len();
        for i in 0..this.hlen {
            this.hostname[i]=dst[i];
        }
        return this;
    }
 
// get an int of length len from stream
    fn parse_int_pull(&mut self,len:usize,ptr: &mut usize) -> RET {
        let mut r=utils::parse_int(&self.io[0..self.iolen],len,ptr); 
        while r.err !=0 { // not enough bytes in IO - pull in another fragment
            let rtn=self.get_record();  // gets more stuff and increments iolen
            if rtn!=HSHAKE as isize {
                r.err=rtn;
                if rtn==ALERT as isize {
                    r.val=self.io[1] as usize;
                }
                break;
            }
            r=utils::parse_int(&self.io[0..self.iolen],len,ptr);
        }
        return r;
    }

    fn parse_bytes_pull(&mut self,e: &mut[u8],ptr: &mut usize) -> RET {
        let mut r=utils::parse_bytes(e,&self.io[0..self.iolen],ptr);
        while r.err !=0 { // not enough bytes in IO - pull in another fragment
            let rtn=self.get_record();  // gets more stuff and increments iolen
            if rtn!=HSHAKE as isize {
                r.err=rtn;
                if rtn==ALERT as isize {
                    r.val=self.io[1] as usize;    // 0 is alert level, 1 is alert description
                }
                break;
            }
            r=utils::parse_bytes(e,&self.io[0..self.iolen],ptr);
        }
        return r;
    }

    fn parse_pull(&mut self,n: usize,ptr:&mut usize) -> RET { // get n bytes into self.io
        let mut r=RET{val:0,err:0};
        while *ptr+n>self.iolen {
            let rtn=self.get_record();
            if rtn!=HSHAKE as isize {
                r.err=rtn;
                if rtn==ALERT as isize {
                    r.val=self.io[1] as usize;    // 0 is alert level, 1 is alert description
                }
                break;
            }
        }
        *ptr += n;
        return r;
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

// Add self.io to transcript hash 
    fn running_hash_io(&mut self) {
        sal::hash_process_array(&mut self.tlshash,&self.io[0..self.iolen]);
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
    }

    pub fn create_send_crypto_context(&mut self) {
        self.k_send.init(self.cipher_suite,&self.cts);
    }

    pub fn create_recv_crypto_context(&mut self) {
        self.k_recv.init(self.cipher_suite,&self.sts);
    }
    
// get Client and Server Handshake secrets for encrypting rest of handshake, from Shared secret SS and early secret ES
    pub fn derive_handshake_secrets(&mut self,ss: &[u8],es: &[u8],h: &[u8],hs: &mut [u8]) {
        let dr="derived";
        let ch="c hs traffic";
        let sh="s hs traffic";
        let mut ds:[u8;MAX_HASH]=[0;MAX_HASH];
        let mut emh:[u8;MAX_HASH]=[0;MAX_HASH];
        let htype=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(htype);
        sal::hash_null(htype,&mut emh[0..hlen]);
        keys::hkdf_expand_label(htype,&mut ds[0..hlen],es,dr.as_bytes(),Some(&emh[0..hlen]));
        sal::hkdf_extract(htype,&mut hs[0..hlen],Some(&ds[0..hlen]),ss);
        keys::hkdf_expand_label(htype,&mut self.cts[0..hlen],&hs[0..hlen],ch.as_bytes(),Some(h));
        keys::hkdf_expand_label(htype,&mut self.sts[0..hlen],&hs[0..hlen],sh.as_bytes(),Some(h));
    }

    pub fn derive_application_secrets(&mut self,hs: &[u8],sfh: &[u8],cfh: &[u8],ems: Option<&mut [u8]>) {
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
        keys::hkdf_expand_label(htype,&mut ds[0..hlen],hs,dr.as_bytes(),Some(&emh[0..hlen]));
        sal::hkdf_extract(htype,&mut ms[0..hlen],Some(&ds[0..hlen]),&zk[0..hlen]);
        keys::hkdf_expand_label(htype,&mut self.cts[0..hlen],&ms[0..hlen],ch.as_bytes(),Some(sfh));
        keys::hkdf_expand_label(htype,&mut self.sts[0..hlen],&ms[0..hlen],sh.as_bytes(),Some(sfh));

        if let Some(sems) = ems {
            let eh="exp master";
            keys::hkdf_expand_label(htype,&mut sems[0..hlen],&ms[0..hlen],eh.as_bytes(),Some(sfh));
        }
        keys::hkdf_expand_label(htype,&mut self.rms[0..hlen],&ms[0..hlen],rh.as_bytes(),Some(cfh));
    }

    fn recover_psk(&mut self) { // recover Pre-Shared-Key from Resumption Master Secret
        let rs="resumption";
        let htype=sal::hash_type(self.cipher_suite);
        let hlen=sal::hash_len(htype);
        keys::hkdf_expand_label(htype,&mut self.t.psk[0..hlen],&self.rms[0..hlen],rs.as_bytes(),Some(&self.t.nonce[0..self.t.nnlen]));
    }

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
        self.sockptr.write(&self.io[0..ptr]);
    }   

    pub fn send_client_hello(&mut self,version:usize,ch: &mut [u8],already_agreed: bool,cid: &mut [u8],ext: &[u8],extra: usize,resume: bool) -> usize {
        let mut rn: [u8;32]=[0;32];
        let mut cs: [u8;2+2*MAX_CIPHER_SUITES]=[0;2+2*MAX_CIPHER_SUITES];
        let mut total=8;
        let mut ptr=0;
        let cm=0x0100;
        let extlen=ext.len()+extra;
        let mut ciphers: [usize;MAX_CIPHER_SUITES] = [0;MAX_CIPHER_SUITES];
        let mut nsc=sal::ciphers(&mut ciphers);
        if already_agreed { // cipher suite already agreed
            nsc=1;
            ciphers[0]=self.cipher_suite;
        }
        sal::random_bytes(32,&mut rn);
        total+=32;
        if !resume {
            sal::random_bytes(32,cid);
        }   
        total+=33;
        let clen=extensions::cipher_suites(&mut cs,nsc,&ciphers);
        total+=clen;
        ptr=utils::append_byte(ch,ptr,CLIENT_HELLO,1);
        ptr=utils::append_int(ch,ptr,total+extlen-2,3);
        ptr=utils::append_int(ch,ptr,TLS1_2,2);
        ptr=utils::append_bytes(ch,ptr,&rn[0..32]);
        ptr=utils::append_int(ch,ptr,32,1);
        ptr=utils::append_bytes(ch,ptr,&cid[0..32]);
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
            logger::logger(IO_PROTOCOL,"Handshake Failed\n",0,None);
        }
        if r.err<0 {
            self.send_client_alert(alert_from_cause(r.err));
            return true;
        }
        if r.err == ALERT as isize {
            logger::log_alert(r.val);
            return true;
        }
        if r.err != 0 {
            return true;
        }
        return false;
    }

    pub fn send_client_alert(&mut self,kind: u8) {
        let pt: [u8;2]=[0x02,kind];
        self.send_message(ALERT,TLS1_2,&pt[0..2],None);
    }


// send Change Cipher Suite - helps get past middleboxes
    pub fn send_cccs(&mut self) {
        let cccs:[u8;6]=[0x14,0x03,0x03,0x00,0x01,0x01];
        self.sockptr.write(&cccs);
    }

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

// Send Client Cert Verify 
    fn send_client_cert_verify(&mut self, sigalg: usize,ccvsig: &[u8]) { 
        let mut pt:[u8;8]=[0;8];
        let mut ptr=0;
        ptr=utils::append_byte(&mut pt,ptr,CERT_VERIFY,1); // indicates handshake message "certificate verify"
        ptr=utils::append_int(&mut pt,ptr,4+ccvsig.len(),3); // .. and its length
        ptr=utils::append_int(&mut pt,ptr,sigalg,2);
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

    pub fn build_extensions(&self,ext: &mut [u8],pk: &[u8],expected: &mut EESTATUS,resume: bool) -> usize {
        let psk_mode=PSKWECDHE;
        let tls_version=TLS1_3;
        let http="http/1.1";
        let alpn=http.as_bytes();
        let mut groups:[usize;MAX_CIPHER_SUITES]=[0;MAX_CIPHER_SUITES];
        let mut sig_algs:[usize;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS];
        let mut sig_alg_certs:[usize;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS];
        let mut nsg=sal::groups(&mut groups);
        let nsa=sal::sigs(&mut sig_algs);
        let nsac=sal::sig_certs(&mut sig_alg_certs);
        let mut extlen=0;
        if resume {
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
            extensions::add_rsl(ext,extlen,CLIENT_MAX_RECORD);
        } else {
            extlen=extensions::add_mfl(ext,extlen,MAX_FRAG); expected.max_frag_len=true;
        }
        extlen=extensions::add_padding(ext,extlen,(sal::random_byte()%16) as usize);
        if !resume { // need some signature related extensions for full handshake
            extlen=extensions::add_supported_sigs(ext,extlen,nsa,&sig_algs);
            extlen=extensions::add_supported_sigcerts(ext,extlen,nsac,&sig_alg_certs);            
        }
        return extlen;
    }

    fn get_server_cert_verify(&mut self,scvsig: &mut [u8],siglen: &mut usize,sigalg: &mut usize) -> RET {
        let mut ptr=0;
        let mut r=self.parse_int_pull(3,&mut ptr); if r.err!=0 {return r;}
        r=self.parse_int_pull(2,&mut ptr); *sigalg=r.val; if r.err!=0 {return r;}
        r=self.parse_int_pull(2,&mut ptr); let len=r.val; if r.err!=0 {return r;}
        r=self.parse_bytes_pull(&mut scvsig[0..len],&mut ptr); if r.err!=0 {return r;}
        *siglen=len;
        sal::hash_process_array(&mut self.tlshash,&self.io[0..ptr]);
        self.iolen=utils::shift_left(&mut self.io[0..self.iolen],ptr);
        r.val=CERT_VERIFY as usize;
        return r;
    }

    fn get_certificate_request(&mut self, nalgs: &mut usize,sigalgs: &mut [usize]) -> RET {
        let mut ptr=0;
        let mut unexp=0;
        let mut r=self.parse_int_pull(3,&mut ptr); if r.err!=0 {return r;}
        r=self.parse_int_pull(1,&mut ptr); let nb=r.val; if r.err!=0 {return r;}
        if nb!=0 {
            r.err=MISSING_REQUEST_CONTEXT;// expecting 0x00 Request context
            return r;
        }
        r=self.parse_int_pull(2,&mut ptr); let mut len=r.val; if r.err!=0 {return r;} // length of extensions
        let mut algs=0;
        while len>0 {
            r=self.parse_int_pull(2,&mut ptr); let ext=r.val; if r.err!=0 {return r;}
            len-=2;
            match ext {
                SIG_ALGS => {
                    r=self.parse_int_pull(2,&mut ptr); let tlen=r.val; if r.err!=0 {return r;}
                    len-=2;
                    r=self.parse_int_pull(2,&mut ptr); algs=r.val/2; if r.err!=0 {return r;}
                    len-=2;
                    for i in 0..algs {
                        r=self.parse_int_pull(2,&mut ptr); if r.err!=0 {return r;}
                        if i<MAX_SUPPORTED_SIGS {
                            sigalgs[i]=r.val;
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
                    r=self.parse_int_pull(2,&mut ptr); let tlen=r.val;
                    len-=2;
                    len-=tlen; ptr+=tlen;
                    unexp+=1;
                }
            }
            if r.err!=0 {return r;}
        }
        sal::hash_process_array(&mut self.tlshash,&self.io[0..ptr]);
        self.iolen=utils::shift_left(&mut self.io[0..self.iolen],ptr);
        r.val=CERT_REQUEST as usize;
        if algs==0 {
            r.err=UNRECOGNIZED_EXT;
            return r;
        }
        if unexp>0 {
            logger::logger(IO_DEBUG,"Unrecognized extensions received\n",0,None);
        }
        *nalgs=algs;
        return r;
    }

// Get handshake finish verifier data in hfin
    fn get_server_finished(&mut self,hfin: &mut [u8],hflen: &mut usize) -> RET {
        let mut ptr=0;
        let mut r=self.get_whats_next(); let nb=r.val; if r.err!=0 {return r;}
        if nb!=FINISHED as usize {
            r.err=WRONG_MESSAGE;
            return r;
        }
        r=self.parse_int_pull(3,&mut ptr); let len=r.val; if r.err!=0 {return r;}
        r=self.parse_bytes_pull(&mut hfin[0..len],&mut ptr); if r.err!=0 {return r;}
        *hflen=len;
        sal::hash_process_array(&mut self.tlshash,&self.io[0..ptr]);
        self.iolen=utils::shift_left(&mut self.io[0..self.iolen],ptr);
        r.val=FINISHED as usize;
        return r;
    }

// Receive a single record. Could be fragment of a full message. Could be encrypted
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
            return MEM_OVERFLOW;   // record is too big - memory overflow
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
    fn get_server_hello(&mut self,kex: &mut usize,cid: &[u8],cookie: &mut [u8],cklen:&mut usize,pk: &mut [u8],pskid: &mut isize) -> RET {
        let mut hrr: [u8; HRR.len()/2]=[0;HRR.len()/2];
        let mut srn: [u8;32]=[0;32];
        let mut sid: [u8;32]=[0;32];
        utils::decode_hex(&mut hrr,&HRR);
        let mut ptr=0;
        self.iolen=0;
        let mut r=self.parse_int_pull(1,&mut ptr);  if r.err!=0 {return r;}
        if r.val!=SERVER_HELLO as usize { // should be Server Hello
            r.err=BAD_HELLO;
            return r;
        }
        r=self.parse_int_pull(3,&mut ptr); let mut left=r.val; if r.err!=0 {return r;} // If not enough, pull in another fragment
        r=self.parse_int_pull(2,&mut ptr); let svr=r.val; if r.err!=0 {return r;}
        left-=2;                // whats left in message
        if svr!=TLS1_2 { 
            r.err=NOT_TLS1_3;  // don't ask
            return r;
        }
        r= self.parse_bytes_pull(&mut srn,&mut ptr); if r.err!=0 {return r;}
        left-=32;
        let mut retry=false;
        if srn==hrr {
            retry=true;
        }
        r=self.parse_int_pull(1,&mut ptr); let silen=r.val; if r.err!=0 || silen!=32 {return r;}
        left-=1;
        r=self.parse_bytes_pull(&mut sid[0..silen],&mut ptr); if r.err!=0 {return r;}
        left-=silen;  
        if cid!=sid {
            r.err=ID_MISMATCH;
            return r;
        }
        r=self.parse_int_pull(2,&mut ptr); let cipher=r.val; if r.err!=0 {return r;}
        left-=2;
	    if self.cipher_suite!=0 { // don't allow a change after initial assignment
		    if cipher!=self.cipher_suite
		    {
			    r.err=BAD_HELLO;
			    return r;
		    }
	    }
	    self.cipher_suite=cipher;
        r=self.parse_int_pull(1,&mut ptr); let cmp=r.val; if r.err!=0 {return r;}
        left-=1; // Compression not used in TLS1.3
        if cmp!=0  { 
            r.err=NOT_TLS1_3;  // don't ask
            return r;
        }
        r=self.parse_int_pull(2,&mut ptr); let mut extlen=r.val; if r.err!=0 {return r;}
        left-=2;  
        if left!=extlen { // Check space left is size of extensions
            r.err=BAD_HELLO;
            return r;
        }

        while extlen>0 {
            r=self.parse_int_pull(2,&mut ptr); let ext=r.val; if r.err!=0 {return r;} 
            extlen-=2;
            r=self.parse_int_pull(2,&mut ptr); let tmplen=r.val; if r.err!=0 {break;} 
            extlen-=2;
            extlen-=tmplen;
            match ext {
                KEY_SHARE => {
                    r=self.parse_int_pull(2,&mut ptr); *kex=r.val; if r.err!=0 {break;}
                    if !retry { // its not a retry request
                        r=self.parse_int_pull(2,&mut ptr); let pklen=r.val; if r.err!=0 || pklen!=pk.len() {break;}
                        r=self.parse_bytes_pull(pk,&mut ptr);
                    }
                },
                PRESHARED_KEY => {
                    r=self.parse_int_pull(2,&mut ptr); *pskid=r.val as isize;
                },
                COOKIE => {
                    r=self.parse_bytes_pull(&mut cookie[0..tmplen],&mut ptr); *cklen=tmplen;
                },
                TLS_VER => {
                    r=self.parse_int_pull(2,&mut ptr); let tls=r.val; if r.err!=0 {break;}
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

// Find out whats coming next
    pub fn get_whats_next(&mut self) -> RET {
        let mut ptr=0;
        let mut r=self.parse_int_pull(1,&mut ptr);
        if r.err!=0 {return r;}
        let nb=r.val as u8;
        if nb==END_OF_EARLY_DATA || nb==KEY_UPDATE { // Servers MUST NOT send this.... KEY_UPDATE should not happen at this stage
            r.err=WRONG_MESSAGE;
            return r;
        }
        let mut b:[u8;1]=[0;1];
        b[0]=nb;
        sal::hash_process_array(&mut self.tlshash,&b[0..1]);
        self.iolen=utils::shift_left(&mut self.io[0..self.iolen],ptr);

        return r;
    }

// Process server's encrypted extensions
    pub fn get_server_encrypted_extensions(&mut self,expected: &EESTATUS,response: &mut EESTATUS) -> RET {
        let mut ptr=0;
        let mut _unexp=0;

        for i in 0..self.iolen {
            self.io[i]=0;
        }

        self.iolen=0;
        let mut r=self.get_whats_next();    
        if r.err!=0 {return r;}
        let nb=r.val as u8;

        r=self.parse_int_pull(3,&mut ptr); if r.err!=0 {return r;}
        response.early_data=false;
        response.alpn=false;
        response.server_name=false;
        response.max_frag_len=false;
        if nb != ENCRYPTED_EXTENSIONS {
            r.err=WRONG_MESSAGE;
            return r;
        }

        r=self.parse_int_pull(2,&mut ptr); let mut len=r.val; if r.err!=0 {return r;}

// extension could include Servers preference for supported groups, which could be
// taken into account by the client for later connections. Here we will ignore it. From RFC:
// "Clients MUST NOT act upon any information found in "supported_groups" prior to successful completion of the handshake"

        while len!=0 {
            r=self.parse_int_pull(2,&mut ptr); let ext=r.val; if r.err!=0 {return r;}
            len-=2;
            r=self.parse_int_pull(2,&mut ptr); let tlen=r.val; if r.err!=0 {return r;}
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
                    r=self.parse_int_pull(1,&mut ptr); if r.err!=0 {return r;}
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
                    r=self.parse_int_pull(2,&mut ptr); let mfl=r.val; if r.err!=0 {return r;}
                    len-=tlen;
                    if tlen!=2 || mfl<64 {
                        r.err=UNRECOGNIZED_EXT;
                        return r;
                    }
                    self.server_max_record=mfl;
                },
                APP_PROTOCOL => {
                    let mut name:[u8;256]=[0;256];
                    r=self.parse_int_pull(2,&mut ptr); if r.err!=0 {return r;}
                    r=self.parse_int_pull(1,&mut ptr); let mfl=r.val; if r.err!=0 {return r;}
                    r=self.parse_bytes_pull(&mut name[0..mfl],&mut ptr); if r.err!=0 {return r;}
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
                    len-=tlen; ptr +=tlen; // skip over it
                    _unexp+=1;
                }
            }
            if r.err!=0 {return r;}
        }
// Update Transcript hash
        sal::hash_process_array(&mut self.tlshash,&self.io[0..ptr]);
        self.iolen=utils::shift_left(&mut self.io[0..self.iolen],ptr); // rewind io buffer
        r.val=nb as usize;

        return r;
    }

// Get certificate chain, and check its validity 
    pub fn get_check_server_certificatechain(&mut self,spk:&mut [u8],spklen: &mut usize) -> RET {
        let mut ptr=0;
        let mut r=self.parse_int_pull(3,&mut ptr); let mut len=r.val; if r.err!=0 {return r;}         // message length   
        logger::logger(IO_DEBUG,"Certificate Chain Length= ",len as isize,None);
        r=self.parse_int_pull(1,&mut ptr); let nb=r.val; if r.err!=0 {return r;} 
        if nb!=0x00 {
            r.err=MISSING_REQUEST_CONTEXT;// expecting 0x00 Request context
            return r;
        }
        r=self.parse_int_pull(3,&mut ptr); len=r.val; if r.err!=0 {return r;}   // get length of certificate chain
	    if len==0 {
		    r.err=EMPTY_CERT_CHAIN;
		    return r;
	    }
        let start=ptr;
        r=self.parse_pull(len,&mut ptr); if r.err!=0 {return r;} // get pointer to certificate chain, and pull it all into self.io
// Update Transcript hash
        sal::hash_process_array(&mut self.tlshash,&self.io[0..ptr]);
        r.err=certchain::check_server_certchain(&self.io[start..start+len],&self.hostname[0..self.hlen],spk,spklen);
        self.iolen=utils::shift_left(&mut self.io[0..self.iolen],ptr); // rewind io buffer
        r.val=CERTIFICATE as usize;
        return r;
    }
// clean up buffers, kill crypto keys
    fn clean(&mut self) {
// clean up buffers, kill crypto keys
        for i in 0..self.iolen {
            self.io[i]=0;
        }
        for i in 0..MAX_HASH {
            self.cts[i]=0;
            self.sts[i]=0;
            self.rms[i]=0
        }
        self.k_send.clear();
        self.k_recv.clear();
    }

    fn clean_io(&mut self) {
        for i in 0..self.iolen {
            self.io[i]=0;
        }        
    }

    pub fn tls_resume(&mut self,early: Option<&[u8]>) -> usize {
        let mut expected=EESTATUS{early_data:false,alpn:false,server_name:false,max_frag_len:false};
        let mut response=EESTATUS{early_data:false,alpn:false,server_name:false,max_frag_len:false};
        let mut have_early_data=false;
        logger::logger(IO_PROTOCOL,"Attempting Resumption Handshake\n",0,None);
        logger::log_ticket(&self.t); 

        let mut ext:[u8;MAX_EXTENSIONS]=[0;MAX_EXTENSIONS];
        let mut ch: [u8; MAX_CLIENT_HELLO] = [0; MAX_CLIENT_HELLO]; 
        let mut csk: [u8;MAX_SECRET_KEY]=[0;MAX_SECRET_KEY];
        let mut pk: [u8;MAX_PUBLIC_KEY]=[0;MAX_PUBLIC_KEY];
        let mut ss: [u8;MAX_SHARED_SECRET_SIZE]=[0;MAX_SHARED_SECRET_SIZE];
        let mut cid: [u8;32]=[0;32];
        let mut cookie: [u8;MAX_COOKIE]=[0;MAX_COOKIE];

// Extract Ticket parameters
        let lifetime=self.t.lifetime;
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

// extract slices..
        let mut hh: [u8;MAX_HASH]=[0;MAX_HASH]; let hh_s=&mut hh[0..hlen];
        let mut hs: [u8;MAX_HASH]=[0;MAX_HASH]; let hs_s=&mut hs[0..hlen];
        let mut fh: [u8;MAX_HASH]=[0;MAX_HASH]; let fh_s=&mut fh[0..hlen];
        let mut th: [u8;MAX_HASH]=[0;MAX_HASH]; let th_s=&mut th[0..hlen];
        let mut bk:[u8;MAX_HASH]=[0;MAX_HASH]; let bk_s=&mut bk[0..hlen];
        let mut es:[u8;MAX_HASH]=[0;MAX_HASH]; let es_s=&mut es[0..hlen];
        let mut bnd:[u8;MAX_HASH]=[0;MAX_HASH]; let bnd_s=&mut bnd[0..hlen];
        let mut cets:[u8;MAX_HASH]=[0;MAX_HASH]; let cets_s=&mut cets[0..hlen];
        let mut chf:[u8;MAX_HASH]=[0;MAX_HASH]; let chf_s=&mut chf[0..hlen];
        let mut psk:[u8;MAX_HASH]=[0;MAX_HASH]; 
        for i in 0..hlen {
            psk[i]=self.t.psk[i];
        }
        let psk_s=&mut psk[0..hlen];
        let mut bl:[u8;MAX_HASH+3]=[0;MAX_HASH+3];

        self.init_transcript_hash();
        let mut external_psk=false;
        if time_ticket_received==0 && age_obfuscator==0 { // its an external PSK
            external_psk=true;
            keys::derive_early_secrets(htype,Some(psk_s),es_s,Some(bk_s),None);
        } else {
            external_psk=false;
            keys::derive_early_secrets(htype,Some(psk_s),es_s,None,Some(bk_s));   // compute early secret and Binder Key from PSK
        }
        logger::logger(IO_DEBUG,"PSK= ",0,Some(psk_s)); 
        logger::logger(IO_DEBUG,"Binder Key= ",0,Some(bk_s)); 
        logger::logger(IO_DEBUG,"Early Secret= ",0,Some(es_s));

// Generate key pair in favourite group - use same favourite group that worked before for this server - so should be no HRR
        let mut sklen=sal::secret_key_size(self.favourite_group);   // may change on a handshake retry
        let mut pklen=sal::public_key_size(self.favourite_group);
        let mut sslen=sal::shared_secret_size(self.favourite_group);
        let pk_s=&mut pk[0..pklen];
        let csk_s=&mut csk[0..sklen];
        let ss_s=&mut ss[0..sslen];
        sal::generate_key_pair(self.favourite_group,csk_s,pk_s);
        logger::logger(IO_DEBUG,"Private Key= ",0,Some(csk_s));
        logger::logger(IO_DEBUG,"Client Public Key= ",0,Some(pk_s));

// Client Hello
// First build standard client Hello extensions
	    let mut extlen=self.build_extensions(&mut ext,pk_s,&mut expected,true);
        if have_early_data {
            extlen=extensions::add_early_data(&mut ext,extlen); expected.early_data=true;                 // try sending client message as early data if allowed
        }
        let mut age=0;
        if !external_psk { // Its an external pre-shared key
            let time_ticket_used=ticket::millis();
            age=time_ticket_used-time_ticket_received; // age of ticket in milliseconds - problem for some sites which work for age=0 ??
            logger::logger(IO_DEBUG,"Ticket age= ",age as isize,None);
            age+=age_obfuscator;
            logger::logger(IO_DEBUG,"obfuscated age = ",age as isize,None);
        }
        let mut extra=0;
        extlen=extensions::add_presharedkey(&mut ext,extlen,age,&self.t.tick[0..self.t.tklen],hlen,&mut extra);

// create and send Client Hello octad
        let chlen=self.send_client_hello(TLS1_2,&mut ch,true,&mut cid,&ext[0..extlen],extra,false);  
// extract slices..

        self.running_hash(&ch[0..chlen]); 
        self.running_hash(&ext[0..extlen]);
        self.transcript_hash(hh_s); // hh = hash of Truncated clientHello
        logger::logger(IO_DEBUG,"Client Hello sent\n",0,None);
        keys::derive_verifier_data(htype,bnd_s,bk_s,hh_s);  
        let blen=self.send_binder(&mut bl,bnd_s);
        self.running_hash(&bl[0..blen]);
        self.transcript_hash(hh_s); // hh = hash of Truncated clientHello

        logger::logger(IO_DEBUG,"BND= ",0,Some(bnd_s));
        logger::logger(IO_DEBUG,"Sending Binders\n",0,None);   // only sending one

        if have_early_data {
            self.send_cccs();
        }

        keys::derive_later_secrets(htype,es_s,hh_s,Some(cets_s),None);   // Get Client Early Traffic Secret from transcript hash and ES
        logger::logger(IO_DEBUG,"Client Early Traffic Secret= ",0,Some(cets_s)); 
        self.k_send.init(self.cipher_suite,cets_s);


// if its allowed, send client message as (encrypted!) early data
        if have_early_data {
            logger::logger(IO_APPLICATION,"Sending some early data\n",0,None);
            if let Some(searly) = early {
                self.send_message(APPLICATION,TLS1_2,searly,None);
            }
        }
// Process Server Hello
        let mut kex=0;
        let mut pskid:isize=-1;
        let mut cklen=0;
        let mut rtn = self.get_server_hello(&mut kex,&cid,&mut cookie,&mut cklen,pk_s,&mut pskid);
  
        self.running_hash_io();         // Hashing Server Hello
        self.transcript_hash(hh_s);     // HH = hash of clientHello+serverHello

        if pskid<0 { // Ticket rejected by Server (as out of date??)
            logger::logger(IO_PROTOCOL,"Ticket rejected by server\n",0,None);
            self.send_client_alert(CLOSE_NOTIFY);
            logger::logger(IO_PROTOCOL,"Resumption Handshake failed\n",0,None);
            self.clean();
            return TLS_FAILURE;
        }

	    if pskid>0 { // pskid out-of-range (only one allowed)
            self.send_client_alert(ILLEGAL_PARAMETER);
            logger::logger(IO_PROTOCOL,"Resumption Handshake failed\n",0,None);
            self.clean();
            return TLS_FAILURE;
	    }
        if self.bad_response(&rtn) {
            self.send_client_alert(CLOSE_NOTIFY);
            self.clean();
            return TLS_FAILURE;
        }   
        logger::log_server_hello(self.cipher_suite,kex,pskid,pk_s,&cookie[0..cklen]);

        if rtn.val==HANDSHAKE_RETRY || kex!=self.favourite_group { // should not happen
            self.send_client_alert(UNEXPECTED_MESSAGE);
            logger::logger(IO_DEBUG,"No change possible as result of HRR\n",0,None); 
            logger::logger(IO_PROTOCOL,"Resumption Handshake failed\n",0,None);
            self.clean();
            return TLS_FAILURE;
        }
        logger::logger(IO_DEBUG,"serverHello= ",0,Some(&self.io[0..self.iolen])); 

// Generate Shared secret SS from Client Secret Key and Server's Public Key
        sal::generate_shared_secret(kex,csk_s,pk_s,ss_s); 
        logger::logger(IO_DEBUG,"Shared Secret= ",0,Some(ss_s));

        self.derive_handshake_secrets(ss_s,es_s,hh_s,hs_s); 
        self.create_recv_crypto_context();

        logger::logger(IO_DEBUG,"Handshake Secret= ",0,Some(hs_s));
        logger::logger(IO_DEBUG,"Client handshake traffic secret= ",0,Some(&self.cts[0..hlen]));
        logger::logger(IO_DEBUG,"Server handshake traffic secret= ",0,Some(&self.sts[0..hlen]));

        let mut rtn=self.get_server_encrypted_extensions(&expected,&mut response);

        if self.bad_response(&rtn) {
            self.clean();
            return TLS_FAILURE;
        }
        logger::log_enc_ext(&expected,&response);
        logger::logger(IO_DEBUG,"Encrypted extensions processed\n",0,None);

        let mut fnlen=0;
        let mut fin:[u8;MAX_HASH]=[0;MAX_HASH];
        rtn=self.get_server_finished(&mut fin,&mut fnlen);
        let fin_s=&fin[0..fnlen];
        if self.bad_response(&rtn) {
            self.clean();
            return TLS_FAILURE;
        }

// Now indicate End of Early Data, encrypted with 0-RTT keys
        self.transcript_hash(hh_s); // hash of clientHello+serverHello+encryptedExtension+serverFinish
        if response.early_data {
            self.send_end_early_data();     // Should only be sent if server has accepted Early data - see encrypted extensions!
            logger::logger(IO_DEBUG,"Send End of Early Data \n",0,None);
        }
        self.transcript_hash(th_s); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData
        logger::logger(IO_DEBUG,"Transcript Hash (CH+SH+EE+SF+ED) = ",0,Some(th_s)); 

// Switch to handshake keys
        self.create_send_crypto_context();
        if !keys::check_verifier_data(htype,fin_s,&self.sts[0..hlen],fh_s) {
            self.send_client_alert(DECRYPT_ERROR);
            logger::logger(IO_DEBUG,"Server Data is NOT verified\n",0,None);
            logger::logger(IO_PROTOCOL,"Resumption Handshake failed\n",0,None);
            self.clean();
            return TLS_FAILURE;
        }

        keys::derive_verifier_data(htype,chf_s,&self.cts[0..hlen],th_s);
        self.send_client_finish(chf_s);
        logger::logger(IO_DEBUG,"Server Data is verified\n",0,None);
        logger::logger(IO_DEBUG,"Client Verify Data= ",0,Some(chf_s)); 

        self.transcript_hash(fh_s); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData+clientFinish

// calculate traffic and application keys from handshake secret and transcript hashes, and store in session
        self.derive_application_secrets(hs_s,hh_s,fh_s,None);
        self.create_send_crypto_context();
        self.create_recv_crypto_context();

        logger::logger(IO_DEBUG,"Client application traffic secret= ",0,Some(&self.cts[0..hlen]));
        logger::logger(IO_DEBUG,"Server application traffic secret= ",0,Some(&self.sts[0..hlen]));
        logger::logger(IO_PROTOCOL,"RESUMPTION Handshake succeeded\n",0,None);
        self.clean_io();

        if response.early_data {
            logger::logger(IO_PROTOCOL,"Application Message accepted as Early Data\n\n",-1,early);
            return TLS_EARLY_DATA_ACCEPTED;
        }
        return TLS_SUCCESS;
    }

    pub fn tls_full(&mut self) -> usize {
        let mut groups:[usize;MAX_CIPHER_SUITES]=[0;MAX_CIPHER_SUITES];
        let mut ciphers:[usize;MAX_SUPPORTED_GROUPS]=[0;MAX_SUPPORTED_GROUPS];
        let mut scvsig:[u8;MAX_SIGNATURE_SIZE]=[0;MAX_SIGNATURE_SIZE];
        let _nsg=sal::groups(&mut groups);
        let nsc=sal::ciphers(&mut ciphers);
        let mut ccs_sent=false;
        let mut resumption_required=false;
        let mut expected=EESTATUS{early_data:false,alpn:false,server_name:false,max_frag_len:false};
        let mut response=EESTATUS{early_data:false,alpn:false,server_name:false,max_frag_len:false};
        let mut ch: [u8; MAX_CLIENT_HELLO] = [0; MAX_CLIENT_HELLO]; 
        let mut csk: [u8;MAX_SECRET_KEY]=[0;MAX_SECRET_KEY];
        let mut pk: [u8;MAX_PUBLIC_KEY]=[0;MAX_PUBLIC_KEY];
        let mut ss: [u8;MAX_SHARED_SECRET_SIZE]=[0;MAX_SHARED_SECRET_SIZE];

        logger::logger(IO_PROTOCOL,"Attempting Full Handshake\n",0,None);
        self.favourite_group=groups[0];   // start out with first one.
        let mut sklen=sal::secret_key_size(self.favourite_group);   // may change on a handshake retry
        let mut pklen=sal::public_key_size(self.favourite_group);
        let mut sslen=sal::shared_secret_size(self.favourite_group);
        sal::generate_key_pair(self.favourite_group,&mut csk[0..sklen],&mut pk[0..pklen]);
        logger::logger(IO_DEBUG,"Private Key= ",0,Some(&csk[0..sklen]));
        logger::logger(IO_DEBUG,"Client Public Key= ",0,Some(&pk[0..pklen]));
        let mut cid: [u8;32]=[0;32];
        let mut ext: [u8;MAX_EXTENSIONS]=[0;MAX_EXTENSIONS];
        let mut cookie: [u8;MAX_COOKIE]=[0;MAX_COOKIE];
        let mut spk: [u8; MAX_SERVER_PUB_KEY]=[0;MAX_SERVER_PUB_KEY];
// add chosen extensions
        let mut extlen=self.build_extensions(&mut ext,&pk[0..pklen],&mut expected,false);
// build and transmit client hello
        let mut chlen=self.send_client_hello(TLS1_0,&mut ch,false,&mut cid,&ext[0..extlen],0,false);
        logger::logger(IO_DEBUG,"Client Hello sent\n",0,None);
// process server hello
        let mut kex=0;
        let mut pskid:isize=-1;
        let mut cklen=0;
        let mut rtn = self.get_server_hello(&mut kex,&cid,&mut cookie,&mut cklen,&mut pk[0..pklen],&mut pskid);
        if self.bad_response(&rtn) {
            self.clean();
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
            self.send_client_alert(ILLEGAL_PARAMETER);
            logger::log_cipher_suite(self.cipher_suite);
            logger::logger(IO_DEBUG,"Cipher Suite not valid\n",0,None);
            logger::logger(IO_PROTOCOL,"Full Handshake failed\n",0,None);
            self.clean();
            return TLS_FAILURE;
        }
        logger::log_cipher_suite(self.cipher_suite);
// extract slices..
        let mut hh: [u8;MAX_HASH]=[0;MAX_HASH]; let hh_s=&mut hh[0..hlen];
        let mut hs: [u8;MAX_HASH]=[0;MAX_HASH]; let hs_s=&mut hs[0..hlen];
        let mut fh: [u8;MAX_HASH]=[0;MAX_HASH]; let fh_s=&mut fh[0..hlen];
        let mut th: [u8;MAX_HASH]=[0;MAX_HASH]; let th_s=&mut th[0..hlen];
        let mut chf: [u8;MAX_HASH]=[0;MAX_HASH]; let chf_s=&mut chf[0..hlen];
        let mut es: [u8;MAX_HASH]=[0;MAX_HASH]; let es_s=&mut es[0..hlen];
        keys::derive_early_secrets(hash_type,None,es_s,None,None);
        logger::logger(IO_DEBUG,"Early secret= ",0,Some(es_s));
// Initialise Transcript Hash
// For Transcript hash we must use cipher-suite hash function
        self.init_transcript_hash();
        if rtn.val==HANDSHAKE_RETRY { // Was server hello actually an hello retry request?
            self.running_synthetic_hash(&ch[0..chlen],&ext[0..extlen]);
            self.running_hash_io();
            if kex==self.favourite_group { // Its the same again
                self.send_client_alert(ILLEGAL_PARAMETER);
                logger::logger(IO_DEBUG,"No change as result of HRR\n",0,None);
                logger::logger(IO_PROTOCOL,"Full Handshake failed\n",0,None);
                self.clean();
                return TLS_FAILURE;
            }
            logger::logger(IO_DEBUG,"Server Hello Retry Request= ",0,Some(&self.io[0..self.iolen]));
            self.favourite_group=kex;
            sklen=sal::secret_key_size(self.favourite_group);   // probably changed on a handshake retry
            pklen=sal::public_key_size(self.favourite_group);
            sslen=sal::shared_secret_size(self.favourite_group);
            sal::generate_key_pair(self.favourite_group,&mut csk[0..sklen],&mut pk[0..pklen]);
            extlen=self.build_extensions(&mut ext,&pk[0..pklen],&mut expected,false);
            if cklen!=0 { // there was a cookie in the HRR ... so send it back in an extension
                extlen=extensions::add_cookie(&mut ext,extlen,&cookie[0..cklen]);
            }
            self.send_cccs();
            ccs_sent=true;
// send new client hello
            chlen=self.send_client_hello(TLS1_2,&mut ch,true,&mut cid,&ext[0..extlen],0,true);
            logger::logger(IO_DEBUG,"Client Hello re-sent\n",0,None);
// get new server hello
            rtn=self.get_server_hello(&mut kex,&cid,&mut cookie,&mut cklen,&mut pk[0..pklen],&mut pskid);
            if self.bad_response(&rtn) {
                self.clean();
                return TLS_FAILURE;
            }
            if rtn.val==HANDSHAKE_RETRY {
                logger::logger(IO_DEBUG,"A second Handshake Retry Request?\n",0,None);
                self.send_client_alert(UNEXPECTED_MESSAGE);
                logger::logger(IO_PROTOCOL,"Full Handshake failed\n",0,None);
                self.clean();
                return TLS_FAILURE;
            }
            resumption_required=true;
        }
        self.running_hash(&ch[0..chlen]);
        self.running_hash(&ext[0..extlen]);
        self.running_hash_io();
        self.transcript_hash(hh_s);
        let pk_s=&pk[0..pklen];
        let csk_s=&csk[0..sklen];
        let ss_s=&mut ss[0..sslen];
        logger::logger(IO_DEBUG,"Server Hello= ",0,Some(&self.io[0..self.iolen]));
        logger::log_server_hello(self.cipher_suite,kex,pskid,pk_s,&cookie[0..cklen]);
        sal::generate_shared_secret(self.favourite_group,csk_s,pk_s,ss_s);
        logger::logger(IO_DEBUG,"Shared Secret= ",0,Some(ss_s));
        self.derive_handshake_secrets(ss_s,es_s,hh_s,hs_s);
        self.create_send_crypto_context();
        self.create_recv_crypto_context();
        logger::logger(IO_DEBUG,"Handshake secret= ",0,Some(hs_s));
        logger::logger(IO_DEBUG,"Client Handshake Traffic secret= ",0,Some(&self.cts[0..hlen]));
        logger::logger(IO_DEBUG,"Server Handshake Traffic secret= ",0,Some(&self.sts[0..hlen]));
        let mut rtn=self.get_server_encrypted_extensions(&expected,&mut response);

        if self.bad_response(&rtn) {
            self.clean();
            return TLS_FAILURE;
        }
        logger::log_enc_ext(&expected,&response);
        logger::logger(IO_DEBUG,"Encrypted extensions processed\n",0,None);
        rtn=self.get_whats_next();
        if self.bad_response(&rtn) {
            self.clean();
            return TLS_FAILURE;
        }
        let mut nccsalgs=0;
        let mut csigalgs:[usize;MAX_SUPPORTED_SIGS]=[0;MAX_SUPPORTED_SIGS];
        let mut gotacertrequest=false;
        if rtn.val == CERT_REQUEST as usize {
            gotacertrequest=true;
            rtn=self.get_certificate_request(&mut nccsalgs,&mut csigalgs);
            if self.bad_response(&rtn) {
                self.clean();
                return TLS_FAILURE;
            }
            logger::logger(IO_PROTOCOL,"Certificate Request received\n",0,None);
            rtn=self.get_whats_next();
            if self.bad_response(&rtn) {
                self.clean();
                return TLS_FAILURE;
            }
        }
        if rtn.val != CERTIFICATE as usize {
            self.send_client_alert(alert_from_cause(WRONG_MESSAGE));
            logger::logger(IO_PROTOCOL,"Full Handshake failed\n",0,None);
            self.clean();
            return TLS_FAILURE;
        }
        let mut spklen=0;
        rtn=self.get_check_server_certificatechain(&mut spk,&mut spklen);
        if self.bad_response(&rtn) {
            self.clean();
            return TLS_FAILURE;
        }
        let spk_s=&spk[0..spklen];
        self.transcript_hash(hh_s);
        logger::logger(IO_DEBUG,"Certificate Chain is valid\n",0,None);
        logger::logger(IO_DEBUG,"Transcript Hash (CH+SH+EE+CT) = ",0,Some(hh_s));  
        rtn=self.get_whats_next();
        if self.bad_response(&rtn) {
            self.clean();
            return TLS_FAILURE;
        }
        if rtn.val != CERT_VERIFY as usize {
            self.send_client_alert(alert_from_cause(WRONG_MESSAGE));
            logger::logger(IO_PROTOCOL,"Full Handshake failed\n",0,None);
            self.clean();
            return TLS_FAILURE;
        }
        let mut siglen=0;
        let mut sigalg=0;
        rtn=self.get_server_cert_verify(&mut scvsig,&mut siglen,&mut sigalg);
        if self.bad_response(&rtn) {
            self.clean();
            return TLS_FAILURE;
        }
        let scvsig_s=&mut scvsig[0..siglen];
        self.transcript_hash(fh_s);
        logger::logger(IO_DEBUG,"Transcript Hash (CH+SH+EE+SCT+SCV) = ",0,Some(fh_s));
        logger::logger(IO_DEBUG,"Server Certificate Signature = ",0,Some(scvsig_s));
        logger::log_sig_alg(sigalg);
        if !keys::check_server_cert_verifier(sigalg,scvsig_s,hh_s,spk_s) {
            self.send_client_alert(DECRYPT_ERROR);
            logger::logger(IO_DEBUG,"Server Cert Verification failed\n",0,None);
            logger::logger(IO_PROTOCOL,"Full Handshake failed\n",0,None);
            self.clean();
            return TLS_FAILURE;
        }
        logger::logger(IO_DEBUG,"Server Cert Verification OK\n",0,None);

        let mut fnlen=0;
        let mut fin:[u8;MAX_HASH]=[0;MAX_HASH];
        rtn=self.get_server_finished(&mut fin,&mut fnlen);
        let fin_s=&fin[0..fnlen];
        if self.bad_response(&rtn) {
            self.clean();
            return TLS_FAILURE;
        }
        if !keys::check_verifier_data(hash_type,fin_s,&self.sts[0..hlen],fh_s) {
            self.send_client_alert(DECRYPT_ERROR);
            logger::logger(IO_DEBUG,"Server Data is NOT verified\n",0,None);
            logger::logger(IO_DEBUG,"Full Handshake failed\n",0,None);
            self.clean();
            return TLS_FAILURE;
        }
        logger::logger(IO_DEBUG,"\nServer Data is verified\n",0,None);
        if !ccs_sent {
            self.send_cccs();
        }
        self.transcript_hash(hh_s);
        if gotacertrequest {
            if HAVE_CLIENT_CERT {
                let mut client_key:[u8;MAX_MYCERT_SIZE]=[0;MAX_MYCERT_SIZE];
                let mut client_certchain:[u8;MAX_MYCERT_SIZE]=[0;MAX_MYCERT_SIZE];
                let mut ccvsig:[u8;MAX_SIGNATURE_SIZE]=[0;MAX_SIGNATURE_SIZE];
                let mut cclen=0;
                let mut cklen=0;
                let kind=certchain::get_client_credentials(&csigalgs[0..nccsalgs],&mut client_key,&mut cklen,&mut client_certchain,&mut cclen);
                if kind!=0 { // Yes, I can do that signature
                    logger::logger(IO_PROTOCOL,"Client is authenticating\n",0,None);
                    let cc_s=&client_certchain[0..cclen];
                    let ck_s=&client_key[0..cklen];
                    self.send_client_certificate(Some(cc_s));
                    self.transcript_hash(th_s);
                    let cclen=keys::create_client_cert_verifier(kind,th_s,ck_s,&mut ccvsig);
                    self.send_client_cert_verify(kind,&ccvsig[0..cclen]);
                } else { // No, I can't - send a null cert
                    self.send_client_certificate(None);
                }
            } else {
                self.send_client_certificate(None);
            }
            self.transcript_hash(th_s);
        } else {
            for i in 0..hlen {
                th_s[i]=hh_s[i];
            }
        }
        logger::logger(IO_DEBUG,"Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]) = ",0,Some(th_s));
        keys::derive_verifier_data(hash_type,chf_s,&self.cts[0..hlen],th_s);
        self.send_client_finish(chf_s);
        logger::logger(IO_DEBUG,"Client Verify Data= ",0,Some(chf_s)); 
        self.transcript_hash(fh_s);
        logger::logger(IO_DEBUG,"Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]+CF) = ",0,Some(fh_s));
        self.derive_application_secrets(hs_s,hh_s,fh_s,None);
        self.create_send_crypto_context();
        self.create_recv_crypto_context();
        logger::logger(IO_DEBUG,"Client application traffic secret= ",0,Some(&self.cts[0..hlen]));
        logger::logger(IO_DEBUG,"Server application traffic secret= ",0,Some(&self.sts[0..hlen]));
        logger::logger(IO_PROTOCOL,"FULL Handshake succeeded\n",0,None);
        self.clean_io();
        if resumption_required { 
            logger::logger(IO_PROTOCOL,"... after handshake resumption\n",0,None);
            return TLS_RESUMPTION_REQUIRED;
        }
        return TLS_SUCCESS;
    }

// connect to server
// first try resumption if session has a good ticket attached
    pub fn connect(&mut self,early: Option<&[u8]>) -> bool {
        let mut rtn:usize;
        let mut early_went=false;
        if self.t.still_good() { // have a good ticket? Try it.
            rtn=self.tls_resume(early);
            if rtn==TLS_EARLY_DATA_ACCEPTED { 
                early_went=true;
            }
        } else {
            logger::logger(IO_PROTOCOL,"Resumption Ticket not found or invalid\n",0,None);
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
        return true;   // exiting with live session, ready to receive fresh ticket
    }

// send a message post-handshake
    pub fn send(&mut self,mess: &[u8]) {
        logger::logger(IO_APPLICATION,"Sending Application Message \n\n",-1,Some(mess));
        self.send_message(APPLICATION,TLS1_2,mess,None);       
    }
// Process Server records received post-handshake
// Should be mostly application data, but..
// could be more handshake data disguised as application data
// For example could include a ticket. Also receiving key K_recv might be updated.

    pub fn recv(&mut self,mess: &mut [u8], mslen: &mut usize) -> isize {
        let mut fin=false;
        let mut kind:isize=0;
        loop {
            logger::logger(IO_PROTOCOL,"Waiting for Server input \n",0,None);
            let mut ptr=0;
            self.iolen=0;
            kind=self.get_record();  // get first fragment to determine type
            if kind<0 {
                return kind;   // its an error
            }
            if kind==TIMED_OUT as isize {
                logger::logger(IO_PROTOCOL,"TIME_OUT\n",0,None);
                return kind;
            }
            if kind==HSHAKE as isize {
                loop {
                    let mut r=self.parse_int_pull(1,&mut ptr); let nb=r.val; if r.err!=0 {return r.err;}
                    r=self.parse_int_pull(3,&mut ptr); let len=r.val; if r.err!=0 {return r.err;}   // message length
                    match nb as u8 {
                        TICKET => {
                            let start=ptr;
                            r=self.parse_pull(len,&mut ptr);
                            let ticket=&self.io[start..start+len];
                            let rtn=self.t.create(ticket::millis(),ticket);
                            if rtn==BAD_TICKET {
                                self.t.valid=false;
                                logger::logger(IO_PROTOCOL,"Got a bad ticket ",0,None);
                            } else {
                                self.t.cipher_suite=self.cipher_suite;
                                self.t.favourite_group=self.favourite_group;
                                self.t.valid=true;
                                logger::logger(IO_PROTOCOL,"Got a ticket with lifetime (minutes)= ",(self.t.lifetime/60) as isize,None);
                            }
                            if ptr==self.iolen {
                                fin=true;
                            }
                            if !fin {continue;}
                        }
                        KEY_UPDATE => {
                            if len!=1 {
                                logger::logger(IO_PROTOCOL,"Something wrong\n",0,None);
                                return BAD_RECORD;
                            } 
                            let htype=sal::hash_type(self.cipher_suite);
                            let hlen=sal::hash_len(htype);
                            r=self.parse_int_pull(1,&mut ptr); let kur=r.val; if r.err!=0 {return r.err;}
                            if kur==0 {
                                self.k_recv.update(&mut self.sts[0..hlen]);
                                logger::logger(IO_PROTOCOL,"KEYS UPDATED\n",0,None);
                            }
                            if kur==1 {
                                self.k_recv.update(&mut self.sts[0..hlen]);
                                logger::logger(IO_PROTOCOL,"Key update notified - client should do the same (?) \n",0,None);
                                logger::logger(IO_PROTOCOL,"KEYS UPDATED\n",0,None);
                            }
                            if ptr==self.iolen {
                                fin=true;
                            }
                            if !fin {continue;}
                        }
                        _ => {
                            logger::logger(IO_PROTOCOL,"Unsupported Handshake message type ",nb as isize,None);
                            fin=true;
                        }
                    }
                    if r.err!=0 {return r.err;}
                    if fin {break;}
                }
            }
            if kind==APPLICATION as isize{ // exit only after we receive some application data
                for i in 0..40 {
                    mess[i]=self.io[i];
                }
                *mslen=40;
                break;
            }
            if kind==ALERT as isize {
                logger::logger(IO_PROTOCOL,"*** Alert received - ",0,None);
                logger::log_alert(self.io[1] as usize);
                return kind;
            }
        }
        if self.t.valid {
            self.recover_psk();
            self.t.origin=FULL_HANDSHAKE;
        } else {
            logger::logger(IO_PROTOCOL,"No ticket provided \n",0,None);
        }
        return kind; 
    }
}
