// Process resumption tickets
//

use std::time::{SystemTime, UNIX_EPOCH};
use crate::config::*;
use crate::sal;

pub fn millis() -> usize {
    return SystemTime::now().duration_since(UNIX_EPOCH).expect("").as_millis() as usize;    
}

pub struct TICKET {
    timestamp:u32,
    cipher_suite:u16,
    group:u16,
    psklen:u8,
    psk: [u8;MAX_HASH],
    idlen: u16,
    identity: [u8;MAX_X509_FIELD],

    ticket_lifetime:u32,
    ticket_age_add:u32,
    nnlen: usize
    nonce: [u8;MAX_KEY],
    tklen: usize,
    tick: [u8;MAX_TICKET_SIZE],
    max_early_data: u32,
} 

impl TICKET {
    pub fn new(suite: u16,kex: u16,id: &[u8],rms: &[u8]) -> TICKET {
        let mut this = TICKET {
            timestamp: millis() as u32,
            cipher_suite: suite,
            group: kex,
            psklen: 0,
            psk: [0;MAX_HASH],
            idlen: 0,
            identity: [0;MAX_X509_FIELD],

            ticket_lifetime:TICKET_LIFETIME,
            ticket_age_add: sal::random_word(),
            nnlen: 32,
            nonce: [0;MAX_KEY],
            eslen: 0,
            encrypted_state: [0;MAX_TICKET_SIZE],
            max_early_data: MAX_EARLY_DATA
        }
        this.idlen=id.len();
        for i in 0..this.idlen {
            identity[i]=id[i];
        }
        for i in 0..this.nnlen {
            this.nonce[i]=sal::random_byte();
        }
        let rs="resumption";
        let htype=sal::hash_type(suite);
        let hlen=sal::hash_len(htype);
        keys::hkdf_expand_label(htype,&mut this.psk[0..hlen],&rms[0..hlen],rs.as_bytes(),Some(&this.nonce[0..this.nnlen]));
        this.psklen=hlen;

        let mut ptr=0;
        ptr=utils::append_byte(&this.tick,ptr,TICKET,1);
        ptr=utils::append_int(&this.tick,ptr,len,3);
        ptr=utils::append_int(&this.tick,

        return this;
    }
}

pub fn send_ticket(&self,tick: &mut [u8]) {
    let mut ptr=0;
    let ticket_age_add = sal::random_word();
    let mut nonce:[u8;12]=[0;12];
    for i in 0..12 {
        nonce[i]=sal::random_byte();
    }
    let mut tag:[u8;16]=[0;16];
    let mut psk:[u8;MAX_HASH]=[0;MAX_HASH];
    let rs="resumption";
    let htype=sal::hash_type(self.cipher_suite);
    let hlen=sal::hash_len(htype);
    keys::hkdf_expand_label(htype,&mut psk[0..hlen],&self.rms[0..hlen],rs.as_bytes(),Some(&nonce));
        this.psklen=hlen;

    let mut state:[u8;MAX_TICKET_SIZE]=[0;MAX_TICKET_SIZE];
    let mut sptr=0;
    sptr=utils::append_int(&mut state,sptr,millis(),4);
    sptr=utils::append_int(&mut state,sptr,self.cipher_suite as usize,2);
    sptr=utils::append_int(&mut state,sptr,self.group as usize,2);
    sptr=utils::append_byte(&mut state,sptr,hlen as usize,1);
    sptr=utils::append_bytes(&mut state,sptr,&mut psk[0..hlen]);
    sptr=utils::append_bytes(&mut state,self.cidlen as usize,2);
    sptr=utils::append_bytes&mut state,&self.clientid[0..self.cidlen]);

    let context=keys::CRYPTO::new();
    context.special_init(&nonce);
    sal::aead_encrypt(&context,&nonce,&mut state[0..sptr],&mut tag);


    let len= sptr+49;
    ptr=utils::append_byte(tick,ptr,TICKET,1);  // message type
    ptr=utils::append_int(tick,ptr,len,3);      // message length
    ptr=utils::append_int(tick,ptr,TICKET_LIFETIME,4);
    ptr=utils::append_int(tick,ptr,ticket_age_add,4);
    ptr=utils::append_byte(tick,ptr,12,1);
    ptr=utils::append_bytes(tick,ptr,&nonce[0..12]);
    ptr=utils::append_int(tick,ptr,sptr+16,2);
    ptr=utils::append_bytes(tick,ptr,&state[0..sptr]);
    ptr=utils::append_bytes(tick,ptr,&tag);
 
    ptr=utils::append_int(tick,ptr,8,2);
    ptr=utils::append_int(tick,ptr,EARLY_DATA as usize,2);
    ptr=utils::append_int(tick,ptr,4,2);
    ptr=utils::append_int(tick,ptr,MAX_EARLY_DATA,4);

}

// recover Pre-Shared-Key from Resumption Master Secret
fn recover_psk(&mut self,t: &mut TICKET) { 
    let rs="resumption";
    let htype=sal::hash_type(self.cipher_suite);
    let hlen=sal::hash_len(htype);
    keys::hkdf_expand_label(htype,&mut t.psk[0..hlen],&self.rms[0..hlen],rs.as_bytes(),Some(&t.nonce[0..t.nnlen]));
    self.t.psklen=hlen;
}

pub fn create_ticket_message(&mut self,tickdata: &mut [u8]) -> usize {
// first grab the state
    let mut s=STATE::new(self.cipher_suite,self.group);
    s.idlen=self.cidlen;
    for i in 0..s.idlen {
        s.identity=self.clientid[i]
    }
    recover_psk(

}

