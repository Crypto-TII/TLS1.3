// Process resumption tickets
//

use std::time::{SystemTime, UNIX_EPOCH};
use crate::config::*;
use crate::tls13::utils;
use crate::tls13::utils::RET;

pub fn millis() -> usize {
    return SystemTime::now().duration_since(UNIX_EPOCH).expect("").as_millis() as usize;    
}

/**
 * @brief ticket context structure */
pub struct TICKET {
    pub valid: bool,                     // Is ticket valid? 
    pub tick:[u8;MAX_TICKET_SIZE],   // Ticket bytes 
    pub nonce:[u8;MAX_KEY],          // 32-byte nonce 
    pub psk:[u8;MAX_HASH],           // pre-shared key 
    pub tklen: usize,
    pub nnlen: usize,
    pub psklen: usize,
    pub age_obfuscator: usize,           // ticket age obfuscator - 0 for external PSK 
    pub max_early_data: usize,           // Maximum early data allowed for this ticket
    pub birth: usize,                    // Birth time of this ticket  
    pub lifetime: usize,                 // ticket lifetime         
    pub cipher_suite: u16,             // Cipher suite used 
    pub favourite_group: u16,          // the server's favourite group 
    pub origin: usize                    // Origin of initial handshake - Full or PSK? 
} 

// ticket structure
impl TICKET {
    pub fn clear(&mut self) {
        self.valid=false;
        self.tklen=0;
        self.nnlen=0;
        self.psklen=0;
        self.age_obfuscator=0;
        self.max_early_data=0;
        self.birth=0;
        self.lifetime=0;
        self.cipher_suite=0;
        self.favourite_group=0;
        self.origin=0;
        for i in 0..MAX_TICKET_SIZE {
            self.tick[i]=0;
        }
        for i in 0..MAX_KEY {
            self.nonce[i]=0;
        }
        for i in 0..MAX_HASH {
            self.psk[i]=0;
        }
    }

// create ticket structure from byte stream
    pub fn create(&mut self,birth: usize,tickdata: &[u8]) -> isize {
        if tickdata.len() == 0 {
            return BAD_TICKET;
        }
        let mut ptr=0;
        let mut r:RET;
        r=utils::parse_int(tickdata,4,&mut ptr); self.lifetime=r.val; if r.err!=0 {return BAD_TICKET;} 
        r=utils::parse_int(tickdata,4,&mut ptr); self.age_obfuscator=r.val; if r.err!=0 {return BAD_TICKET;} 
        r=utils::parse_int(tickdata,1,&mut ptr); let mut len=r.val; if r.err!=0 {return BAD_TICKET;}

        r=utils::parse_bytes(&mut self.nonce[0..len],tickdata,&mut ptr); if r.err!=0 {return BAD_TICKET;}
        self.nnlen=len;
        r=utils::parse_int(tickdata,2,&mut ptr); len=r.val; if r.err!=0 {return BAD_TICKET;}
        r=utils::parse_bytes(&mut self.tick[0..len],tickdata,&mut ptr); if r.err!=0 {return BAD_TICKET;}
        self.tklen=len;
        r=utils::parse_int(tickdata,2,&mut ptr); len=r.val; if r.err!=0 {return BAD_TICKET;}
        
        self.birth=birth;
        self.max_early_data=0;

        while len>0 {
            r=utils::parse_int(tickdata,2,&mut ptr); let ext=r.val; if r.err!=0 {return BAD_TICKET;}
            len -= 2;
            match ext {
                EARLY_DATA => {
                    r=utils::parse_int(tickdata,2,&mut ptr); let tmplen=r.val; if tmplen!=4 || r.err!=0 {return BAD_TICKET;}
                    len-=2;
                    r=utils::parse_int(tickdata,4,&mut ptr); self.max_early_data=r.val;
                    len-=tmplen;
                }
                _ => {
                    r=utils::parse_int(tickdata,2,&mut ptr); let tmplen=r.val;
                    len-=2;
                    len-=tmplen; ptr+=tmplen;
                }
            }
            if r.err!=0 {return BAD_TICKET;}
        } 
        self.valid=true;
        return 0;
    }

// check if ticket is likely to work
    pub fn still_good(&self) -> bool {
        if self.origin==EXTERNAL_PSK {
            return true;
        }
        if self.lifetime==0 || !self.valid {
            return false;
        }
        let ttr=self.birth;
        let ttu=millis() as usize;
        let age=ttu-ttr;
        if age>1000*self.lifetime {
            return false;
        }
        return true;
    }
}