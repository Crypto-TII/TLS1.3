
//! Client Certificate and private key stored here

use crate::config::*;

// ECC-SS keys 256 bit. Certificate expires May 2023

pub const MYPRIVATE: &str = 
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkYO7LpVcia9BoJSQ\
Ls2rOGluxjkah3LzRChLGt8oyXShRANCAAQpVUJz1HzNuFR9QfLaQz5eO9BMSrHT\
OblikZXqx3xbwQaAZgGJLfYgiPc+cSVBtJeWYUruLdTRnNEWPVULstnI";

pub const CHAINLEN:usize = 1;

pub const MYCERTCHAIN: [&str;CHAINLEN] = [ 
"MIICczCCAhmgAwIBAgIUO4ZDnPLFU4TKBeKzGAQ/8jsumt8wCgYIKoZIzj0EAwIw\
gY4xCzAJBgNVBAYTAklFMREwDwYDVQQIDAhMZWluc3RlcjENMAsGA1UEBwwEVHJp\
bTEPMA0GA1UECgwGU2hhbXVzMREwDwYDVQQLDAhSZXNlYXJjaDETMBEGA1UEAwwK\
TWlrZSBTY290dDEkMCIGCSqGSIb3DQEJARYVbWlrZS5zY290dEBtaXJhY2wuY29t\
MB4XDTIyMDUwMjA4MzgzOFoXDTIzMDUwMjA4MzgzOFowgY4xCzAJBgNVBAYTAklF\
MREwDwYDVQQIDAhMZWluc3RlcjENMAsGA1UEBwwEVHJpbTEPMA0GA1UECgwGU2hh\
bXVzMREwDwYDVQQLDAhSZXNlYXJjaDETMBEGA1UEAwwKTWlrZSBTY290dDEkMCIG\
CSqGSIb3DQEJARYVbWlrZS5zY290dEBtaXJhY2wuY29tMFkwEwYHKoZIzj0CAQYI\
KoZIzj0DAQcDQgAEKVVCc9R8zbhUfUHy2kM+XjvQTEqx0zm5YpGV6sd8W8EGgGYB\
iS32IIj3PnElQbSXlmFK7i3U0ZzRFj1VC7LZyKNTMFEwHQYDVR0OBBYEFLqCgrLR\
ZgirGFexJSa18p7YgpehMB8GA1UdIwQYMBaAFLqCgrLRZgirGFexJSa18p7Ygpeh\
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgI1dd2DBjgRls92H0\
SpxxnguAEeVw/jxqF1xw+xoECV0CIQDmex6iyHQEzDP7cyzKo4WHuEG6UkjlaRUA\
XhcQYkLKHg=="];

// Report signature requirements for our certificate chain
pub fn get_sig_requirements(sig_reqs:&mut [u16]) -> usize {
    sig_reqs[0]=ECDSA_SECP256R1_SHA256;
    return 1;
}
