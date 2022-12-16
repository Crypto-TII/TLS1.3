#![allow(non_snake_case)]
extern crate mcore;

use mcore::sha3;
use mcore::sha3::SHA3;
use mcore::rand::RAND;
use mcore::hmac;

use mcore::bls12381::big;
use mcore::bls12381::big::BIG;
use mcore::bls12381::dbig::DBIG;
use mcore::bls12381::ecp;
use mcore::bls12381::ecp::ECP;
use mcore::bls12381::ecp2::ECP2;
use mcore::bls12381::fp::FP;
use mcore::bls12381::fp2::FP2;
//use mcore::bls12381::fp12::FP12;
use mcore::bls12381::pair;
use mcore::bls12381::rom;

pub const FS: usize = big::MODBYTES as usize;

const TAPK: &str = "0402d506a111d406dd0ad9d64b6515c4e15fd28ab45595b89817871d9220f0242c7b7ef1800ad8e6a8f047100088702ac8042add1af478ae20672c6670959ae36f19dcdee948f6b40a3498af69d708fbf15e81b536dacac484a697a59f3742063b";

fn roundup(a:usize,b:usize) -> usize {
    return 1+(a-1)/b;
}

fn char2int(inp: u8) -> u8 {
    if inp>='0' as u8 && inp <='9' as u8 {
        return inp-'0' as u8;
    }
    if inp>='A' as u8 && inp <='F' as u8 {
        return inp-('A' as u8) +10;
    }
    if inp>='a' as u8 && inp <='f' as u8 {
        return inp-('a' as u8) +10;
    }
    return 0;
}

// s better have even number of characters!
fn decode_hex(x: &mut[u8],s: &str) -> usize {
    let c=s.as_bytes();
    let mut i=0;
    let mut j=0;

    while j<c.len() {
        x[i]=char2int(c[j])*16+char2int(c[j+1]);
        i+=1;
        j+=2;
    }
    return i;
}

/* Encode octet to curve point on G2 */
fn h1(identity:&str) -> ECP2 {
    let mut okm:[u8;128]=[0;128];
    let id=identity.as_bytes();
    let dst="BLS12381G1_XMD:SHA-256_SVDW_NU_BFIBE".as_bytes();
    let q = BIG::new_ints(&rom::MODULUS);
    let k=q.nbits();
    let r = BIG::new_ints(&rom::CURVE_ORDER);
    let m=r.nbits();
    let el=roundup(k+roundup(m,2),8);
    hmac::xof_expand(sha3::SHAKE128,&mut okm,2*el,&dst,&id);
	let mut dx=DBIG::frombytes(&okm[0..el]);
    let u1=FP::new_big(&dx.dmod(&q));
    dx=DBIG::frombytes(&okm[el..2*el]);
    let u2=FP::new_big(&dx.dmod(&q));
    let u=FP2::new_fps(&u1,&u2);
    let mut P=ECP2::map2point(&u);
    P.cfp();
    P.affine();
    return P;
}

/* create random r in Zq from U and V, and rP */
fn h3(u: &[u8],v: &[u8],r: &mut BIG) -> ECP {
    let q = BIG::new_ints(&rom::CURVE_ORDER);
    let mut raw:[u8;128]=[0;128];
	let mut sh = SHA3::new(sha3::SHAKE256);
	for i in 0..u.len() {
        sh.process(u[i]);
    }
	for i in 0..v.len() {
        sh.process(v[i]);
    }
    sh.shake(&mut raw,128);

    let mut rng = RAND::new();
    rng.seed(128, &raw);
    *r = BIG::randtrunc(&q, 16 * ecp::AESKEY, &mut rng);
    let G = ECP::generator();
    return pair::g1mul(&G, r);
}

// hash input octet to 32 bytes
fn h4(i: &[u8],o: &mut [u8]) {
	let mut sh = SHA3::new(sha3::HASH256); 
    for j in 0..i.len() {
        sh.process(i[j]);
    }
    sh.hash(o);
}

// encapsulate 32-byte key inside ciphertext ct
pub fn bfibe_cca_encrypt(identity: &str,r32: &[u8],key: &mut[u8],ct: &mut[u8]) -> bool {
	let mut sigma: [u8;32]=[0;32];
    let mut u: [u8;2*FS+1]=[0;2*FS+1];
	let mut v: [u8;32]=[0;32];
	let mut w: [u8;32]=[0;32];
	let mut mask: [u8;32]=[0;32];
	let mut z: [u8;12*FS]=[0;12*FS];
    let mut sh = SHA3::new(sha3::SHAKE256);
    let mut r=BIG::new();

	for i in 0..r32.len() {
		sh.process(r32[i]);
    }
	sh.shake(&mut sigma,32);
    sh.shake(key,32);

    let Qid=h1(identity);
    let rP=h3(&sigma,key,&mut r);
    h4(&sigma,&mut mask);

    for i in 0..32 {
        w[i]=key[i]^mask[i];
    }

    let mut tapk: [u8; TAPK.len()/2]=[0;TAPK.len()/2];
    decode_hex(&mut tapk,&TAPK);
    let Ppub=ECP::frombytes(&tapk);
    if Ppub.is_infinity() {
        return false;
    }

    let P=pair::g1mul(&Ppub, &r);
    rP.tobytes(&mut u,false);
    let mut g=pair::ate(&Qid,&P);
    g = pair::fexp(&g);
    g.tobytes(&mut z);
    h4(&z,&mut mask);

    for i in 0..32 {
        v[i]=sigma[i]^mask[i];
    }

    let ul=u.len();
    for i in 0..ul {
        ct[i]=u[i];
    }
    for i in 0..32 {
        ct[i+ul]=v[i];
    }
    for i in 0..32 {
        ct[i+ul+32]=w[i];
    }
    return true;
}

// decapsulate 32-byte key inside ciphertext ct
pub fn bfibe_cca_decrypt(csk: &[u8],ct: &[u8],key: &mut[u8]) -> bool {
	let mut sigma: [u8;32]=[0;32];
	let u=&ct[0..2*FS+1];
    let v=&ct[2*FS+1..2*FS+33];
    let w=&ct[2*FS+33..2*FS+65];
	let mut z: [u8;12*FS]=[0;12*FS];
    let mut r=BIG::new();
    let rP=ECP::frombytes(&u);
    let SK=ECP2::frombytes(csk);

    if SK.is_infinity() || rP.is_infinity() {
        return false;
    } 

    let mut g=pair::ate(&SK,&rP);
    g = pair::fexp(&g);
    g.tobytes(&mut z);
    h4(&z,&mut sigma);

    for i in 0..32 {
        sigma[i]^=v[i];
    }
    h4(&sigma,key);
    for i in 0..32 {
        key[i]^=w[i];
    }
    let rPc=h3(&sigma,key,&mut r);
    if !rP.equals(&rPc) {
        return false;
    }
    return true;
}

pub const KYLEN:usize = 32;
pub const CTLEN:usize = 161;

/*
const ID: &str = "localhost";
const IDSK: &str = "040ec014966d3442e85ed19b46044d9655d8ed91ef05e6678e57a51cfd9202c8dad2c854850b09fc919b6cb000a2f5b05801b767a87194d62d45cb1b1a9cd15b63ea733770361de22f64946631c2c21826d8abf884e4d07159d54c91b79662e2e4050ae782a9fb9394853669540b4cb1f46098ca690bd572b9c47587ca12a2f2c268e1a22ebc0d752f95bcf926a8b6e2cb1452dc7bf03eab18c5b68822b0da20279d1e8997a759637abdffec93f4c985f9256deed1cca5c50e2c37ae6c10c67c13";
const LOOPS: usize = 100;

fn main() {
    println!("Testing IBE KEM");
    let mut ct:[u8;161]=[0;161];
    let mut key:[u8;32]=[0;32];
    let mut key2:[u8;32]=[0;32];
    let mut r32:[u8;32]=[0;32];

    let mut csk: [u8; IDSK.len()/2]=[0;IDSK.len()/2];
    decode_hex(&mut csk,&IDSK);

    for i in 0..LOOPS {
        for j in 0..32 {
            r32[j]=((i+j)%256) as u8;
        }
        bfibe_cca_encrypt(ID,&r32,&mut key,&mut ct);
        print!("EK= ");
        for i in 0..32 {
            print!("{:02x}",key[i]);
        }
        println!("");

        bfibe_cca_decrypt(&csk,&ct,&mut key2);
        print!("DK= ");
        for i in 0..32 {
            print!("{:02x}",key2[i]);
        }
        println!("");
        for i in 0..32 {
            if key[i]!=key2[i] {
                println!("SCREAM"); break;
            }
        }
    }
}
*/
