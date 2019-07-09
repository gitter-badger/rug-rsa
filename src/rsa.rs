extern crate rug;
extern crate rand;
extern crate rayon;

use rug::rand::RandState;
use rug::{Assign, Integer};
use rug::integer::Order;
use rand::prelude::*;
use rayon::prelude::*;

#[derive(Debug)]
pub enum RsaError {
    InitError,
    PrimesInvalid,
}

#[derive(Debug)]
pub struct PublicKey {
    n: Integer,
    e: Integer,
}

#[derive(Debug)]
pub struct PrivateKey {
    n: Integer,
    e: Integer,
    d: Integer,
}

pub struct KeyPair {
    private: PrivateKey,
    public: PublicKey
}

fn generate_a_big_number(bit_length: u32) -> Integer {
    let mut rand = RandState::new();
    let mut i = Integer::from(Integer::random_bits(0, &mut rand));
    let random_vector = (1..bit_length/8)
        .into_par_iter()
        .map(|_| {
            rand::thread_rng().gen::<u8>()
        })
        .collect::<Vec<u8>>();

    i.assign_digits(&random_vector, Order::Msf);
    i 
}

fn generate_p_and_q(key_length: u32, p: &mut Integer, q: &mut Integer) -> Result<(), RsaError> {
        // generate a prime number with length inferior to target key length
        p.assign( generate_a_big_number(3*(key_length/4)));
        p.next_prime_mut();
        

        q.assign( generate_a_big_number(3*(key_length/4)));
        q.next_prime_mut();

        let n = p.clone() * q.clone();
        if n.significant_bits() <= key_length {
            Err(RsaError::PrimesInvalid)
        } else {
            Ok(())
        }

}

impl PublicKey {
    pub fn new(p: Integer, q: Integer, e: Integer) -> Result<Self, RsaError> {
        let n = p * q;
        let public_key = PublicKey{n, e};
        // check if key is valid

        Ok(public_key)
    }

    pub fn n(&self) -> &Integer {
        &self.n
    }

    pub fn e(&self) -> &Integer {
        &self.e
    }

    pub fn encrypt(&self, m: &Integer) -> Result<Integer, RsaError> {
        let c = m.clone().pow_mod(&self.e, &self.n).unwrap();
        Ok(c)
    }
}

impl PrivateKey {
    pub fn new(p: Integer, q: Integer, e: Integer) -> Result<Self, RsaError> {
        let n = q.clone() * p.clone();
        let lambda_n: Integer = p - 1;
        let lambda_n = lambda_n.lcm(&(q-1));
        let d = e.clone().invert(&lambda_n).unwrap();
        let private_key = PrivateKey{n, e, d};
        Ok(private_key)
    }

    pub fn d(&self) -> &Integer {
        &self.d
    }

    pub fn decrypt(&self, c: &Integer) -> Result<Integer, RsaError> {
        let m = c.clone().pow_mod(&self.d, &self.n).unwrap();
        Ok(m)
    }
}

impl KeyPair {

    pub fn gen(key_length: u32, e: Option<u32>) -> Result<Self, RsaError> {
        let e = match e {
            Some(e) => Integer::from(e),
            None => Integer::from(65537),
        };
        let mut p = Integer::new();
        let mut q = Integer::new();
        while generate_p_and_q(key_length, &mut p, &mut q).is_err() {}

        KeyPair::from_primes(p, q, e)
    }

    pub fn from_primes(p: Integer, q: Integer, e: Integer) -> Result<Self, RsaError> {
        let private = PrivateKey::new(p.clone(), q.clone(), e.clone())?;
        let public = PublicKey::new(p, q, e)?;
        let keypair = KeyPair{private, public};
        Ok(keypair)
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private
    }
}

