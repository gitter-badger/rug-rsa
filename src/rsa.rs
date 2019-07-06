extern crate rug;

use rug::Integer;

pub struct PublicKey {
    n: Integer,
    e: Integer,
}

pub struct PrivateKey {
    n: Integer,
    e: Integer,
    d: Integer,
}

pub struct KeyPair {
    private: PrivateKey,
    public: PublicKey
}

pub trait PublicKeyTrait {
    fn n(&self) -> &Integer;
    fn e(&self) -> &Integer;

    fn key_length(&self) -> usize {
        0
    }
}

impl PublicKeyTrait for PublicKey {
    fn n(&self) -> &Integer {
        &self.n
    }

    fn e(&self) -> &Integer {
        &self.n
    }
}
