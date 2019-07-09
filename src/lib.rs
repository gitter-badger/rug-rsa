extern crate rug;
pub mod rsa;


#[cfg(test)]
mod tests {
    use super::*;
    use rug::Integer;

    #[test]
    fn create_rsa_object() {
        let p = Integer::from(61);
        let q = Integer::from(53);
        let e = Integer::from(17);
        let n = Integer::from(3233);

        let key = rsa::PublicKey::new(p, q, e.clone()).unwrap();
        
        assert_eq!(&n, key.n());
        assert_eq!(&e, key.e());
    }

    #[test]
    fn create_private_key() {
        let p = Integer::from(61);
        let q = Integer::from(53);
        let e = Integer::from(17);
        let d = Integer::from(413);
        let keypair = rsa::KeyPair::from_primes(p, q, e).unwrap();

        assert_eq!(&d, keypair.private_key().d());
    }

    #[test]
    fn test_generate_a_keypair() {
        let m = Integer::from(65);
        let keypair = rsa::KeyPair::gen(4096, None).unwrap();

        let ciphertext = keypair.public_key().encrypt(&m).unwrap();
        let plaintext = keypair.private_key().decrypt(&ciphertext).unwrap();

        assert_eq!(65, plaintext);
    }

    #[test]
    fn encrypt_message_with_several_numbers() {
        let p = Integer::from(61);
        let q = Integer::from(53);
        let e = Integer::from(17);
        let m = Integer::from(65);
        let c = Integer::from(2790);
        let keypair = rsa::KeyPair::from_primes(p, q, e).unwrap();
        let ciphertext = keypair.public_key().encrypt(&m).unwrap();

        assert_eq!(c, ciphertext);
    }

    #[test]
    fn decrypt_message_with_small_numbers() {
        let p = Integer::from(61);
        let q = Integer::from(53);
        let e = Integer::from(17);
        let m = Integer::from(65);
        let c = Integer::from(2790);
        let keypair = rsa::KeyPair::from_primes(p, q, e).unwrap();
        let plaintext = keypair.private_key().decrypt(&c).unwrap();

        assert_eq!(m, plaintext);
    }
}
