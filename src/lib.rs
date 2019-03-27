use std::fmt;

use term_painter::Color::*;
use term_painter::ToStyle;

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::NONCEBYTES;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce;

//TODO find the constant linked to 32
pub fn pk_convert(pk: &[u8]) -> [u8; 32] {
    let mut array = [0u8; 32];
    for (&x, p) in pk.iter().zip(array.iter_mut()) {
        *p = x;
    }
    array
}

pub fn nonce_convert(pk: &[u8]) -> [u8; NONCEBYTES] {
    let mut array = [0u8; NONCEBYTES];
    for (&x, p) in pk.iter().zip(array.iter_mut()) {
        *p = x;
    }
    array
}

//holds data for instructor and students
pub struct ClassCrypto {
	id: String,
    sk: box_::SecretKey,
	pk: box_::PublicKey,
    instructor: bool
}

impl ClassCrypto {
    //constructs a new entity used for encrpytion
    pub fn new(student_id: &str, instructor: bool) -> ClassCrypto {
        let (pk, sk) = box_::gen_keypair(); 
		let cc = ClassCrypto {
            id: String::from(student_id),
            sk,
			pk,
            instructor
        };
        cc
    }
    //constructs a ClassCrypto instance from a string
    pub fn new_from_sk(student_id: &str, sk_in: String,instructor: bool) -> Result<ClassCrypto, &'static str> {
        let sk_decoded = hex::decode(sk_in).unwrap();
        let sk = box_::SecretKey::from_slice(&sk_decoded).unwrap();

        let pk = sk.public_key(); 
        let cc = ClassCrypto {
            id: String::from(student_id),
            sk,
			pk,
            instructor
        };
        Ok(cc)
    }

    //returns secret key in a hex dump
    pub fn return_sk(&self) -> String {
        let sk = &self.sk[..];
        return hex::encode(sk);
    }

    //returns public key in a hex dump
    pub fn return_pk(&self) -> String {
        return hex::encode(self.pk);
    }



    pub fn encrypt(&self, plaintext: &str, recipient_pk_str: String) -> String{

        let recipient_pk = box_::PublicKey(pk_convert(&hex::decode(recipient_pk_str).unwrap()));

        let nonce = box_::gen_nonce();
        
        let ciphertext = box_::seal(plaintext.as_bytes(), &nonce, &recipient_pk, &self.sk);
        
        let mut enc_nonce = hex::encode(nonce);
        let enc_ciphertext = hex::encode(&ciphertext);
        //dbg!(enc_nonce.len());
        //dbg!(&enc_ciphertext);

        //prepends nones onto string to send as the message
        enc_nonce.push_str(&enc_ciphertext);
        enc_nonce
    }

	pub fn decrypt(&self, ciphertext: &str, sender_pk_str: String) -> Result<Vec<u8>,()> {
        let sender_pk_hex = match hex::decode(&sender_pk_str){
            Err(e) => return Err(()),
            Ok(f) => f
        }; 
        
        let sender_pk = box_::PublicKey(pk_convert(&sender_pk_hex));
        
        let decoded_ciphertext = hex::decode(ciphertext).unwrap();
        let nonce = &decoded_ciphertext[0..NONCEBYTES];
        let ciphertext = &decoded_ciphertext[NONCEBYTES..];

        let plaintext = match box_::open(&ciphertext, &Nonce(nonce_convert(nonce)), &sender_pk, &self.sk){
            Err(e) => return Err(()),
            Ok(f) => f
        }; 
        Ok(plaintext)
    }

}

impl fmt::Display for ClassCrypto {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write strictly the first element into the supplied output
        // stream: `f`. Returns `fmt::Result` which indicates whether the
        // operation succeeded or failed. Note that `write!` uses syntax which
        // is very similar to `println!`.
        if self.instructor{
            write!(
                f,
                "Instructor ID:\r\n\t{}\r\nPublicKey:\r\n\t{}\r\nPrivateKey:\r\n\t{}",
                self.id, Yellow.paint(self.return_pk()), Red.paint(self.return_sk())
            )
        } else {

            write!(
                f,
                "Student ID:\r\n\t{}\r\nPublicKey:\r\n\t{}\r\nPrivateKey:\r\n\t{}",
                self.id, Yellow.paint(self.return_pk()), Red.paint(self.return_sk())
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str;
	use sodiumoxide::crypto::box_;

    #[test]
    fn encrypt_decrypt() {
        let (ourpk, oursk) = box_::gen_keypair();
		
        // normally theirpk is sent by the other party
		let (theirpk, theirsk) = box_::gen_keypair();
		let nonce = box_::gen_nonce();
		let plaintext = b"some data";
		let ciphertext = box_::seal(plaintext, &nonce, &theirpk, &oursk);
		let their_plaintext = box_::open(&ciphertext, &nonce, &ourpk, &theirsk).unwrap();
		assert!(plaintext == &their_plaintext[..]);

    }
    #[test]
    fn gen_keys() {
        //simple test to ensure keys are generated properly
        let a = ClassCrypto::new("alex", true);
    }
    #[test]
    fn test_gen_from_hex_keys() {
        //test to see if same key pair can be regenerated from ascii hex
        let a = ClassCrypto::new("alex", true);
    	let a2 = ClassCrypto::new_from_sk("alex2", a.return_sk(), false).unwrap();
        assert!(a.return_pk() == a2.return_pk());
        
    }
   #[test]
    fn test_encrypt_message() {
        //test to see if same key pair can be regenerated from ascii hex
        let a = ClassCrypto::new("alex", true);
    	let m = ClassCrypto::new("megan", false);
        println!("{}",a);
        println!("{}",m);
        let msg = "i hate girls lacrosse";

        let cipher = a.encrypt(msg, m.return_pk());
        let recv = m.decrypt(&cipher, a.return_pk()).unwrap();
        dbg!(str::from_utf8(&recv).unwrap());
        //assert!(msg == recv);
    }
    #[test]
    fn test_encrypt_message_to_self() {
        //test to see if same key pair can be regenerated from ascii hex
        let a = ClassCrypto::new("alex", true);
    	let m = ClassCrypto::new_from_sk("megan", a.return_sk(), false).unwrap();
        println!("{}",a);
        println!("{}",m);
        let msg = "i hate girls lacrosse";

        let cipher = a.encrypt(msg, m.return_pk());
        let recv = m.decrypt(&cipher, a.return_pk()).unwrap();
        dbg!(str::from_utf8(&recv).unwrap());
        //assert!(msg == recv);
    }
    #[test]
    fn test_fail_decrypt() {
        //test to see if same key pair can be regenerated from ascii hex
        let a = ClassCrypto::new("alex", true);
    	let m = ClassCrypto::new_from_sk("megan", a.return_sk(), false).unwrap();
        let h = ClassCrypto::new("hallie", true);
        println!("{}",a);
        println!("{}",m);
        let msg = "i hate girls lacrosse";

        let cipher = a.encrypt(msg, m.return_pk());
        let recv = match h.decrypt(&cipher, a.return_pk()){
            Err(e) => assert!(true),
            Ok(f) => assert!(false, "this should have failed")
        };
    }

}
