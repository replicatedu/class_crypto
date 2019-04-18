use std::fmt;

use term_painter::Color::*;
use term_painter::ToStyle;

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::{NONCEBYTES, PUBLICKEYBYTES}; //,SECRETKEYBYTES};

#[macro_use]
extern crate serde_derive;
extern crate toml;

pub mod serialization;
use serialization::{Class, Instructors, Participant, Students, Message};

//convert variable PublicKey u8 array reference into a constant sized array
pub fn pk_convert(pk: &[u8]) -> [u8; PUBLICKEYBYTES] {
    let mut array = [0u8; PUBLICKEYBYTES];
    for (&x, p) in pk.iter().zip(array.iter_mut()) {
        *p = x;
    }
    array
}

//convert variable Nonce u8 array reference into a constant sized array
pub fn nonce_convert(pk: &[u8]) -> [u8; NONCEBYTES] {
    let mut array = [0u8; NONCEBYTES];
    for (&x, p) in pk.iter().zip(array.iter_mut()) {
        *p = x;
    }
    array
}

pub fn convert_student_to_serializable(student: &ClassCrypto) -> Students {
    let student = Students {
        id: student.id.to_string(),
        pk: student.return_pk(),
    };
    student
}

pub fn student_to_str(obj: Students)-> String{
    toml::to_string(&obj).unwrap()
}

pub fn convert_instructor_to_serializable(instructor: &ClassCrypto) -> Instructors {
    let instructor = Instructors {
        id: instructor.id.to_string(),
        pk: instructor.return_pk(),
    };
    instructor
}

pub fn instructor_to_str(obj: Instructors)-> String{
    toml::to_string(&obj).unwrap()
}

pub fn convert_me_to_serializable(me: &ClassCrypto) -> Participant {
    let me = Participant {
        id: me.id.to_string(),
        pk: me.return_pk(),
        sk: me.return_sk(),
        instructor: me.instructor,
    };
    me
}

pub fn participant_to_str(obj: Participant)-> String{
    toml::to_string(&obj).unwrap()
}

//holds data for instructor and students
pub struct ClassCrypto {
    id: String,
    sk: box_::SecretKey,
    pk: box_::PublicKey,
    instructor: bool,
}

impl ClassCrypto {
    //constructs a new entity used for encrpytion
    pub fn new(student_id: &str, instructor: bool) -> ClassCrypto {
        let (pk, sk) = box_::gen_keypair();
        let cc = ClassCrypto {
            id: String::from(student_id),
            sk,
            pk,
            instructor,
        };
        cc
    }
    //constructs a ClassCrypto instance from a string
    pub fn new_from_sk(
        student_id: &str,
        sk_in: String,
        instructor: bool,
    ) -> Result<ClassCrypto, &'static str> {
        let sk_decoded = hex::decode(sk_in).expect("hex decoding failed");
        let sk = box_::SecretKey::from_slice(&sk_decoded).expect("secret key invalid");

        let pk = sk.public_key();
        let cc = ClassCrypto {
            id: String::from(student_id),
            sk,
            pk,
            instructor,
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

    pub fn encrypt(&self, plaintext: Vec<u8>, recipient_pk_str: String) -> String {
        let recipient_pk = box_::PublicKey(pk_convert(&hex::decode(recipient_pk_str).expect("encryption failed")));

        let nonce = box_::gen_nonce();

        let ciphertext = box_::seal(&plaintext, &nonce, &recipient_pk, &self.sk);

        let mut enc_nonce = hex::encode(nonce);
        let enc_ciphertext = hex::encode(&ciphertext);

        //prepends nones onto string to send as the message
        enc_nonce.push_str(&enc_ciphertext);
        enc_nonce
    }

    pub fn encrypt_to_toml(&self, plaintext: Vec<u8>, recipient_pk_str: String) -> String {
        let msg = self.encrypt(plaintext,recipient_pk_str);
        let id = &self.id;
        let pk = self.return_pk();
        let emsg = Message{
            id: id.to_string(),
            pk: pk,
            msg: msg
        };
        toml::to_string(&emsg).expect("toml encoding failed")
    }

    pub fn decrypt(&self, ciphertext: &str, sender_pk_str: String) -> Result<Vec<u8>, ()> {
        let sender_pk_hex = match hex::decode(&sender_pk_str) {
            Err(_) => return Err(()),
            Ok(f) => f,
        };

        let sender_pk = box_::PublicKey(pk_convert(&sender_pk_hex));

        let decoded_ciphertext = hex::decode(ciphertext).expect("hex decoding failed");

        //seperate the nonce and the ciphertext
        let nonce = &decoded_ciphertext[0..NONCEBYTES];
        let ciphertext = &decoded_ciphertext[NONCEBYTES..];

        let plaintext = match box_::open(
            &ciphertext,
            &Nonce(nonce_convert(nonce)),
            &sender_pk,
            &self.sk,
        ) {
            Err(_) => return Err(()),
            Ok(f) => f,
        };
        Ok(plaintext)
    }

    pub fn decrypt_from_toml(&self,toml_text: &str) -> Result<Vec<u8>, ()>{
        let msg:Message = toml::from_str(&toml_text).expect("toml decoding failed");
        self.decrypt(&msg.msg, msg.pk)
    }
}

impl fmt::Display for ClassCrypto {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write strictly the first element into the supplied output
        // stream: `f`. Returns `fmt::Result` which indicates whether the
        // operation succeeded or failed. Note that `write!` uses syntax which
        // is very similar to `println!`.
        if self.instructor {
            write!(
                f,
                "Instructor ID:\r\n\t{}\r\nPublicKey:\r\n\t{}\r\nPrivateKey:\r\n\t{}",
                self.id,
                Yellow.paint(self.return_pk()),
                Red.paint(self.return_sk())
            )
        } else {
            write!(
                f,
                "Student ID:\r\n\t{}\r\nPublicKey:\r\n\t{}\r\nPrivateKey:\r\n\t{}",
                self.id,
                Yellow.paint(self.return_pk()),
                Red.paint(self.return_sk())
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand;
    use sodiumoxide::crypto::box_;
    use std::str;
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
        let _a = ClassCrypto::new("alex", true);
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
        //println!("{}",a);
        //println!("{}",m);
        let msg = "i hate girls lacrosse";

        let cipher = a.encrypt(msg.as_bytes().to_vec(), m.return_pk());
        let recv = m.decrypt(&cipher, a.return_pk()).unwrap();
        dbg!(str::from_utf8(&recv).unwrap());
        assert!(msg == str::from_utf8(&recv).unwrap());
    }
    #[test]
    fn test_encrypt_message_to_self() {
        //test to see if same key pair can be regenerated from ascii hex
        let a = ClassCrypto::new("alex", true);
        let m = ClassCrypto::new_from_sk("megan", a.return_sk(), false).unwrap();
        //println!("{}",a);
        //println!("{}",m);
        let msg = "i hate girls lacrosse";

        let cipher = a.encrypt(msg.as_bytes().to_vec(), m.return_pk());
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
        //println!("{}",a);
        //println!("{}",m);
        let msg = "i hate girls lacrosse";

        let cipher = a.encrypt(msg.as_bytes().to_vec(), m.return_pk());
        let _recv = match h.decrypt(&cipher, a.return_pk()) {
            Err(_e) => assert!(true),
            Ok(_f) => assert!(false, "this should have failed"),
        };
    }
    #[test]
    fn test_encrypt_decrypt_binary() {
        //test to see if same key pair can be regenerated from ascii hex
        let a = ClassCrypto::new("alex", true);
        let m = ClassCrypto::new_from_sk("megan", a.return_sk(), false).unwrap();
        //println!("{}",a);
        //println!("{}",m);
        let random_bytes: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();

        let cipher = a.encrypt(random_bytes.to_vec(), m.return_pk());
        let recv = m.decrypt(&cipher, a.return_pk()).unwrap();

        assert!(random_bytes == recv);
    }
    #[test]
    fn serialize_me() {
        //test to see if me can be regenerated from ascii hex
        let a = ClassCrypto::new("alex", true);
        let me = convert_me_to_serializable(&a);
        let toml = toml::to_string(&me).unwrap();
        dbg!(toml);
    }
    #[test]
    fn serialize_instructor() {
        //test to see instructor can be serialized
        let a = ClassCrypto::new("alex", true);
        let me = convert_instructor_to_serializable(&a);
        let toml = toml::to_string(&me).unwrap();
        dbg!(toml);
    }
    #[test]
    fn serialize_student() {
        //test to see student can be serialized
        let a = ClassCrypto::new("alex", true);
        let me = convert_student_to_serializable(&a);
        let toml = toml::to_string(&me).unwrap();
        dbg!(toml);
    }
    #[test]
    fn encrypt_toml() {
        //test to see student can be serialized
        let a = ClassCrypto::new("alex", true);
        let m = ClassCrypto::new("megan", false);
        //println!("{}",a);
        //println!("{}",m);
        let msg = "i hate girls lacrosse";

        let cipher_toml = a.encrypt_to_toml(msg.as_bytes().to_vec(), m.return_pk());
        let uncipher_toml = m.decrypt_from_toml(&cipher_toml);
        dbg!(cipher_toml);
        dbg!(str::from_utf8(&uncipher_toml.unwrap()).unwrap());
    }
}
