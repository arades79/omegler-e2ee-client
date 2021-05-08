// trait ExtendedDiffieHelmen
// {
//     type Key: Clone
//     fn generate_signed_pre_keys() -> [Key; 32];
//     fn exchange(id_key: Key, one_time_key: Key, )
// }

use crypto_box::{
    aead::Aead, aead::Error, aead::Nonce, generate_nonce, Box as CryptoBox, PublicKey,
    SecretKey as BoxSecret,
};

pub(crate) struct DisconnectedUser(BoxSecret);

impl DisconnectedUser {
    fn into_connected(self, partner_key: &PublicKey) -> ConnectedUser {
        let chat_crypto_box = CryptoBox::new(partner_key, &self.0);
        ConnectedUser(chat_crypto_box)
    }

    fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }
}

impl Default for DisconnectedUser {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let secret = BoxSecret::generate(&mut rng);
        Self(secret)
    }
}

impl From<BoxSecret> for DisconnectedUser {
    fn from(secret: BoxSecret) -> Self {
        Self(secret)
    }
}

pub(crate) struct ConnectedUser(CryptoBox);

pub(crate) struct EncryptedMessage {
    ciphertext: Vec<u8>,
    nonce: Nonce<CryptoBox>,
}

impl ConnectedUser {
    fn disconnect(self) -> DisconnectedUser {
        DisconnectedUser::default()
    }

    fn encrypt_message(&self, message_plaintext: &[u8]) -> Result<EncryptedMessage, Error> {
        let mut rng = rand::thread_rng();
        let nonce = generate_nonce(&mut rng);
        let ciphertext = self.0.encrypt(&nonce, message_plaintext)?;
        Ok(EncryptedMessage { ciphertext, nonce })
    }

    fn decrypt_message(&self, incoming_message: EncryptedMessage) -> Result<Vec<u8>, Error> {
        self.0.decrypt(
            &incoming_message.nonce,
            incoming_message.ciphertext.as_slice(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_connected_user() -> ConnectedUser {
        let alice = DisconnectedUser::default();
        let bob = DisconnectedUser::default();

        alice.into_connected(&bob.public_key())
    }
    #[test]
    fn encrypted_text_not_match_plaintext() {
        let alice = setup_connected_user();

        let plaintext = b"hello there";

        let encrypted_message = alice.encrypt_message(plaintext).unwrap();

        let ciphertext = encrypted_message.ciphertext.as_slice();

        assert_ne!(plaintext, ciphertext);
    }
    #[test]
    fn encrypted_text_decrypts_to_plaintext() {
        let alice = setup_connected_user();

        let plaintext = b"hello there";

        let encrypted = alice.encrypt_message(plaintext).unwrap();

        let decrypted = alice.decrypt_message(encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }
}
