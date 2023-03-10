/* ---------------------------------------------------------------- *
 * PROCESSES                                                        *
 * ---------------------------------------------------------------- */

use crate::{
    consts::{DHLEN, HASHLEN, MAC_LENGTH, MAX_MESSAGE, SECRET_DATA_CRC_OFFSET, SECRET_DATA_LEN},
    error::NoiseError,
    state::{CipherState, HandshakeState},
    types::{Hash, Keypair, PrivateKey, Psk, PublicKey},
    utils::from_slice_hashlen,
};
use wasm_bindgen::prelude::*;
/// A `NoiseSession` object is used to keep track of the states of both local
/// and remote parties before, during, and after a handshake.
///
/// It contains:
/// - `hs`: Keeps track of the local party's state while a handshake is being
///   performed.
/// - `h`:  Stores the handshake hash output after a successful handshake in a
///   Hash object. Is initialized as array of 0 bytes.
/// - `cs1`: Keeps track of the local party's post-handshake state. Contains a
///   cryptographic key and a nonce.
/// - `cs2`: Keeps track of the remote party's post-handshake state. Contains a
///   cryptographic key and a nonce.
/// - `mc`:  Keeps track of the total number of incoming and outgoing messages,
///   including those sent during a handshake.
/// - `i`: `bool` value that indicates whether this session corresponds to the
///   local or remote party.
/// - `is_transport`: `bool` value that indicates whether a handshake has been
///   performed succesfully with a remote session and the session is in transport mode.

#[wasm_bindgen]
pub struct NoiseSession {
    hs: HandshakeState,
    h: Hash,
    cs1: CipherState,
    cs2: CipherState,
    mc: u128,
    i: bool,
    is_transport: bool,
}

#[wasm_bindgen]
impl NoiseSession {
    /// Returns `true` if a handshake has been successfully performed and the session is in transport mode, or false otherwise.
    pub fn is_transport(&self) -> bool {
        self.is_transport
    }
    /// Clears `cs1`.
    pub fn clear_local_cipherstate(&mut self) {
        self.cs1.clear();
    }

    /// Clears `cs2`.
    pub fn clear_remote_cipherstate(&mut self) {
        self.cs2.clear();
    }

    /// Calls the [Rekey](https://noiseprotocol.org/noise.html#rekey) method for `cs1`
    pub fn rekey_local_cipherstate(&mut self) {
        self.cs1.rekey()
    }

    /// Calls the [Rekey](https://noiseprotocol.org/noise.html#rekey) method for `cs2`
    pub fn rekey_remote_cipherstate(&mut self) {
        self.cs1.rekey()
    }

    /// `NoiseSession` destructor function.
    pub fn end_session(mut self) {
        self.hs.clear();
        self.clear_local_cipherstate();
        self.clear_remote_cipherstate();
        self.cs2.clear();
        self.mc = 0;
        self.h = Hash::new();
    }

    /// Returns `h`.
    fn get_handshake_hash(&self) -> Option<[u8; HASHLEN]> {
        if self.is_transport {
            return Some(self.h.as_bytes());
        }
        None
    }

    /// Returns `mc`.
    fn get_message_count(&self) -> u128 {
        self.mc
    }

    /// Sets the value of the local ephemeral keypair as the parameter `e`.
    fn set_ephemeral_keypair(&mut self, e: Keypair) {
        self.hs.set_ephemeral_keypair(e);
    }

    /// Returns a `Option<PublicKey>` object that contains the remote party's static `PublicKey`.
    /// Note that this function returns `None` before a handshake is successfuly performed and
    /// the session is in transport mode.
    fn get_remote_static_public_key(&self) -> Option<PublicKey> {
        if self.is_transport {
            return Some(self.hs.get_remote_static_public_key());
        }
        None
    }

    /// Instantiates a `NoiseSession` object. Takes the following as parameters:
    /// - `initiator`: `bool` variable. To be set as `true` when initiating a handshake with a remote party, or `false` otherwise.
    /// - `prologue`: `Message` object. Could optionally contain the name of the protocol to be used.
    /// - `s`: `Keypair` object. Contains local party's static keypair.
    /// - `rs`: `Option<PublicKey>`. Contains the remote party's static public key.	Tip: use `Some(rs_value)` in case a remote static key exists and `None` otherwise.
    /// - `psk`: `Psk` object. Contains the pre-shared key.
    fn init_session(
        initiator: bool,
        prologue: &[u8],
        s: Keypair,
        rs: Option<PublicKey>,
        psk: Psk,
    ) -> NoiseSession {
        if initiator {
            NoiseSession {
                hs: HandshakeState::initialize_initiator(
                    prologue,
                    s,
                    rs.unwrap_or(PublicKey::empty()),
                    psk,
                ),
                mc: 0,
                i: initiator,
                cs1: CipherState::new(),
                cs2: CipherState::new(),
                h: Hash::new(),
                is_transport: false,
            }
        } else {
            NoiseSession {
                hs: HandshakeState::initialize_responder(
                    prologue,
                    s,
                    rs.unwrap_or(PublicKey::empty()),
                    psk,
                ),
                mc: 0,
                i: initiator,
                cs1: CipherState::new(),
                cs2: CipherState::new(),
                h: Hash::new(),
                is_transport: false,
            }
        }
    }

    fn verify_secret_crc(secret: &[u8; SECRET_DATA_LEN]) -> Result<(), NoiseError> {
        let checksum1 = ((secret[SECRET_DATA_CRC_OFFSET] as u32) << 0)
            + ((secret[SECRET_DATA_CRC_OFFSET + 1] as u32) << 8)
            + ((secret[SECRET_DATA_CRC_OFFSET + 2] as u32) << 16)
            + ((secret[SECRET_DATA_CRC_OFFSET + 3] as u32) << 24);
        let checksum2 = crc32fast::hash(&secret[..SECRET_DATA_CRC_OFFSET]);

        if checksum1 != checksum2 {
            Err(NoiseError::ChecksumError)
        } else {
            Ok(())
        }
    }

    fn init_session_from_secret_string(secret: &[u8]) -> Result<NoiseSession, NoiseError> {
        let mut secret_data = [0u8; SECRET_DATA_LEN];
        match hex::decode_to_slice(secret, &mut secret_data) {
            Ok(_) => (),
            Err(e) => return Err(NoiseError::Hex(e)),
        };

        NoiseSession::verify_secret_crc(&secret_data)?;

        let s = Keypair::from_key(PrivateKey::from_bytes(from_slice_hashlen(
            &secret_data[0..],
        )))?;
        let rs = PublicKey::from_bytes(from_slice_hashlen(&secret_data[DHLEN..]))?;
        let psk = Psk::from_bytes(from_slice_hashlen(&secret_data[2 * DHLEN..]));

        Ok(NoiseSession::init_session(true, b"asdf", s, Some(rs), psk))
    }

    pub fn init_session_from_secret(secret: &str) -> Result<NoiseSession, JsError> {
        match NoiseSession::init_session_from_secret_string(secret.as_bytes()) {
            Ok(val) => Ok(val),
            Err(e) => Err(JsError::new(&e.to_string())),
        }
    }

    /// Takes a `&mut [u8]` containing plaintext as a parameter.
    /// This method returns a `Ok(()))` upon successful encryption, and `Err(NoiseError)` otherwise
    /// _Note that for security reasons and for better performance, `send_message` overwrites the bytes containing the plaintext with the ciphertext. For this reason and to account for the fact that ciphertext and handshake messages encapsulate important values, a pattern specific padding of zero bytes must be added to the following messages.
    /// For transport messages:
    /// All messages must be appended with 16 empty bytes that act as a placeholder for the MAC (Message Authentication Code). These 16 bytes will be overwritten by `send_message`
    /// For handshake messages:
    /// Kindly use the message lengths listed in the test file under `../tests/handshake.rs`, where examples and notes are also provided.
    /// _Also Note that while `is_transport` is false the ciphertext will be included as a payload for handshake messages and thus will not offer the same guarantees offered by post-handshake messages._
    fn int_send_message(&mut self, in_out: &mut [u8]) -> Result<(), NoiseError> {
        if in_out.len() < MAC_LENGTH || in_out.len() > MAX_MESSAGE {
            return Err(NoiseError::UnsupportedMessageLengthError);
        }
        if self.mc == 0 {
            self.hs.write_message_a(in_out)?;
        } else if self.mc == 1 {
            let temp = self.hs.write_message_b(in_out)?;
            self.h = temp.0;
            self.is_transport = true;
            self.cs1 = temp.1;
            self.cs2 = temp.2;
            self.hs.clear();
        } else if self.i {
            self.cs1.write_message_regular(in_out)?;
        } else {
            self.cs2.write_message_regular(in_out)?;
        }
        self.mc += 1;
        Ok(())
    }

    pub fn send_message(&mut self, message: Option<String>) -> Result<String, JsError> {
        let mut in_out: [u8; MAX_MESSAGE] = [0; MAX_MESSAGE];
        match message {
            Some(val) => in_out.copy_from_slice(val.as_bytes()),
            None => (),
        };

        match self.int_send_message(&mut in_out) {
            Ok(_) => Ok(String::from_utf8(in_out.to_vec()).unwrap()),
            Err(e) => Err(JsError::new(&e.to_string())),
        }
    }

    /// Takes a `&mut [u8]` received from the remote party as a parameter.
    /// This method returns a `Ok(()))` upon successful decrytion. and `Err(NoiseError)` otherwise.
    /// _Note that for security reasons and for better performance, `recv_message` overwrites the bytes containing the ciphertext with the plaintext and clears the MAC from them last 16 bytes of the message, and other keys that might be encapsulated while performing a handshake.
    /// For transport messages:
    /// You should expect to find the plaintext in the same array you passed a reference of as a parameter. The last 16 bytes of this array will be zero bytes and can be safely ignored.
    /// For handshake messages:
    /// Kindly use the message lengths listed in the test file under `../tests/handshake.rs`, where examples and notes are also provided.
    ///
    /// _Note that while `is_transport` is false the ciphertext will be included as a payload for handshake messages and thus will not offer the same guarantees offered by post-handshake messages._
    fn recv_message(&mut self, in_out: &mut [u8]) -> Result<(), NoiseError> {
        if in_out.len() < MAC_LENGTH || in_out.len() > MAX_MESSAGE {
            return Err(NoiseError::UnsupportedMessageLengthError);
        }
        if self.mc == 0 {
            self.hs.read_message_a(in_out)?;
        } else if self.mc == 1 {
            let temp = self.hs.read_message_b(in_out)?;
            self.h = temp.0;
            self.is_transport = true;
            self.cs1 = temp.1;
            self.cs2 = temp.2;
            self.hs.clear();
        } else if self.i {
            self.cs2.read_message_regular(in_out)?;
        } else {
            self.cs1.read_message_regular(in_out)?;
        }
        self.mc += 1;
        Ok(())
    }
}
