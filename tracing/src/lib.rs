use aes_soft::block_cipher_trait::generic_array::GenericArray;
use aes_soft::block_cipher_trait::BlockCipher;
use aes_soft::Aes128;
use sha3::{Digest, Sha3_256};

pub mod path;
pub mod tree;

fn hash(x: &[u8]) -> [u8; 16] {
    let mut y: [u8; 16] = Default::default();
    y.copy_from_slice(&Sha3_256::digest(x).as_slice()[0..16]);
    y
}

fn prf(k: &[u8; 16], x: &[u8]) -> [u8; 16] {
    let mut y: [u8; 16] = Default::default();
    y.copy_from_slice(&Sha3_256::digest(&[k, x].concat()).as_slice()[0..16]);
    y
}

fn encipher(k: &[u8; 16], x: &[u8; 16]) -> [u8; 16] {
    let mut y: [u8; 16] = Default::default();
    let cipher = Aes128::new(GenericArray::from_slice(k));
    let mut block = GenericArray::clone_from_slice(x);
    cipher.encrypt_block(&mut block);
    y.copy_from_slice(&block.as_slice());
    y
}

fn decipher(k: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut x: [u8; 16] = Default::default();
    let cipher = Aes128::new(GenericArray::from_slice(k));
    let mut block = GenericArray::clone_from_slice(y);
    cipher.decrypt_block(&mut block);
    x.copy_from_slice(&block.as_slice());
    x
}
