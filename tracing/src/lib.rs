use aes_soft::block_cipher_trait::generic_array::GenericArray;
use aes_soft::block_cipher_trait::BlockCipher;
use aes_soft::Aes128;
use sha3::{Digest, Sha3_256};

pub struct TraceMetadata {
    ptr: [u8; 16],
}

pub struct SenderTraceTag {
    addr: [u8; 16],
    ct: [u8; 16],
}

pub fn new_message(m: &[u8]) -> TraceMetadata {
    //TraceMetadata{ ptr: [0, 16] }
    TraceMetadata{ ptr: rand::random::<[u8; 16]>() }
}

pub fn generate_tag(k: &[u8; 16], m: &[u8], md: &TraceMetadata) -> SenderTraceTag {
    let mut addr: [u8; 16] = Default::default();
    let mut ct: [u8; 16] = Default::default();

    addr.copy_from_slice(&Sha3_256::digest(&[k, m].concat()).as_slice()[0..16]);

    let mut block = GenericArray::clone_from_slice(m);
    let cipher = Aes128::new(GenericArray::from_slice(&md.ptr));
    cipher.encrypt_block(&mut block);
    ct.copy_from_slice(&block.as_slice());

    SenderTraceTag{ addr: addr, ct: ct }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
