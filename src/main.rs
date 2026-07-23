// https://www.rfc-editor.org/info/rfc8439


fn __clear_u32_arr(arr: &mut [u32]) {
    for i in 0..arr.len() {
        unsafe {
            core::ptr::write_volatile::<u32>(
                &mut arr[i] as *mut u32, 0u32
            );
        }
    }
}


fn quarter_round(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(16);
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(12);
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(8);
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(7);

    (a, b, c, d)
}


fn inner_round(state: &mut [u32; 16]) {
    /* 
      QUARTERROUND(0, 4, 8, 12)
      QUARTERROUND(1, 5, 9, 13)
      QUARTERROUND(2, 6, 10, 14)
      QUARTERROUND(3, 7, 11, 15)
      QUARTERROUND(0, 5, 10, 15)
      QUARTERROUND(1, 6, 11, 12)
      QUARTERROUND(2, 7, 8, 13)
      QUARTERROUND(3, 4, 9, 14)
    */

    // columns round 
    (state[0], state[4], state[8], state[12]) = quarter_round(state[0], state[4], state[8], state[12]);
    (state[1], state[5], state[9], state[13]) = quarter_round(state[1], state[5], state[9], state[13]);
    (state[2], state[6], state[10], state[14]) = quarter_round(state[2], state[6], state[10], state[14]);
    (state[3], state[7], state[11], state[15]) = quarter_round(state[3], state[7], state[11], state[15]);

    // diagonal round
    (state[0], state[5], state[10], state[15]) = quarter_round(state[0], state[5], state[10], state[15]);
    (state[1], state[6], state[11], state[12]) = quarter_round(state[1], state[6], state[11], state[12]);
    (state[2], state[7], state[8], state[13]) = quarter_round(state[2], state[7], state[8], state[13]);
    (state[3], state[4], state[9], state[14]) = quarter_round(state[3], state[4], state[9], state[14]);
}


fn block_key_generator(key: &[u32; 8], block: u32, nonce: &[u32; 3]) -> [u32; 16] {
//    chacha20_block(key, counter, nonce):
//        state = constants | key | counter | nonce
//        initial_state = state
//        for i=1 upto 10
//        inner_block(state)
//        end
//        state += initial_state
//        return serialize(state)
//        end

    // STATE MAP:
    // c=constant k=key b=blockcount n=nonce
    // C C C C 
    // K K K K
    // K K K K
    // B N N N

    let mut state: [u32; 16] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
        block, nonce[0], nonce[1], nonce[2]
    ];
    
    let mut initial_state = state;

    for _ in 0..10 {
        inner_round(&mut state);
    }

    // adding initial state
    for el_i in 0..16 {
        state[el_i] = state[el_i].wrapping_add(initial_state[el_i])
    }

    
    // clearing memory of temp state var
    __clear_u32_arr(&mut initial_state);
    
    state
}


fn block_key_generator_le_wrapper(key: &[u8; 32], block: &[u8; 4], nonce: &[u8; 12]) -> [u8; 64] {
    // convert ordinary key, block and nonce to little endian (small bytes are first)
    let mut new_key = [0u32; 8];
    let mut le_result = [0u8; 64];

    for (dst, chunk) in new_key.iter_mut().zip(key.chunks_exact(4)) {
        *dst = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    let mut new_block = u32::from_le_bytes(*block);
    let mut new_nonce = [
        u32::from_le_bytes(nonce[0..4].try_into().unwrap()),
        u32::from_le_bytes(nonce[4..8].try_into().unwrap()),
        u32::from_le_bytes(nonce[8..12].try_into().unwrap()),
    ];

    let state = block_key_generator(&new_key, new_block, &new_nonce);

    for (state_el, chunk) in state.iter().zip(le_result.chunks_mut(4)) {
        chunk.copy_from_slice(
            &u32::to_le_bytes(*state_el)
        );
    }

    // clearing memory of temp state var
    __clear_u32_arr(&mut new_key);
    __clear_u32_arr(&mut new_nonce);

    unsafe {
        core::ptr::write_volatile::<u32>(
            &mut new_block as *mut u32, 0u32
        );
    }

    le_result
}


fn chacha20_process(text: &mut [u8], key: &[u8; 32], nonce: &[u8; 12]) {
    // process the text using chacha20 algorithm
    // text may be a plaintext or ciphertext
    // key in LE format
    
    let mut counter: u32 = 1;

    for chunk in text.chunks_mut(64) {
        let key_block = block_key_generator_le_wrapper(
                key, &u32::to_le_bytes(counter), nonce
        );

        // encrypting with stream block
        for (d, k) in chunk.iter_mut().zip(key_block.iter()) {
            *d = *d ^ *k;
        }
        
        counter += 1;
    }

    // clearing memory of temp state var
    counter = 0;
}


fn main() {
}


#[cfg(test)]
mod chacha20_tests {
    use super::*;

    #[test]
    fn test_quarter_round() {
        let (a, b, c, d) = quarter_round(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567);
        assert_eq!(a, 0xea2a92f4);
        assert_eq!(b, 0xcb1cf8ce);
        assert_eq!(c, 0x4581472e);
        assert_eq!(d, 0x5881c4bb);
    }


    #[test]
    fn test_block_key_generator() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 
            0x04, 0x05, 0x06, 0x07, 
            0x08, 0x09, 0x0a, 0x0b, 
            0x0c, 0x0d, 0x0e, 0x0f, 
            0x10, 0x11, 0x12, 0x13, 
            0x14, 0x15, 0x16, 0x17, 
            0x18, 0x19, 0x1a, 0x1b, 
            0x1c, 0x1d, 0x1e, 0x1f
        ];

        let block = [0x01, 0x00, 0x00, 0x00];

        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
        ];

        let state = block_key_generator_le_wrapper(&key, &block, &nonce);


        let expected_state = [
            0xe4e7f110u32, 0x15593bd1u32, 0x1fdd0f50u32, 0xc47120a3u32, 
            0xc7f4d1c7u32, 0x0368c033u32, 0x9aaa2204u32, 0x4e6cd4c3u32, 
            0x466482d2u32, 0x09aa9f07u32, 0x05d7c214u32, 0xa2028bd9u32, 
            0xd19c12b5u32, 0xb94e16deu32, 0xe883d0cbu32, 0x4e3c50a2u32, 
        ];
        
        for i in 0..16 {
            assert_eq!(
                state[i*4..(i+1)*4], 
                u32::to_le_bytes(expected_state[i])
            );
        }
    }


    #[test]
    fn test_chacha20_process() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 
            0x04, 0x05, 0x06, 0x07, 
            0x08, 0x09, 0x0a, 0x0b, 
            0x0c, 0x0d, 0x0e, 0x0f, 
            0x10, 0x11, 0x12, 0x13, 
            0x14, 0x15, 0x16, 0x17, 
            0x18, 0x19, 0x1a, 0x1b, 
            0x1c, 0x1d, 0x1e, 0x1f
        ];

        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
        ];

        let mut text = [
            0x4cu8, 0x61u8, 0x64u8, 0x69u8, 0x65u8, 0x73u8, 0x20u8, 0x61u8, 0x6eu8, 0x64u8, 0x20u8, 0x47u8, 0x65u8, 0x6eu8, 0x74u8, 0x6cu8, 
            0x65u8, 0x6du8, 0x65u8, 0x6eu8, 0x20u8, 0x6fu8, 0x66u8, 0x20u8, 0x74u8, 0x68u8, 0x65u8, 0x20u8, 0x63u8, 0x6cu8, 0x61u8, 0x73u8, 
            0x73u8, 0x20u8, 0x6fu8, 0x66u8, 0x20u8, 0x27u8, 0x39u8, 0x39u8, 0x3au8, 0x20u8, 0x49u8, 0x66u8, 0x20u8, 0x49u8, 0x20u8, 0x63u8, 
            0x6fu8, 0x75u8, 0x6cu8, 0x64u8, 0x20u8, 0x6fu8, 0x66u8, 0x66u8, 0x65u8, 0x72u8, 0x20u8, 0x79u8, 0x6fu8, 0x75u8, 0x20u8, 0x6fu8, 
            0x6eu8, 0x6cu8, 0x79u8, 0x20u8, 0x6fu8, 0x6eu8, 0x65u8, 0x20u8, 0x74u8, 0x69u8, 0x70u8, 0x20u8, 0x66u8, 0x6fu8, 0x72u8, 0x20u8, 
            0x74u8, 0x68u8, 0x65u8, 0x20u8, 0x66u8, 0x75u8, 0x74u8, 0x75u8, 0x72u8, 0x65u8, 0x2cu8, 0x20u8, 0x73u8, 0x75u8, 0x6eu8, 0x73u8, 
            0x63u8, 0x72u8, 0x65u8, 0x65u8, 0x6eu8, 0x20u8, 0x77u8, 0x6fu8, 0x75u8, 0x6cu8, 0x64u8, 0x20u8, 0x62u8, 0x65u8, 0x20u8, 0x69u8, 
            0x74u8, 0x2eu8 
        ];

        chacha20_process(&mut text, &key, &nonce);
        
        let expected_ciphertext = [
            0x6eu8, 0x2eu8, 0x35u8, 0x9au8, 0x25u8, 0x68u8, 0xf9u8, 0x80u8, 0x41u8, 0xbau8, 0x07u8, 0x28u8, 0xddu8, 0x0du8, 0x69u8, 0x81u8, 
            0xe9u8, 0x7eu8, 0x7au8, 0xecu8, 0x1du8, 0x43u8, 0x60u8, 0xc2u8, 0x0au8, 0x27u8, 0xafu8, 0xccu8, 0xfdu8, 0x9fu8, 0xaeu8, 0x0bu8, 
            0xf9u8, 0x1bu8, 0x65u8, 0xc5u8, 0x52u8, 0x47u8, 0x33u8, 0xabu8, 0x8fu8, 0x59u8, 0x3du8, 0xabu8, 0xcdu8, 0x62u8, 0xb3u8, 0x57u8, 
            0x16u8, 0x39u8, 0xd6u8, 0x24u8, 0xe6u8, 0x51u8, 0x52u8, 0xabu8, 0x8fu8, 0x53u8, 0x0cu8, 0x35u8, 0x9fu8, 0x08u8, 0x61u8, 0xd8u8, 
            0x07u8, 0xcau8, 0x0du8, 0xbfu8, 0x50u8, 0x0du8, 0x6au8, 0x61u8, 0x56u8, 0xa3u8, 0x8eu8, 0x08u8, 0x8au8, 0x22u8, 0xb6u8, 0x5eu8, 
            0x52u8, 0xbcu8, 0x51u8, 0x4du8, 0x16u8, 0xccu8, 0xf8u8, 0x06u8, 0x81u8, 0x8cu8, 0xe9u8, 0x1au8, 0xb7u8, 0x79u8, 0x37u8, 0x36u8, 
            0x5au8, 0xf9u8, 0x0bu8, 0xbfu8, 0x74u8, 0xa3u8, 0x5bu8, 0xe6u8, 0xb4u8, 0x0bu8, 0x8eu8, 0xedu8, 0xf2u8, 0x78u8, 0x5eu8, 0x42u8, 
            0x87u8, 0x4du8, 
        ];

        for (c_b, exp_b) in text.iter().zip(expected_ciphertext.iter()) {
            assert_eq!(c_b, exp_b);
        }
    }


    #[test]
    fn test_chacha20_encrypt_and_decrypt() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 
            0x04, 0x05, 0x06, 0x07, 
            0x08, 0x09, 0x0a, 0x0b, 
            0x0c, 0x0d, 0x0e, 0x0f, 
            0x10, 0x11, 0x12, 0x13, 
            0x14, 0x15, 0x16, 0x17, 
            0x18, 0x19, 0x1a, 0x1b, 
            0x1c, 0x1d, 0x1e, 0x1f
        ];

        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
        ];

        let mut text = [
            0x4cu8, 0x61u8, 0x64u8, 0x69u8, 0x65u8, 0x73u8, 0x20u8, 0x61u8, 0x6eu8, 0x64u8, 0x20u8, 0x47u8, 0x65u8, 0x6eu8, 0x74u8, 0x6cu8, 
            0x65u8, 0x6du8, 0x65u8, 0x6eu8, 0x20u8, 0x6fu8, 0x66u8, 0x20u8, 0x74u8, 0x68u8, 0x65u8, 0x20u8, 0x63u8, 0x6cu8, 0x61u8, 0x73u8, 
            0x73u8, 0x20u8, 0x6fu8, 0x66u8, 0x20u8, 0x27u8, 0x39u8, 0x39u8, 0x3au8, 0x20u8, 0x49u8, 0x66u8, 0x20u8, 0x49u8, 0x20u8, 0x63u8, 
            0x6fu8, 0x75u8, 0x6cu8, 0x64u8, 0x20u8, 0x6fu8, 0x66u8, 0x66u8, 0x65u8, 0x72u8, 0x20u8, 0x79u8, 0x6fu8, 0x75u8, 0x20u8, 0x6fu8, 
            0x6eu8, 0x6cu8, 0x79u8, 0x20u8, 0x6fu8, 0x6eu8, 0x65u8, 0x20u8, 0x74u8, 0x69u8, 0x70u8, 0x20u8, 0x66u8, 0x6fu8, 0x72u8, 0x20u8, 
            0x74u8, 0x68u8, 0x65u8, 0x20u8, 0x66u8, 0x75u8, 0x74u8, 0x75u8, 0x72u8, 0x65u8, 0x2cu8, 0x20u8, 0x73u8, 0x75u8, 0x6eu8, 0x73u8, 
            0x63u8, 0x72u8, 0x65u8, 0x65u8, 0x6eu8, 0x20u8, 0x77u8, 0x6fu8, 0x75u8, 0x6cu8, 0x64u8, 0x20u8, 0x62u8, 0x65u8, 0x20u8, 0x69u8, 
            0x74u8, 0x2eu8 
        ];

        let original_text = text;

        // encrypt data
        chacha20_process(&mut text, &key, &nonce);
        
        // decrypt data
        chacha20_process(&mut text, &key, &nonce);

        for (or_b, p_b) in original_text.iter().zip(text.iter()) {
            assert_eq!(or_b, p_b);
        }

        println!("Original text (encrypt and decrypt test): ");
        println!("->   {}", str::from_utf8(&original_text).unwrap());
        println!("Decrypted text (encrypt and decrypt test): ");
        println!("->   {}", str::from_utf8(&text).unwrap());
    }
}
