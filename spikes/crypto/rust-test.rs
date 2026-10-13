// Minimal std-only caller of the single Swift C ABI.
use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn oftc_swift_aes256_cbc(
        encrypt: c_int,
        key: *const u8,
        key_len: usize,
        iv: *const u8,
        iv_len: usize,
        input: *const u8,
        input_len: usize,
        output: *mut u8,
        output_len: usize,
    ) -> c_int;
    fn oftc_swift_hmac(
        sha256: c_int,
        key: *const u8,
        key_len: usize,
        input: *const u8,
        input_len: usize,
        digest: *mut u8,
        digest_len: usize,
    ) -> c_int;
    fn oftc_swift_random(output: *mut u8, output_len: usize) -> c_int;
    fn oftc_swift_group20_generate(key_out: *mut *mut c_void,
                                   public_out: *mut u8) -> c_int;
    fn oftc_swift_group20_shared(key: *mut c_void, peer: *const u8,
                                 peer_len: usize, secret: *mut u8,
                                 secret_len: usize) -> c_int;
    fn oftc_swift_group20_free(key: *mut c_void);
}

fn main() {
    let key = [0x0b_u8; 20];
    let message = b"Hi There";
    let mut digest = [0_u8; 32];
    let status = unsafe {
        oftc_swift_hmac(1, key.as_ptr(), key.len(), message.as_ptr(), message.len(),
                  digest.as_mut_ptr(), digest.len())
    };
    assert_eq!(status, 0);
    assert_eq!(digest, [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    ]);
    let mut sha1 = [0_u8; 20];
    assert_eq!(unsafe {
        oftc_swift_hmac(0, key.as_ptr(), key.len(), message.as_ptr(), message.len(),
                        sha1.as_mut_ptr(), sha1.len())
    }, 0);
    assert_eq!(sha1, [
        0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b,
        0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
    ]);
    assert_eq!(unsafe {
        oftc_swift_hmac(1, key.as_ptr(), key.len(), message.as_ptr(), message.len(),
                        digest.as_mut_ptr(), 20)
    }, -1);
    let mut random = [0_u8; 32];
    assert_eq!(unsafe { oftc_swift_random(random.as_mut_ptr(), random.len()) }, 0);
    assert_ne!(random, [0_u8; 32]);
    assert_eq!(unsafe { oftc_swift_random(std::ptr::null_mut(), 32) }, -1);

    let aes_key = [0_u8; 32];
    let iv = [0_u8; 16];
    let input = [0_u8; 16];
    let mut ciphertext = [0_u8; 16];
    let mut plain = [0_u8; 16];
    assert_eq!(unsafe {
        oftc_swift_aes256_cbc(1, aes_key.as_ptr(), 32, iv.as_ptr(), 16,
                        input.as_ptr(), 16, ciphertext.as_mut_ptr(), 16)
    }, 0);
    assert_eq!(unsafe {
        oftc_swift_aes256_cbc(0, aes_key.as_ptr(), 32, iv.as_ptr(), 16,
                        ciphertext.as_ptr(), 16, plain.as_mut_ptr(), 16)
    }, 0);
    assert_eq!(plain, input);
    assert_eq!(unsafe {
        oftc_swift_aes256_cbc(1, aes_key.as_ptr(), 32, iv.as_ptr(), 16,
                              input.as_ptr(), 15, ciphertext.as_mut_ptr(), 16)
    }, -1);
    println!("PASS: Rust-to-Swift FFI HMAC, CBC, random");

    let mut a = std::ptr::null_mut();
    let mut b = std::ptr::null_mut();
    let mut pub_a = [0_u8; 96];
    let mut pub_b = [0_u8; 96];
    let mut ab = [0_u8; 48];
    let mut ba = [0_u8; 48];
    unsafe {
        assert_eq!(oftc_swift_group20_generate(&mut a, pub_a.as_mut_ptr()), 0);
        assert_eq!(oftc_swift_group20_generate(&mut b, pub_b.as_mut_ptr()), 0);
        assert_eq!(oftc_swift_group20_shared(a, pub_b.as_ptr(), 96,
                                              ab.as_mut_ptr(), 48), 0);
        assert_eq!(oftc_swift_group20_shared(b, pub_a.as_ptr(), 96,
                                              ba.as_mut_ptr(), 48), 0);
        assert_eq!(oftc_swift_group20_shared(a, pub_b.as_ptr(), 95,
                                              ab.as_mut_ptr(), 48), -1);
        assert_eq!(oftc_swift_group20_shared(a, [0_u8; 96].as_ptr(), 96,
                                              ab.as_mut_ptr(), 48), -2);
        oftc_swift_group20_free(a);
        oftc_swift_group20_free(b);
    }
    assert_eq!(ab, ba);
    println!("PASS: Rust-to-Swift FFI group-20 exchange");
}
