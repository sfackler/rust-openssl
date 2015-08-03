use crypto::symm;
use ffi;

pub fn evpc(t: symm::Type) -> (*const ffi::EVP_CIPHER, u32, u32) {
    unsafe {
        match t {
            symm::Type::AES_128_ECB => (ffi::EVP_aes_128_ecb(), 16, 16),
            symm::Type::AES_128_CBC => (ffi::EVP_aes_128_cbc(), 16, 16),
            #[cfg(feature = "aes_xts")]
            symm::Type::AES_128_XTS => (ffi::EVP_aes_128_xts(), 32, 16),
            #[cfg(feature = "aes_ctr")]
            symm::Type::AES_128_CTR => (ffi::EVP_aes_128_ctr(), 16, 0),
            //AES_128_GCM => (EVP_aes_128_gcm(), 16, 16),

            symm::Type::AES_256_ECB => (ffi::EVP_aes_256_ecb(), 32, 16),
            symm::Type::AES_256_CBC => (ffi::EVP_aes_256_cbc(), 32, 16),
            #[cfg(feature = "aes_xts")]
            symm::Type::AES_256_XTS => (ffi::EVP_aes_256_xts(), 64, 16),
            #[cfg(feature = "aes_ctr")]
            symm::Type::AES_256_CTR => (ffi::EVP_aes_256_ctr(), 32, 0),
            //AES_256_GCM => (EVP_aes_256_gcm(), 32, 16),

            symm::Type::RC4_128 => (ffi::EVP_rc4(), 16, 0),
        }
    }
}