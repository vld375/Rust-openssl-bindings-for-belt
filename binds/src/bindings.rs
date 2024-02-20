//#[link(name = "libcrypto", kind = "static")]
extern "C" {
    pub fn EVP_belt_hash() -> *const openssl_sys::EVP_MD;
    pub fn EVP_bash256() -> *const openssl_sys::EVP_MD;
    pub fn EVP_bash384() -> *const openssl_sys::EVP_MD;
    pub fn EVP_bash512() -> *const openssl_sys::EVP_MD;

    pub fn EVP_belt_ecb256() -> *const openssl_sys::EVP_CIPHER;
    pub fn EVP_belt_cbc256() -> *const openssl_sys::EVP_CIPHER;
    pub fn EVP_belt_cfb256() -> *const openssl_sys::EVP_CIPHER;
    pub fn EVP_belt_ctr256() -> *const openssl_sys::EVP_CIPHER;

    pub fn EVP_PKEY_assign_BIGN(pkey: *mut openssl_sys::EVP_PKEY, bignkey: *const u8) -> i32;
}

