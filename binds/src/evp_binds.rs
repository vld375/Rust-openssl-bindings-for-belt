use crate::bindings::*;
use openssl::md::MdRef;
use openssl::md::Md;
use openssl::cipher::CipherRef;
use foreign_types::ForeignTypeRef;
use openssl::hash::MessageDigest;

pub trait Belt {
    fn belt_hash() -> &'static MdRef;
    fn bash256() -> &'static MdRef;
    fn bash384() -> &'static MdRef;
    fn bash512() -> &'static MdRef;

    fn belt_ecb256() -> &'static CipherRef;
    fn belt_cbc256() -> &'static CipherRef;
    fn belt_cfb256() -> &'static CipherRef;
    fn belt_ctr256() -> &'static CipherRef;
}
impl Belt for Md{
    fn belt_hash() -> &'static MdRef {
        unsafe { MdRef::from_ptr(EVP_belt_hash() as *mut _) }
    }
    fn bash256() -> &'static MdRef {
        unsafe { MdRef::from_ptr(EVP_bash256() as *mut _) }
    }
    fn bash384() -> &'static MdRef {
        unsafe { MdRef::from_ptr(EVP_bash384() as *mut _) }
    }
    fn bash512() -> &'static MdRef {
        unsafe { MdRef::from_ptr(EVP_bash512() as *mut _) }
    }
    
    fn belt_ecb256() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(EVP_belt_ecb256() as *mut _) }
    }
    fn belt_cbc256() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(EVP_belt_cbc256() as *mut _) }
    }
    fn belt_cfb256() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(EVP_belt_cfb256() as *mut _) }
    }
    fn belt_ctr256() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(EVP_belt_ctr256() as *mut _) }
    }
}

pub trait Message_digest {
    fn belt_hash() -> MessageDigest;
    fn bash256() -> MessageDigest;
    fn bash384() -> MessageDigest;
    fn bash512() -> MessageDigest;
}
impl Message_digest for MessageDigest {
    fn belt_hash() -> MessageDigest{
        return unsafe { MessageDigest::from_ptr(EVP_belt_hash()) };
    }
    fn bash256() -> MessageDigest{
        return unsafe { MessageDigest::from_ptr(EVP_bash256()) };
    }
    fn bash384() -> MessageDigest{
        return unsafe { MessageDigest::from_ptr(EVP_bash384()) };
    }
    fn bash512() -> MessageDigest{
        return unsafe { MessageDigest::from_ptr(EVP_bash512()) };
    }
}