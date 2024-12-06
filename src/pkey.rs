use openssl::pkey::{Id, PKey, Private, Public};
use openssl::pkey_ctx::PkeyCtx;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};

use crate::utils::printHexString;

pub fn genPkey() -> Result<PKey<Private>, Box<dyn Error>> {
    let mut ctx = PkeyCtx::new_id(Id::from_raw(1478) /*BIGN ID*/)?;
    ctx.keygen_init()?;
    let p_key: PKey<Private> = ctx.keygen()?;
    return Ok(p_key);
}

pub fn WriteKeys(pkey: &PKey<Private>, public_path: &str, private_path: &str) {
    let mut public_key_file = File::create(public_path).unwrap();

    public_key_file
        .write_all(&pkey.public_key_to_pem().unwrap())
        .unwrap();

    let mut private_key_file = File::create(private_path).unwrap();
    private_key_file
        .write_all(&pkey.private_key_to_pem_pkcs8().unwrap())
        .unwrap();
}

pub fn GetPublicKey(public_path: &str) -> PKey<Public> {
    let mut public_key_file = File::open(public_path).unwrap();
    let mut public_key: Vec<u8> = Vec::new();
    public_key_file.read_to_end(public_key.as_mut()).unwrap();

    let public_key = PKey::public_key_from_pem(&public_key).unwrap();
    return public_key;
}

pub fn GetPrivateKey(private_path: &str) -> PKey<Private> {
    let mut private_key_file = File::open(private_path).unwrap();
    let mut private_key: Vec<u8> = Vec::new();
    private_key_file.read_to_end(private_key.as_mut()).unwrap();

    let private_key = PKey::private_key_from_pem(&private_key).unwrap();
    return private_key;
}
