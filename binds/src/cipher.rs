use openssl::{cipher_ctx::CipherCtx, md::Md, cipher::Cipher};
use std::error::Error;
use crate::evp_binds::BeltCipher;

pub fn belt_cbc256_decrypt(key: &Vec<u8>, iv: &Vec<u8>, data: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut ctx = CipherCtx::new()?;
    let mut buf = vec![];

    ctx.decrypt_init(Some(Cipher::belt_cbc256()), Some(key), Some(iv))?;
    ctx.set_padding(false);
    ctx.cipher_update_vec(&data, &mut buf)?;
    ctx.cipher_final_vec(&mut buf)?;

    return Ok(buf);
}

pub fn belt_cbc256_encrypt(key: &Vec<u8>, iv: &Vec<u8>, pt: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut ctx = CipherCtx::new()?;
    let mut buf = vec![];

    ctx.encrypt_init(Some(Cipher::belt_cbc256()), Some(key), Some(iv))?;
    ctx.set_padding(false);
    ctx.cipher_update_vec(&pt, &mut buf)?;
    ctx.cipher_final_vec(&mut buf)?;

    return Ok(buf);
}

pub fn belt_ecb256_decrypt(key: &Vec<u8>,  data: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut ctx = CipherCtx::new()?;
    let mut buf = vec![];

    ctx.decrypt_init(Some(Cipher::belt_ecb256()), Some(&key), None)?;
    ctx.set_padding(false);
    ctx.cipher_update_vec(&data, &mut buf)?;
    ctx.cipher_final_vec(&mut buf)?;

    return Ok(buf);
}

pub fn belt_ecb256_encrypt(key: &Vec<u8>, pt: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut ctx = CipherCtx::new()?;
    let mut buf = vec![];

    ctx.encrypt_init(Some(Cipher::belt_ecb256()), Some(key), None)?;
    ctx.set_padding(false);
    ctx.cipher_update_vec(pt, &mut buf)?;
    ctx.cipher_final_vec(&mut buf)?;
    return Ok(buf);
}

pub fn belt_cfb256_decrypt(key: &Vec<u8>, iv: &Vec<u8>, data: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut ctx = CipherCtx::new()?;
    let mut buf = vec![];

    ctx.decrypt_init(Some(Cipher::belt_cfb256()), Some(&key), Some(&iv))?;
    ctx.set_padding(false);
    ctx.cipher_update_vec(&data, &mut buf)?;
    ctx.cipher_final_vec(&mut buf)?;

    return Ok(buf);
}

pub fn belt_cfb256_encrypt(key: &Vec<u8>, iv: &Vec<u8>, pt: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut ctx = CipherCtx::new()?;
    let mut buf = vec![];

    ctx.encrypt_init(Some(Cipher::belt_cfb256()), Some(key), Some(iv))?;
    ctx.set_padding(false);
    ctx.cipher_update_vec(pt, &mut buf)?;
    ctx.cipher_final_vec(&mut buf)?;

    return Ok(buf);
}

pub fn belt_ctr256_decrypt(key: &Vec<u8>, iv: &Vec<u8>, data: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut ctx = CipherCtx::new()?;
    let mut buf = vec![];

    ctx.decrypt_init(Some(Cipher::belt_ctr256()), Some(&key), Some(&iv))?;
    ctx.set_padding(false);
    ctx.cipher_update_vec(&data, &mut buf)?;
    ctx.cipher_final_vec(&mut buf)?;

    return Ok(buf);
}

pub fn belt_ctr256_encrypt(key: &Vec<u8>, iv: &Vec<u8>, pt: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut ctx = CipherCtx::new()?;
    let mut buf = vec![];

    ctx.encrypt_init(Some(Cipher::belt_ctr256()), Some(key), Some(iv))?;
    ctx.set_padding(false);
    ctx.cipher_update_vec(pt, &mut buf)?;
    ctx.cipher_final_vec(&mut buf)?;
    
    return Ok(buf);
}