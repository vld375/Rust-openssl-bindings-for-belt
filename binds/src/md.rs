use openssl::md_ctx::MdCtx;
use openssl::md::Md;
use std::error::Error;
use crate::evp_binds::BeltMD;

pub fn belt_hash(input_str: &[u8]) -> Result<[u8;32], Box<dyn Error>> {
    let mut digest = [0;32];
    let mut ctx = MdCtx::new()?;
    ctx.digest_init(Md::belt_hash())?;
    ctx.digest_update(input_str)?;
    ctx.digest_final(&mut digest)?;
    return Ok(digest);
}

pub fn bash256(input_str: &[u8]) -> Result<[u8;32], Box<dyn Error>> {
    let mut digest = [0;32];
    let mut ctx = MdCtx::new()?;
    ctx.digest_init(Md::bash256())?;
    ctx.digest_update(input_str)?;
    ctx.digest_final(&mut digest)?;
    return Ok(digest);
}

pub fn bash384(input_str: &[u8]) -> Result<[u8;48], Box<dyn Error>> {
    let mut digest = [0;48];
    let mut ctx = MdCtx::new()?;
    
    ctx.digest_init(Md::bash384())?;
    ctx.digest_update(input_str)?;
    ctx.digest_final(&mut digest)?;
    return Ok(digest);
}

pub fn bash512(input_str: &[u8]) -> Result<[u8;64], Box<dyn Error>> {
    let mut digest = [0;64];
    let mut ctx = MdCtx::new()?;
    ctx.digest_init(Md::bash512())?;
    ctx.digest_update(input_str)?;
    ctx.digest_final(&mut digest)?;
    return Ok(digest);
}