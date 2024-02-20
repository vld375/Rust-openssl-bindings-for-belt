#![allow(warnings)]
mod pkey;
mod utils;

mod test_hash;
use test_hash::*;

mod test_cipher;
use test_cipher::*;

mod test_cert_and_tls;
use test_cert_and_tls::*;

mod test_sign;
use test_sign::*;

fn main() {
    
    println!("//////// BELT-HASH ////////");
    Test_BeltHash();
    println!();
    println!("//////// BASH256 ////////");
    Test_bash256();
    println!();
    println!("//////// BASH384 ////////");
    Test_bash384();
    println!();
    println!("//////// BASH512 ////////");
    Test_bash512();
    println!();
    //////////////////////
    println!("//////// BELT-CBC256 ////////");
    Test_belt_cbc256();
    println!();
    println!("//////// BELT-CFB256 ////////");
    Test_belt_cfb256();
    println!();
    println!("//////// BELT-CTR256 ////////");
    Test_belt_ctr256();
    println!();
    println!("//////// BELT-ECB256 ////////");
    Test_belt_ecb256();
    println!();
    println!("//////// SIGN ////////");
    Test_Sign();
    Test_CMS_sign();
    Test_PKCS7_sign();
    println!();
    println!("//////// Cert ////////");
    Test_Cert_and_TLS();

}

//////////////////////////////////////////////////////////////////////////
