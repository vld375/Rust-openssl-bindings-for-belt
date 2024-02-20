use crate::utils::printHexString;
use binds::cipher;

pub fn Test_belt_cbc256() {
    let key =
        hex::decode("0c8414395fe337eff6d44d81e4feaf530c8414395fe337eff6d44d81e4feaf53").unwrap();
    let iv = hex::decode("138581f3e5f9a6e06a4e18760c9485c1").unwrap();
    let pt =
        hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51").unwrap();

    let buf = cipher::belt_cbc256_encrypt(&key, &iv, &pt).unwrap();

    println!("Input: {}", printHexString(&pt));
    println!("Encrypted Text: {}", printHexString(&buf));

    let buf2 = cipher::belt_cbc256_decrypt(&key, &iv, &buf).unwrap();

    println!("decrypted Text: {}", printHexString(&buf2));
}

pub fn Test_belt_ecb256() {
    let key =
        hex::decode("0c8414395fe337eff6d44d81e4feaf530c8414395fe337eff6d44d81e4feaf53").unwrap();
    let pt =
        hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51").unwrap();

    let buf = cipher::belt_ecb256_encrypt(&key, &pt).unwrap();

    println!("Input: {}", printHexString(&pt));
    println!("Encrypted Text: {}", printHexString(&buf));

    let buf2 = cipher::belt_ecb256_decrypt(&key, &buf).unwrap();

    println!("decrypted Text: {}", printHexString(&buf2));
}

pub fn Test_belt_cfb256() {
    let key =
        hex::decode("0c8414395fe337eff6d44d81e4feaf530c8414395fe337eff6d44d81e4feaf53").unwrap();
    let iv = hex::decode("138581f3e5f9a6e06a4e18760c9485c1").unwrap();
    let pt =
        hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51").unwrap();

    let buf = cipher::belt_cfb256_encrypt(&key, &iv, &pt).unwrap();

    println!("Input: {}", printHexString(&pt));
    println!("Encrypted Text: {}", printHexString(&buf));

    let buf2 = cipher::belt_cfb256_decrypt(&key, &iv, &buf).unwrap();

    println!("decrypted Text: {}", printHexString(&buf2));
}

pub fn Test_belt_ctr256() {
    let key =
        hex::decode("0c8414395fe337eff6d44d81e4feaf530c8414395fe337eff6d44d81e4feaf53").unwrap();
    let iv = hex::decode("138581f3e5f9a6e06a4e18760c9485c1").unwrap();
    let pt =
        hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51").unwrap();

    let buf = cipher::belt_ctr256_encrypt(&key, &iv, &pt).unwrap();

    println!("Input: {}", printHexString(&pt));
    println!("Encrypted Text: {}", printHexString(&buf));

    let buf2 = cipher::belt_ctr256_decrypt(&key, &iv, &buf).unwrap();

    println!("decrypted Text: {}", printHexString(&buf2));
}
