use crate::utils::printHexString;
use binds::md;

pub fn Test_BeltHash() {
    // Входные данные
    let input_str = b"test";

    let digest = md::belt_hash(input_str).unwrap();
    //Вывод результата
    let hexStrings = (printHexString(input_str), printHexString(&digest));
    println!("input data: {}", hexStrings.0);
    println!("output hash: {}", hexStrings.1);
}

pub fn Test_bash256() {
    // Входные данные
    let input_str = b"Some Crypto Text";

    let digest = md::bash256(input_str).unwrap();
    //Вывод результата
    let hexStrings = (printHexString(input_str), printHexString(&digest));
    println!("input data: {}", hexStrings.0);
    println!("output hash: {}", hexStrings.1);
}

pub fn Test_bash384() {
    // Входные данные
    let input_str = b"Some Crypto Text";

    let digest = md::bash384(input_str).unwrap();
    //Вывод результата
    let hexStrings = (printHexString(input_str), printHexString(&digest));
    println!("input data: {}", hexStrings.0);
    println!("output hash: {}", hexStrings.1);
}

pub fn Test_bash512() {
    // Входные данные
    let input_str = b"Some Crypto Text";

    let digest = md::bash512(input_str).unwrap();
    //Вывод результата
    let hexStrings = (printHexString(input_str), printHexString(&digest));
    println!("input data: {}", hexStrings.0);
    println!("output hash: {}", hexStrings.1);
}
