use crate::pkey::*;
use crate::utils::printHexString;
use binds::Message_digest;
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey};
use openssl::sign::{Signer, Verifier};
use openssl::stack::StackRef;
use std::fs::File;
use std::io::{Read, Write};
use openssl::cms::{CmsContentInfo, CMSOptions};
use crate::pkey::genPkey;
use crate::pkey::GetPublicKey;
use crate::pkey::WriteKeys;
use openssl::asn1::Asn1Time;
use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod, SslStream, SslVersion};
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use std::fs;
use pdf_signing;

pub fn Test_Sign() {
    // Генарация пары ключей
    let pkey = genPkey().unwrap();

    // Запись ключей в Pem файл
    WriteKeys(&pkey, "public_key.pem", "private_key.pem");

    // Получение ключей из файлов виде объектов Pkey
    let public_key = GetPublicKey("public_key.pem");
    let private_key = GetPrivateKey("private_key.pem");

    // Данные для подписи
    let mut input = File::open("test.txt").unwrap();
    let mut data: Vec<u8> = Vec::new();
    input.read_to_end(data.as_mut()).unwrap();

    // Подписываем данные с хэш-функцией belt-hash и заносим подпись в файл
    let mut signer = Signer::new(MessageDigest::belt_hash(), &private_key).unwrap();
    signer.update(&data).unwrap();

    let signature = signer.sign_to_vec().unwrap();

    let mut sign_file = File::create("test_txt.sgn").unwrap();
    sign_file.write_all(&signature).unwrap();

    println!("Signature: {}", printHexString(&signature));

    // Проверяем подпись
    let mut sign_file = File::open("test_txt.sgn").unwrap();
    let mut signature: Vec<u8> = Vec::new();
    sign_file.read_to_end(signature.as_mut()).unwrap();

    //let pub_key = GetPublicKey("pub_key.pem");
    //let signature = hex::decode("511FF89ABE1AF32EA478727F7D347ED046271E85B45B559B2573C5485C85FCF39205AC0BA3FB3DC162869108516849D1").unwrap();
    //println!("{}", signature.len());
    let mut verifier = Verifier::new(MessageDigest::belt_hash(), &public_key).unwrap();
    verifier.update(&data).unwrap();

    println!("Verify Result: {}", verifier.verify(&signature).unwrap());
}

pub fn Test_CMS_sign(){

    //Генарация пары ключей
    let pkey = genPkey().unwrap();
    WriteKeys(&pkey, "cms_public.pem", "cms_private.pem");

    // Создать новый объект X509Name для имени субъекта запроса на сертификат
    let mut subject_nameBuilder = X509NameBuilder::new().unwrap();
    subject_nameBuilder.append_entry_by_text("CN", "127.0.0.1");
    let subject_name = subject_nameBuilder.build();
    // Создать новый объект X509Builder для создания запроса на сертификат

    let mut builder = X509Builder::new().unwrap();
    // Установить имя субъекта запроса на сертификат
    builder.set_subject_name(&subject_name).unwrap();
    // Установить открытый ключ запроса на сертификат
    builder.set_pubkey(&pkey).unwrap();
    builder
        .set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
        .unwrap();
    builder
        .set_not_after(Asn1Time::days_from_now(365).unwrap().as_ref())
        .unwrap();
    // Добавить расширение KeyUsage в запрос на сертификат
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .data_encipherment()
        .build()
        .unwrap();
    builder.append_extension(key_usage).unwrap();

    let mut extended_key_usage = ExtendedKeyUsage::new().server_auth().build().unwrap();
    builder.append_extension(extended_key_usage).unwrap();

    // Добавить расширение BasicConstraints в запрос на сертификат
    let basic_constraints = BasicConstraints::new().ca().pathlen(0).build().unwrap();
    builder.append_extension(basic_constraints).unwrap();
    
    // Подписать запрос на сертификат с использованием закрытого ключа
    builder.sign(&pkey, MessageDigest::belt_hash()).unwrap();

    let cert = builder.build();
    
    // Сохранить сертификат в файл
    let mut file = std::fs::File::create("cert.pem").unwrap();
    file.write_all(&cert.to_pem().unwrap()).unwrap();
    ///////////////////////////////////////////////////////////////////////////////////////

    let certificate_contents = fs::read("cert.pem").unwrap();
    let private_key_contents = fs::read("cms_private.pem").unwrap();
    let data = fs::read("dummy.pdf").unwrap();

    let signcert = X509::from_pem(&certificate_contents).unwrap();
    let pkey = PKey::private_key_from_pem(&private_key_contents).unwrap();
    
    let flags = CMSOptions::DETACHED | CMSOptions::BINARY;

    
    let cms = CmsContentInfo::sign(
      Some(&signcert),
      Some(&pkey),
      None, 
      Some(&data),
      flags
    ).unwrap();
    

    fs::write("signature.pem", cms.to_pem().unwrap()).unwrap();

}