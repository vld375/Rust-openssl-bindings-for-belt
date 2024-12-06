use crate::pkey::genPkey;
use crate::pkey::GetPublicKey;
use crate::pkey::WriteKeys;
use binds::Message_digest;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod, SslStream, SslVersion};
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;

pub fn Test_Cert_and_TLS() {
    CreateCert();
    ////////////////////////////////////////////////////////////////////
    CheckCert();
    ////////////////////////////////////////////////////////////////////
    // CreateTCPServer();
}

fn CreateCert() {
    //Генарация пары ключей
    let pkey = genPkey().unwrap();
    WriteKeys(&pkey, "cert_public.pem", "cert_private.pem");
    // Сохранить закрытый ключ в файл
    let mut file = std::fs::File::create("server.key").unwrap();
    file.write_all(&pkey.private_key_to_pem_pkcs8().unwrap())
        .unwrap();

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
    let mut file = std::fs::File::create("server.crt").unwrap();
    file.write_all(&cert.to_pem().unwrap()).unwrap();
}

fn CheckCert() {
    // Проверка сертификата по публичному ключу
    let mut cert_file = File::open("server.crt").unwrap();
    let mut certData: Vec<u8> = Vec::new();
    cert_file.read_to_end(certData.as_mut()).unwrap();

    let cert = X509::from_pem(&certData).unwrap();
    let public_key = GetPublicKey("cert_public.pem");
    println!(
        "Check certificate with public key: {}",
        cert.verify(&public_key).unwrap()
    );
    println!("{:?}", cert)
}

fn CreateTCPServer() {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor.set_cipher_list("DHT-PSK-BIGN-BELT-DWP-HBELT:DHE-PSK-BIGN-BELT-DWP-HBELT:DHT-PSK-BIGN-BELT-CTR-MAC-HBELT:DHE-PSK-BIGN-BELT-CTR-MAC-HBELT:DHT-BIGN-BELT-CTR-MAC-HBELT:DHE-BIGN-BELT-CTR-MAC-HBELT:DHE-BIGN-BELT-DWP-HBELT:DHT-BIGN-BELT-DWP-HBELT").unwrap();
    acceptor
        .set_private_key_file("server.key", SslFiletype::PEM)
        .unwrap();
    acceptor
        .set_certificate_file("server.crt", SslFiletype::PEM)
        .unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    acceptor.check_private_key().unwrap();
    let acceptor = Arc::new(acceptor.build());

    let listener = TcpListener::bind("127.0.0.1:8443").unwrap();
    println!("Server started");

    fn handle_client(stream: SslStream<TcpStream>) {
        // ...
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let acceptor = acceptor.clone();
                thread::spawn(move || {
                    let stream = acceptor.accept(stream).unwrap();
                    handle_client(stream);
                });
            }
            Err(e) => {
                println!("connection failed: {}", e)
            }
        }
    }
}
