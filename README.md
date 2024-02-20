# Rust openssl bindings for belt
 
# Binds crate:
binds/src/bindings.rs - функции из DLL в Rust  
binds/src/cipher.rs - Функции шифрования/дешифрования  
binds/src/md.rs - Функции хэширования  
binds/src/evp_binds.rs - привязка EVP функций к структурам Md, Cipher, MessageDigiest через трейты  

# Main crate:
src/test_sign.rs - Проверка формирования подписи через Signer, CMS, PKCS7  
src/test_hash.rs - Проверка хэширования  
src/test_cipher.rs - Проверка шифрования/дешифрования  
src/test_cert_and_tls.rs - Проверка создания сертификатов и их использование для TLS  
src/pkey.rs - Генерация BIGN ключей, запись/чтение в файл  
src/utils.rs - Доп.функции для вывода  

# Подключение:
1. Перекинуть папку binds в папку проекта  
2. в Cargo.toml добавить в [dependencies] строку " binds = { path = "binds" } "  
   
![image](https://github.com/BakeySounder/Rust-openssl-bindings-for-belt/assets/65306613/d4d1e9e9-d4b3-4361-9d06-97bdfc7e3da8)

4. добавить DLL файлы в папку:  
target/debug/libcrypto.lib  
target/debug/libcrypto-1_1-x64.dll  
target/debug/libssl.lib  
target/debug/libssl-1_1-x64.dll    

# Результат тестовой программы:  
![image](https://github.com/BakeySounder/Rust-openssl-bindings-for-belt/assets/65306613/ef949ba8-8348-44f4-9f45-a353b385a27f)
