use std::{fs, io};
use std::fs::File;
use std::io::{Cursor, Read, stdin, Write};
use std::path::Path;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
use argon2::password_hash::SaltString;
use colored::{Color, Colorize};
use colored::Color::Blue;
use rand::rngs::OsRng;
use rand::TryRngCore;
use tar::Builder;

fn main() {
    println!("write lock for lock write anything else for unlock");
    let mut somthing = String::new();
    stdin().read_line(&mut somthing).unwrap();
    if (somthing.trim() == "lock") {
        lock_prompt()
    } else { 
        unlock_prompt()
    }
}

fn lock_prompt() {
    let mut color1_text : String = String::new();
    let mut color2_text : String = String::new();

    color1_text = "Write the name of the folder you want to lock.".to_string();
    color2_text = "(make sure it's in the same folder as the app)".to_string();
    println!("{} {}", color1_text.color(Color::Blue), color2_text.color(Color::White));
    let mut dir_name : String = String::new();
    io::stdin().read_line(&mut dir_name).expect("Invalid dir_name!");
    color1_text = "Write the password you want to encrypt the folder with.".to_string();
    println!("{}", color1_text.color(Blue));
    let mut password : String = String::new();
    io::stdin().read_line(&mut/*hi hru fellow devs*/ password).expect("Invalid password!");
    dir_name = dir_name.trim().to_string();
    password = password.trim().to_string();
    
    let directory : &Path = Path::new(&dir_name);
    if directory.exists() && directory.metadata().unwrap().is_dir() {
        println!("Directory '{}' found. Proceeding with lock...", dir_name);
        lock(dir_name, password);
    } else {
        println!("Directory '{}' does not exist or is not a folder!", dir_name);
    }
}

fn lock(dir: String, pwd: String) {
    let mut tar_bytes: Vec<u8> = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_bytes);
        let archive_name = Path::new(&dir)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| dir.clone());
        builder.append_dir_all(archive_name, &dir).unwrap();
        builder.finish().unwrap();
    }

    fs::create_dir_all(format!("{}_locked", &dir)).unwrap();
    let enc_path = format!("{dir}_locked/locked.tar.enc");
    let meta_path = format!("{dir}_locked/locked.meta");

    let mut salt = [0u8; 16];
    OsRng.try_fill_bytes(&mut salt).unwrap();
    let mut nonce_bytes = [0u8; 12];
    OsRng.try_fill_bytes(&mut nonce_bytes).unwrap();

    let key = derive_key_from_password(pwd.as_str(), &salt);

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, tar_bytes.as_slice()).unwrap();

    let mut enc_file = File::create(&enc_path).unwrap();
    enc_file.write_all(&ciphertext).unwrap();

    let mut meta_file = File::create(&meta_path).unwrap();
    meta_file.write_all(&salt).unwrap();
    meta_file.write_all(&nonce_bytes).unwrap();
    meta_file.flush().unwrap();

    println!("Wrote encrypted: {}", enc_path);
    println!("Wrote metadata: {}", meta_path);
}

fn derive_key_from_password(password: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut key = [0u8; 32];

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());

    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Argon2 key derivation failed");

    key
}

fn write_meta(dat_path: &str, salt: [u8;16], nonce: [u8;12], password: &str) {
    let salt_string = SaltString::encode_b64(&salt).expect("invalid salt length");

    let argon = Argon2::default();
    let phc_hash = argon
        .hash_password(password.as_bytes(), &salt_string)
        .expect("argon2 hash failed")
        .to_string();

    let mut f = File::create(dat_path.to_string()).expect("failed to create dat file");
    f.write_all(&salt).expect("write salt");
    f.write_all(&nonce).expect("write nonce");
    let hash_bytes = phc_hash.as_bytes();
    let len_be = (hash_bytes.len() as u16).to_be_bytes();
    f.write_all(&len_be).expect("write length");
    f.write_all(hash_bytes).expect("write hash");
    f.flush().expect("flush dat");
}

fn unlock_prompt() {
    let header = "Write the name of the folder you want to unlock.".blue();
    let hint = "(folder should have been locked by this app)".white();
    println!("{} {}", header, hint);

    let mut dir_name = String::new();
    io::stdin().read_line(&mut dir_name).expect("Invalid dir_name!");
    let dir_name = dir_name.trim().to_string();

    let pw_prompt = "Write the password to unlock the folder.".blue();
    println!("{}", pw_prompt);

    let mut password = String::new();
    io::stdin().read_line(&mut password).expect("Invalid password!");
    let password = password.trim().to_string();

    let enc_path = format!("{dir_name}_locked/locked.tar.enc");
    let meta_path = format!("{dir_name}_locked/locked.meta");
    if !std::path::Path::new(&enc_path).exists() || !std::path::Path::new(&meta_path).exists() {
        eprintln!("{}", "Error: locked files not found for that folder.".red());
        return;
    }

    unlock(dir_name, password);
}

fn unlock(dir: String, pwd: String) {
    let enc_path = format!("{dir}_locked/locked.tar.enc");
    let meta_path = format!("{dir}_locked/locked.meta");

    println!("{}", "Reading metadata...".yellow());
    let mut meta_buf = Vec::new();
    File::open((&meta_path).to_string()).unwrap().read_to_end(&mut meta_buf).unwrap();
    if meta_buf.len() < 28 {
        eprintln!("{}", "Metadata file corrupt or too small.".red());
        return;
    }

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&meta_buf[0..16]);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&meta_buf[16..28]);

    println!("{}", "Deriving key from password...".yellow());
    let key = derive_key_from_password(pwd.as_str(), &salt);

    println!("{}", "Reading ciphertext...".yellow());
    let mut cipher_buf = Vec::new();
    File::open((&enc_path).to_string()).unwrap().read_to_end(&mut cipher_buf).unwrap();

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);
    println!("{}", "Attempting decryption...".yellow());
    let plaintext = match cipher.decrypt(nonce, cipher_buf.as_ref()) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("{}", "Decryption failed — wrong password or tampered file.".red());
            return;
        }
    };

    println!("{}", "Decryption successful — unpacking tar...".green());
    let restored_dir = format!("{}_restored", dir);
    std::fs::create_dir_all((&restored_dir).to_string()).unwrap();

    let cursor = Cursor::new(plaintext);
    let mut archive = tar::Archive::new(cursor);
    archive.unpack((&restored_dir).to_string()).unwrap();

    println!("{}", format!("Unpacked to {restored_dir}/").green());
}

// yay (kill me)