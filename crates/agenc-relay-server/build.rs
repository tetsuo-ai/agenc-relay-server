#![forbid(unsafe_code)]

//! Bind release-builder identities without reading keys or runtime configuration.

use std::env;
use std::error::Error;
use std::process::Command;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    for (name, length) in [
        ("AGENC_BUILD_COMMIT", 40),
        ("AGENC_BUILD_SOURCE_SHA256", 64),
        ("AGENC_BUILD_LOCK_SHA256", 64),
    ] {
        emit_identity(name, length)?;
    }
    let target = env::var("TARGET")?;
    if !target
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
    {
        return Err("invalid Cargo target identity".into());
    }
    println!("cargo:rustc-env=AGENC_BUILD_TARGET={target}");
    emit_compiler()
}

fn emit_identity(name: &str, length: usize) -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-env-changed={name}");
    match env::var(name) {
        Ok(value)
            if value.len() == length
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            println!("cargo:rustc-env={name}={value}");
        }
        Err(env::VarError::NotPresent) => println!("cargo:rustc-env={name}=unknown"),
        _ => return Err(format!("{name} must contain a lowercase hexadecimal identity").into()),
    }
    Ok(())
}

fn emit_compiler() -> Result<(), Box<dyn Error>> {
    let compiler = Command::new(env::var_os("RUSTC").ok_or("Cargo omitted RUSTC")?)
        .arg("--version")
        .output()?;
    if !compiler.status.success() || compiler.stdout.len() > 1024 {
        return Err("cannot identify the Rust compiler".into());
    }
    let version = std::str::from_utf8(&compiler.stdout)?.trim();
    if !version
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b" .()-".contains(&byte))
    {
        return Err("invalid Rust compiler version output".into());
    }
    println!("cargo:rustc-env=AGENC_BUILD_COMPILER={version}");
    Ok(())
}
