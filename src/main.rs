use anyhow::Result;

use clap::{ArgGroup, Parser};
use zpki::{ZpkiType, save};
use zpki::{collect_san_args, ensure_root_material, generate_leaf_cert_and_key};

#[derive(Parser, Debug)]
#[command(
    group(ArgGroup::new("subject")
        .args(["san", "ip"])
        .required(true)
        .multiple(true))
)]
/// Generate leaf certificates signed by a root CA
struct Args {
    /// SAN to use
    #[arg(long, num_args = 1..)]
    san: Vec<String>,

    /// IP to use
    #[arg(long, num_args = 1..)]
    ip: Vec<String>,
}

/// Entry point - parses CLI args and generates leaf certificate with root CA
fn main() -> Result<()> {
    let args = Args::parse();
    let (subject, san_inputs) = collect_san_args(args.san, args.ip)?;

    let root_dir = std::env::current_dir()?;
    let leaf_dir = root_dir.join(subject);

    if leaf_dir.exists() {
        println!("Leaf directory already exists");
        return Ok(());
    }

    std::fs::create_dir_all(&leaf_dir)?;

    let (root_key, root_cert_pem) = ensure_root_material(&root_dir)?;
    let (leaf_key, leaf_cert) = generate_leaf_cert_and_key(san_inputs, &root_key, &root_cert_pem)?;

    save(&leaf_dir, leaf_key.serialize_pem(), ZpkiType::Key)?;
    save(&leaf_dir, leaf_cert.pem(), ZpkiType::Cert)?;

    println!(
        "Certificate generated successfully in {}",
        leaf_dir.display()
    );
    Ok(())
}
