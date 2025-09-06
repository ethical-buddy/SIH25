use anyhow::Result;
use ed25519_dalek::{Keypair, Signature, Signer, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, KEYPAIR_LENGTH};
use rand::rngs::OsRng;
use crate::evidence::WipeEvidence;
use serde_json::to_vec;
use std::fs;

pub fn generate_keypair_to_file(path: &str) -> Result<()> {
    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    fs::write(path, bincode::serialize(&keypair)?)?;
    Ok(())
}

pub fn load_keypair_from_file(path: &str) -> Result<Keypair> {
    let bytes = fs::read(path)?;
    let kp: Keypair = bincode::deserialize(&bytes)?;
    Ok(kp)
}

pub fn sign_evidence(kp: &Keypair, ev: &WipeEvidence) -> Result<String> {
    let mut canonical = to_vec(ev)?; // we will refine to deterministic serialization later
    let sig: Signature = kp.sign(&canonical);
    Ok(base64::encode(sig.to_bytes()))
}

// oye ambar isko bs testing tk rkhna badme canonical json me try krege agr kaam krfya``
