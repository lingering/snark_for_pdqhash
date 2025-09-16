//! Example of using the PDQ SNARK system to generate and verify proofs about PDQ hashes.
//!
//! This example demonstrates how to:
//! 1. Load an image
//! 2. Generate a PDQ hash
//! 3. Create a SNARK proof of knowledge of an image that hashes to a specific value
//! 4. Verify the proof
extern crate anyhow;
extern crate ark_std;
extern crate image;
extern crate log;
extern crate pdqhash;
use anyhow::Context;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use image::io::Reader as ImageReader;
use pdqhash::generate_pdq;
#[cfg(feature = "snark")]
use pdqhash::PDQSnark;
use std::env;
use std::fs;
use std::path::Path;

// This example requires the 'snark' feature to be enabled
#[cfg(not(feature = "snark"))]
fn main() {
    eprintln!("Error: This example requires the 'snark' feature to be enabled.");
    eprintln!("Run with: cargo run --example snark_example --features snark -- <path_to_image>");
    std::process::exit(1);
}

#[cfg(feature = "snark")]
fn main() -> anyhow::Result<()> {
    // Get image path from command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path_to_image>", args[0]);
        eprintln!("\nExample: {} examples/test.jpg", args[0]);
        std::process::exit(1);
    }

    let image_path = Path::new(&args[1]);
    if !image_path.exists() {
        anyhow::bail!("Image file not found: {}", image_path.display());
    }

    println!("Loading image: {}", image_path.display());

    // Load the image using the image crate
    let img = ImageReader::open(image_path)
        .with_context(|| format!("Failed to open image: {}", image_path.display()))?
        .decode()
        .with_context(|| format!("Failed to decode image: {}", image_path.display()))?;

    println!("Generating PDQ hash...");
    let (hash, quality) =
        generate_pdq(&img).ok_or_else(|| anyhow::anyhow!("Failed to generate PDQ hash"))?;

    println!("Image quality score: {:.2}", quality);
    println!("PDQ hash: {:02x?}", hash);

    println!("\nGenerating SNARK parameters (this may take a minute)...");
    let mut rng = StdRng::from_entropy();
    let snark = PDQSnark::setup(&mut rng).context("Failed to setup SNARK parameters")?;

    // Read the image file as bytes for the witness
    let image_data = fs::read(image_path)
        .with_context(|| format!("Failed to read image file: {}", image_path.display()))?;

    println!("Generating proof (this may take a minute)...");
    let (proof, public_inputs) = snark
        .create_proof(&image_data, hash, &mut rng)
        .context("Failed to generate proof")?;

    println!("Verifying proof...");
    let is_valid = snark
        .verify_proof(&proof, &public_inputs)
        .context("Failed to verify proof")?;

    if is_valid {
        println!("\n✓ Success! Proof is valid.");
        println!("The prover knows an image that hashes to the given PDQ hash.");
    } else {
        println!("\n✗ Proof verification failed!");
    }

    Ok(())
}
