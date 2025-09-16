extern crate anyhow;
extern crate clap;
extern crate image;
extern crate log;
extern crate pdqhash;

use anyhow::Context;
use clap::Parser;
use image::io::Reader as ImageReader;
use log::{info, LevelFilter};
use pdqhash::generate_pdq;
use std::path::PathBuf;

#[cfg(feature = "snark")]
use {
    ark_bls12_381::Fr as BlsFr,
    ark_groth16::{Proof, VerifyingKey},
    ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
    ark_std::rand::rngs::StdRng,
    ark_std::rand::SeedableRng,
    pdqhash::{Bls12_381, PDQSnark},
};

/// Command-line interface for the PDQ Hash tool
#[derive(clap::Parser, Debug)]
#[clap(name = "pdqhash", version, about = "PDQ perceptual hashing tool with SNARK support", long_about = None)]
struct Cli {
    /// Enable debug logging
    #[clap(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    /// Subcommand to execute
    #[clap(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Generate a PDQ hash from an image
    Hash {
        /// Path to the input image file
        #[clap(short, long)]
        input: PathBuf,

        /// Output file (default: stdout)
        #[clap(short, long)]
        output: Option<PathBuf>,
    },

    /// Generate a SNARK proof for a PDQ hash (requires 'snark' feature)
    #[cfg(feature = "snark")]
    Prove {
        /// Path to the input image file
        #[clap(short, long)]
        input: PathBuf,

        /// Output file for the proof (default: proof.bin)
        #[clap(short, long, default_value = "proof.bin")]
        output: PathBuf,

        /// Output file for the public inputs (default: public_inputs.bin)
        #[clap(long, default_value = "public_inputs.bin")]
        public_inputs: PathBuf,

        /// Output file for the verifying key (default: verifying_key.bin)
        #[clap(long, default_value = "verifying_key.bin")]
        verifying_key: PathBuf,
    },

    /// Verify a SNARK proof for a PDQ hash (requires 'snark' feature)
    #[cfg(feature = "snark")]
    Verify {
        /// Path to the proof file
        #[clap(short, long)]
        proof: PathBuf,

        /// Path to the public inputs file
        #[clap(long)]
        public_inputs: PathBuf,

        /// Path to the verifying key file
        #[clap(long)]
        verifying_key: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Set up logging
    let log_level = match cli.debug {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp(None)
        .init();

    match cli.command {
        Commands::Hash { input, output } => {
            info!("Generating PDQ hash for {:?}", input);
            let img = ImageReader::open(&input)
                .with_context(|| format!("Failed to open image: {}", input.display()))?
                .decode()
                .with_context(|| format!("Failed to decode image: {}", input.display()))?;

            let (hash, quality) =
                generate_pdq(&img).with_context(|| "Failed to generate PDQ hash")?;

            let hash_hex = hex::encode(hash);
            if let Some(output_path) = output {
                std::fs::write(output_path, format!("{}\nquality: {}\n", hash_hex, quality))?;
            } else {
                println!("{}\nquality: {}", hash_hex, quality);
            }
        }
        #[cfg(feature = "snark")]
        Commands::Prove {
            input,
            output,
            public_inputs,
            verifying_key,
        } => {
            info!("Generating SNARK proof for {:?}", input);
            let img = ImageReader::open(&input)
                .with_context(|| format!("Failed to open image: {}", input.display()))?
                .decode()
                .with_context(|| format!("Failed to decode image: {}", input.display()))?;
            let (hash, _quality) =
                generate_pdq(&img).with_context(|| "Failed to generate PDQ hash")?;
            println!("Generating SNARK parameters...");
            let mut rng = StdRng::from_entropy();
            let snark = PDQSnark::setup(&mut rng)?;
            let image_data = std::fs::read(&input)?;
            println!("Generating proof...");
            let (proof, pub_inputs) = snark.create_proof(&image_data, hash, &mut rng)?;
            let mut proof_bytes = Vec::new();
            proof.serialize_compressed(&mut proof_bytes)?;
            std::fs::write(&output, proof_bytes)?;

            let mut public_bytes = Vec::new();
            pub_inputs.serialize_compressed(&mut public_bytes)?;
            std::fs::write(&public_inputs, public_bytes)?;

            let mut vk_bytes = Vec::new();
            snark.verifying_key.serialize_compressed(&mut vk_bytes)?;
            std::fs::write(&verifying_key, vk_bytes)?;

            println!("Proof, public inputs, and verifying key written.");
        }
        #[cfg(feature = "snark")]
        Commands::Verify {
            proof,
            public_inputs,
            verifying_key,
        } => {
            info!("Verifying SNARK proof");
            let proof_bytes = std::fs::read(&proof)?;
            let proof = Proof::<Bls12_381>::deserialize_compressed_unchecked(&*proof_bytes)?;

            let pub_inputs_bytes = std::fs::read(&public_inputs)?;
            let public_inputs_vec =
                Vec::<BlsFr>::deserialize_compressed_unchecked(&*pub_inputs_bytes)?;

            let vk_bytes = std::fs::read(&verifying_key)?;
            let verifying_key =
                VerifyingKey::<Bls12_381>::deserialize_compressed_unchecked(&*vk_bytes)?;

            let is_valid = PDQSnark::verify_with_key(&verifying_key, &proof, &public_inputs_vec)?;
            if is_valid {
                println!("✓ Proof is valid!");
            } else {
                println!("✗ Proof is invalid!");
            }
        }
    }
    Ok(())
}
