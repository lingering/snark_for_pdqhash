//! Demonstrates generating Groth16 PDQ proofs for bundled images.
//!
//! Run with:
//! ```bash
//! cargo run --example emma_snark --features snark
//! ```

#[cfg(not(feature = "snark"))]
fn main() {
    eprintln!("Error: enable the 'snark' feature to run this example.");
}

#[cfg(feature = "snark")]
fn main() -> anyhow::Result<()> {
    use anyhow::Context;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use image::DynamicImage;
    use pdqhash::{dwn_pdq::generate_pdq_full_size, PDQSnark};

    struct Sample {
        name: &'static str,
        bytes: &'static [u8],
    }

    let samples = [
        Sample {
            name: "original.jpeg",
            bytes: include_bytes!("../src/test_data/bridge-1-original.jpg"),
        },
        Sample {
            name: "flipx.jpeg",
            bytes: include_bytes!("../src/test_data/bridge-5-flipx.jpg"),
        },
    ];

    let mut rng = StdRng::from_seed([7u8; 32]);
    let snark = PDQSnark::setup(&mut rng).context("failed to setup Groth16 parameters")?;

    for sample in samples {
        let dyn_img = image::load_from_memory(sample.bytes)
            .with_context(|| format!("failed to decode {}", sample.name))?;
        let (hash, quality) = generate_pdq_full_size(&dyn_img);

        println!("\nImage: {}", sample.name);
        println!("Quality: {:.4}", quality);
        println!("Hash: {:02x?}", hash);

        let (proof, public_inputs) = snark
            .create_proof(sample.bytes, hash, &mut rng)
            .with_context(|| format!("failed to create proof for {}", sample.name))?;
        println!("Proof created {:?}", proof);
        let valid = snark
            .verify_proof(&proof, &public_inputs)
            .context("verification failure")?;
        println!("Proof valid: {}", valid);
    }
    Ok(())
}
