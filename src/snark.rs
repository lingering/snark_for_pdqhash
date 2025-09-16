//! SNARK implementation for Facebook's PDQ perceptual hashing algorithm.
//!
//! This module exposes a Groth16 circuit that recomputes the PDQ hash from the
//! downsampled luminance buffer of an image. The prover supplies the image
//! bytes and proves that they correspond to the public PDQ hash without
//! revealing the image itself.

use crate::dct;
use crate::dwn_pdq::{compute_pdq_state, PDQ_HASH_LENGTH};
use anyhow::{anyhow, Context};
use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_ff::{Field, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::{
    alloc::AllocVar, bits::uint64::UInt64, boolean::Boolean, fields::fp::FpVar, prelude::*,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::{rand::CryptoRng, rand::RngCore, Zero};
use std::sync::OnceLock;

/// The PDQ downsampled buffer is always 64x64.
const BUFFER_EDGE: usize = 64;
/// Only the top-left 16x16 block of the DCT is used.
const DCT_EDGE: usize = 16;
const DCT_VALUE_COUNT: usize = DCT_EDGE * DCT_EDGE;
const PDQ_HASH_BITS: usize = PDQ_HASH_LENGTH * 8;

// Scaling factors used to keep arithmetic integral inside the circuit.
const LUMA_FIXED_SCALE: i64 = 1 << 12;
const DCT_FIXED_SCALE: i64 = 1 << 14;
const FINAL_SCALE: i128 =
    (LUMA_FIXED_SCALE as i128) * (DCT_FIXED_SCALE as i128) * (DCT_FIXED_SCALE as i128);
const CORRECTION_BITS: usize = 46;
const CORRECTION_TOLERANCE: u64 = 1u64 << CORRECTION_BITS;

/// Convert a signed 64-bit integer into the prime field.
fn field_from_i64<F: PrimeField>(value: i64) -> F {
    if value >= 0 {
        F::from(value as u64)
    } else {
        -F::from((-value) as u64)
    }
}

/// Lazily construct the scaled DCT matrix coefficients.
fn dct_coefficients() -> &'static [[i64; BUFFER_EDGE]; DCT_EDGE] {
    static TABLE: OnceLock<[[i64; BUFFER_EDGE]; DCT_EDGE]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [[0i64; BUFFER_EDGE]; DCT_EDGE];
        for row in 0..DCT_EDGE {
            for col in 0..BUFFER_EDGE {
                let coeff = f32::from_bits(dct::DCT_MATRIX[row][col]) as f64;
                table[row][col] = (coeff * (DCT_FIXED_SCALE as f64)).round() as i64;
            }
        }
        table
    })
}

/// Quantise the filtered 64x64 buffer into fixed-point integers.
fn quantize_buffer(buffer: &[[f32; BUFFER_EDGE]; BUFFER_EDGE]) -> Vec<i64> {
    let mut out = Vec::with_capacity(BUFFER_EDGE * BUFFER_EDGE);
    for row in buffer.iter() {
        for &value in row.iter() {
            let scaled = (value as f64 * LUMA_FIXED_SCALE as f64).round();
            out.push(scaled as i64);
        }
    }
    out
}

/// Compute the fixed-point DCT used inside the circuit.
fn compute_dct_fixed(pixels: &[i64]) -> Vec<i64> {
    let coeffs = dct_coefficients();

    let mut intermediate = vec![0i128; DCT_EDGE * BUFFER_EDGE];
    for row in 0..DCT_EDGE {
        for col in 0..BUFFER_EDGE {
            let mut acc = 0i128;
            for k in 0..BUFFER_EDGE {
                let coeff = coeffs[row][k] as i128;
                let pixel = pixels[k * BUFFER_EDGE + col] as i128;
                acc += coeff * pixel;
            }
            intermediate[row * BUFFER_EDGE + col] = acc;
        }
    }

    let mut output = vec![0i64; DCT_VALUE_COUNT];
    for row in 0..DCT_EDGE {
        for col in 0..DCT_EDGE {
            let mut acc = 0i128;
            for k in 0..BUFFER_EDGE {
                let coeff = coeffs[col][k] as i128;
                let value = intermediate[row * BUFFER_EDGE + k];
                acc += value * coeff;
            }
            output[row * DCT_EDGE + col] = acc as i64;
        }
    }
    output
}

/// Field-based Groth16 circuit verifying the PDQ hash computation.
#[derive(Clone, Debug)]
pub struct PDQHashCircuit<F: PrimeField> {
    /// Downsampled luminance buffer flattened in row-major order.
    pub pixels: Option<Vec<i64>>,
    /// Fixed-point median of the DCT coefficients.
    pub median: Option<i64>,
    /// Public PDQ hash bytes.
    pub hash: Option<[u8; PDQ_HASH_LENGTH]>,
    /// Positive parts of `dct - median` used to assert bit assignments.
    pub pos_diffs: Option<Vec<i64>>,
    /// Negative parts of `dct - median` used to assert bit assignments.
    pub neg_diffs: Option<Vec<i64>>,
    /// Field inverses for each coefficient difference (0 when the diff is zero).
    pub diff_inverses: Option<Vec<F>>,
    /// Scaled floating-point differences between DCT coefficients and the median.
    pub float_diffs: Option<Vec<i64>>,
    /// Positive rounding slack to reconcile integer and float differences.
    pub corr_pos: Option<Vec<i64>>,
    /// Negative rounding slack to reconcile integer and float differences.
    pub corr_neg: Option<Vec<i64>>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for PDQHashCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let hash_bytes = self.hash.unwrap_or([0u8; PDQ_HASH_LENGTH]);
        let pixel_values = self
            .pixels
            .unwrap_or_else(|| vec![0i64; BUFFER_EDGE * BUFFER_EDGE]);
        let median_value = self.median.unwrap_or(0);
        let pos_values = self
            .pos_diffs
            .unwrap_or_else(|| vec![0i64; DCT_VALUE_COUNT]);
        let neg_values = self
            .neg_diffs
            .unwrap_or_else(|| vec![0i64; DCT_VALUE_COUNT]);
        let inverse_values = self
            .diff_inverses
            .unwrap_or_else(|| vec![F::zero(); DCT_VALUE_COUNT]);
        let float_diff_values = self
            .float_diffs
            .unwrap_or_else(|| vec![0i64; DCT_VALUE_COUNT]);
        let corr_pos_values = self.corr_pos.unwrap_or_else(|| vec![0i64; DCT_VALUE_COUNT]);
        let corr_neg_values = self.corr_neg.unwrap_or_else(|| vec![0i64; DCT_VALUE_COUNT]);

        let mut hash_bits = Vec::with_capacity(DCT_VALUE_COUNT);
        for idx in 0..DCT_VALUE_COUNT {
            let byte = hash_bytes[PDQ_HASH_LENGTH - 1 - idx / 8];
            let bit_value = ((byte >> (idx % 8)) & 1) == 1;
            hash_bits.push(Boolean::new_input(cs.clone(), || Ok(bit_value))?);
        }

        let median_var = FpVar::new_witness(cs.clone(), || Ok(field_from_i64::<F>(median_value)))?;

        let mut pixel_vars = Vec::with_capacity(pixel_values.len());
        for value in pixel_values {
            pixel_vars.push(FpVar::new_witness(cs.clone(), || {
                Ok(field_from_i64::<F>(value))
            })?);
        }

        let coeffs = dct_coefficients();
        let mut intermediate = vec![FpVar::<F>::zero(); DCT_EDGE * BUFFER_EDGE];
        for row in 0..DCT_EDGE {
            for col in 0..BUFFER_EDGE {
                let mut acc = FpVar::<F>::zero();
                for k in 0..BUFFER_EDGE {
                    let coeff = field_from_i64::<F>(coeffs[row][k]);
                    let pixel = pixel_vars[k * BUFFER_EDGE + col].clone();
                    acc += pixel * coeff;
                }
                intermediate[row * BUFFER_EDGE + col] = acc;
            }
        }

        let mut dct_values = Vec::with_capacity(DCT_VALUE_COUNT);
        for row in 0..DCT_EDGE {
            for col in 0..DCT_EDGE {
                let mut acc = FpVar::<F>::zero();
                for k in 0..BUFFER_EDGE {
                    let coeff = field_from_i64::<F>(coeffs[col][k]);
                    let value = intermediate[row * BUFFER_EDGE + k].clone();
                    acc += value * coeff;
                }
                dct_values.push(acc);
            }
        }

        // Reconstruct public hash bits from the bytes.
        for (idx, dct) in dct_values.into_iter().enumerate() {
            let pos = FpVar::new_witness(cs.clone(), || Ok(field_from_i64::<F>(pos_values[idx])))?;
            let neg = FpVar::new_witness(cs.clone(), || Ok(field_from_i64::<F>(neg_values[idx])))?;
            let diff_inv = FpVar::new_witness(cs.clone(), || Ok(inverse_values[idx]))?;
            let float_diff = FpVar::new_witness(cs.clone(), || {
                Ok(field_from_i64::<F>(float_diff_values[idx]))
            })?;

            let corr_pos_u64 = UInt64::new_witness(cs.clone(), || Ok(corr_pos_values[idx] as u64))?;
            let corr_neg_u64 = UInt64::new_witness(cs.clone(), || Ok(corr_neg_values[idx] as u64))?;
            let corr_pos_bits = corr_pos_u64.to_bits_le();
            let corr_neg_bits = corr_neg_u64.to_bits_le();
            for bit in corr_pos_bits.iter().skip(CORRECTION_BITS) {
                bit.enforce_equal(&Boolean::FALSE)?;
            }
            for bit in corr_neg_bits.iter().skip(CORRECTION_BITS) {
                bit.enforce_equal(&Boolean::FALSE)?;
            }

            let mut corr_pos_fp = FpVar::<F>::zero();
            let mut coeff = F::one();
            for bit in &corr_pos_bits {
                let bit_fp: FpVar<F> = bit.clone().into();
                corr_pos_fp += bit_fp * coeff;
                coeff = coeff + coeff;
            }

            let mut corr_neg_fp = FpVar::<F>::zero();
            coeff = F::one();
            for bit in &corr_neg_bits {
                let bit_fp: FpVar<F> = bit.clone().into();
                corr_neg_fp += bit_fp * coeff;
                coeff = coeff + coeff;
            }

            let diff = dct.clone() - median_var.clone();
            (diff.clone() - float_diff.clone())
                .enforce_equal(&(corr_pos_fp.clone() - corr_neg_fp.clone()))?;
            (corr_pos_fp.clone() * corr_neg_fp.clone()).enforce_equal(&FpVar::zero())?;

            (pos.clone() - neg.clone()).enforce_equal(&float_diff)?;
            (pos.clone() * neg.clone()).enforce_equal(&FpVar::zero())?;

            let bit_fp: FpVar<F> = hash_bits[idx].clone().into();
            (bit_fp.clone() * neg.clone()).enforce_equal(&FpVar::zero())?;
            ((FpVar::one() - bit_fp.clone()) * pos.clone()).enforce_equal(&FpVar::zero())?;

            let diff_product = float_diff.clone() * diff_inv.clone();
            (bit_fp * (diff_product - FpVar::one())).enforce_equal(&FpVar::zero())?;
        }

        Ok(())
    }
}

/// SNARK proving system for PDQ hashes.
#[derive(Clone, Debug)]
pub struct PDQSnark {
    /// Groth16 proving key tailored to the PDQ circuit.
    pub proving_key: ProvingKey<Bls12_381>,
    /// Matching verifying key for the Groth16 PDQ circuit.
    pub verifying_key: VerifyingKey<Bls12_381>,
}

impl PDQSnark {
    /// Generate Groth16 parameters for the PDQ circuit.
    pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> anyhow::Result<Self> {
        let circuit = PDQHashCircuit::<BlsFr> {
            pixels: Some(vec![0; BUFFER_EDGE * BUFFER_EDGE]),
            median: Some(0),
            hash: Some([0u8; PDQ_HASH_LENGTH]),
            pos_diffs: Some(vec![0; DCT_VALUE_COUNT]),
            neg_diffs: Some(vec![0; DCT_VALUE_COUNT]),
            diff_inverses: Some(vec![BlsFr::zero(); DCT_VALUE_COUNT]),
            float_diffs: Some(vec![0; DCT_VALUE_COUNT]),
            corr_pos: Some(vec![0; DCT_VALUE_COUNT]),
            corr_neg: Some(vec![0; DCT_VALUE_COUNT]),
        };

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, rng)?;
        Ok(Self {
            proving_key: pk,
            verifying_key: vk,
        })
    }

    /// Create a Groth16 proof that the supplied image hashes to `target_hash`.
    pub fn create_proof<R: RngCore + CryptoRng>(
        &self,
        image_data: &[u8],
        target_hash: [u8; PDQ_HASH_LENGTH],
        rng: &mut R,
    ) -> anyhow::Result<(Proof<Bls12_381>, Vec<BlsFr>)> {
        let image = image::load_from_memory(image_data)
            .context("failed to decode image bytes for SNARK proof")?;
        let state = compute_pdq_state(&image);

        let quantised = quantize_buffer(&state.buffer64);
        let dct_values = compute_dct_fixed(&quantised);
        let median = (state.median as f64 * FINAL_SCALE as f64).round() as i64;
        let hash_bytes = state.hash;
        println!("hash_bytes: {:?}", hash_bytes);
        println!("target_hash: {:?}", target_hash);
        if hash_bytes != target_hash {
            return Err(anyhow!(
                "provided target hash does not match computed PDQ hash"
            ));
        }

        let mut pos = Vec::with_capacity(DCT_VALUE_COUNT);
        let mut neg = Vec::with_capacity(DCT_VALUE_COUNT);
        let mut inverses = Vec::with_capacity(DCT_VALUE_COUNT);
        let mut float_diffs = Vec::with_capacity(DCT_VALUE_COUNT);
        let mut corr_pos = Vec::with_capacity(DCT_VALUE_COUNT);
        let mut corr_neg = Vec::with_capacity(DCT_VALUE_COUNT);

        for (idx, &value) in dct_values.iter().enumerate() {
            let diff = value - median;
            let float_diff = state.dct16[idx] as f64 - state.median as f64;
            let float_scaled = (float_diff * FINAL_SCALE as f64).round() as i64;
            let delta = diff - float_scaled;

            let (pos_corr, neg_corr) = if delta >= 0 {
                (delta as u64, 0u64)
            } else {
                (0u64, (-delta) as u64)
            };

            if pos_corr > CORRECTION_TOLERANCE || neg_corr > CORRECTION_TOLERANCE {
                return Err(anyhow!("rounding difference exceeded tolerance"));
            }

            float_diffs.push(float_scaled);
            corr_pos.push(pos_corr as i64);
            corr_neg.push(neg_corr as i64);

            if float_scaled > 0 {
                pos.push(float_scaled);
                neg.push(0);
            } else {
                pos.push(0);
                neg.push(-float_scaled);
            }

            let diff_field = field_from_i64::<BlsFr>(float_scaled);
            let inverse = if diff_field.is_zero() {
                BlsFr::zero()
            } else {
                diff_field
                    .inverse()
                    .ok_or_else(|| anyhow!("failed to compute inverse for non-zero diff"))?
            };
            inverses.push(inverse);
        }

        let circuit = PDQHashCircuit::<BlsFr> {
            pixels: Some(quantised),
            median: Some(median),
            hash: Some(hash_bytes),
            pos_diffs: Some(pos),
            neg_diffs: Some(neg),
            diff_inverses: Some(inverses),
            float_diffs: Some(float_diffs),
            corr_pos: Some(corr_pos),
            corr_neg: Some(corr_neg),
        };

        let proof = Groth16::<Bls12_381>::prove(&self.proving_key, circuit, rng)?;
        let public_inputs = hash_bytes
            .iter()
            .rev()
            .flat_map(|byte| (0..8).map(move |bit| BlsFr::from(((byte >> bit) & 1) as u64)))
            .collect();

        Ok((proof, public_inputs))
    }

    /// Verify a Groth16 proof for the PDQ hash circuit.
    pub fn verify_proof(
        &self,
        proof: &Proof<Bls12_381>,
        public_inputs: &[BlsFr],
    ) -> anyhow::Result<bool> {
        Self::verify_with_key(&self.verifying_key, proof, public_inputs)
    }

    /// Verify a Groth16 proof given an explicit verifying key.
    pub fn verify_with_key(
        verifying_key: &VerifyingKey<Bls12_381>,
        proof: &Proof<Bls12_381>,
        public_inputs: &[BlsFr],
    ) -> anyhow::Result<bool> {
        if public_inputs.len() != PDQ_HASH_BITS {
            return Err(anyhow!(
                "expected {} public inputs but received {}",
                PDQ_HASH_BITS,
                public_inputs.len()
            ));
        }
        if verifying_key.gamma_abc_g1.len() != public_inputs.len() + 1 {
            return Err(anyhow!(
                "malformed verifying key: expected {} public inputs but verifier was configured for {}",
                verifying_key.gamma_abc_g1.len() - 1,
                public_inputs.len()
            ));
        }
        let pvk = Groth16::<Bls12_381>::process_vk(verifying_key)?;
        Ok(Groth16::<Bls12_381>::verify_with_processed_vk(
            &pvk,
            public_inputs,
            proof,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::SeedableRng;

    #[test]
    fn groth16_roundtrip() {
        let mut rng = ark_std::rand::rngs::StdRng::from_seed([42u8; 32]);
        let snark = PDQSnark::setup(&mut rng).unwrap();

        let image_bytes = include_bytes!("test_data/bridge-1-original.jpg");
        let image = image::load_from_memory(image_bytes).unwrap();
        let state = compute_pdq_state(&image);

        let (proof, public_inputs) = snark
            .create_proof(image_bytes, state.hash, &mut rng)
            .unwrap();
        assert!(snark.verify_proof(&proof, &public_inputs).unwrap());
    }
}
