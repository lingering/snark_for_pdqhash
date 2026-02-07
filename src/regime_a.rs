//! Regime A protocol implementation (single-shot masked threshold test).
//!
//! This module implements the algebraic protocol from the design note using a
//! small prime field and a multiplicative group modulo the same prime.
//! The proof object here is a **mock proof** used for executable testing and
//! benchmarking; it is not zero knowledge.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

const DEFAULT_PRIME: u64 = 2_305_843_009_213_693_951; // 2^61 - 1 (prime)
const DEFAULT_GENERATOR: u64 = 5;

#[derive(Clone, Debug)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        let seed = if seed == 0 { 0x9e3779b97f4a7c15 } else { seed };
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_field_nonzero(&mut self, p: u64) -> u64 {
        1 + (self.next_u64() % (p - 1))
    }

    fn next_field(&mut self, p: u64) -> u64 {
        self.next_u64() % p
    }
}

fn mod_add(a: u64, b: u64, p: u64) -> u64 {
    ((a as u128 + b as u128) % p as u128) as u64
}

fn mod_sub(a: u64, b: u64, p: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        ((a as u128 + p as u128 - b as u128) % p as u128) as u64
    }
}

fn mod_mul(a: u64, b: u64, p: u64) -> u64 {
    ((a as u128 * b as u128) % p as u128) as u64
}

fn hash64<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Public protocol parameters.
#[derive(Clone, Debug)]
pub struct RegimeAParams {
    pub p: u64,
    pub g: u64,
    pub ell: usize,
    pub b_chunks: usize,
    pub epsilon: usize,
}

impl RegimeAParams {
    pub fn new(ell: usize, b_chunks: usize, epsilon: usize) -> Self {
        assert!(ell > 0);
        assert!(b_chunks > 0);
        assert!(epsilon <= ell);
        Self {
            p: DEFAULT_PRIME,
            g: DEFAULT_GENERATOR,
            ell,
            b_chunks,
            epsilon,
        }
    }

    pub fn lambda(&self) -> usize {
        self.ell * self.b_chunks
    }
}

/// TTP output needed by clients and server.
#[derive(Clone, Debug)]
pub struct TtpSetup {
    pub params: RegimeAParams,
    pub gamma: Vec<u64>,
    pub r_masks: Vec<u64>,
    pub r_sum: u64,
    pub db: Vec<Vec<u8>>,
}

impl TtpSetup {
    pub fn setup(db: Vec<Vec<u8>>, params: RegimeAParams, seed: u64) -> Self {
        assert!(!db.is_empty());
        assert!(db.iter().all(|d| d.len() == params.lambda()));
        assert!(db
            .iter()
            .all(|d| d.iter().all(|bit| *bit == 0u8 || *bit == 1u8)));
        let mut rng = XorShift64::new(seed);

        let gamma = (0..db.len())
            .map(|_| rng.next_field_nonzero(params.p))
            .collect::<Vec<_>>();

        let r_masks = (0..params.b_chunks)
            .map(|_| rng.next_field(params.p))
            .collect::<Vec<_>>();

        let r_sum = r_masks
            .iter()
            .fold(0u64, |acc, r| mod_add(acc, *r, params.p));

        Self {
            params,
            gamma,
            r_masks,
            r_sum,
            db,
        }
    }

    fn chunk<'a>(&self, d: &'a [u8], b: usize) -> &'a [u8] {
        let start = b * self.params.ell;
        &d[start..start + self.params.ell]
    }

    fn hamming_chunk(&self, x: &[u8], y: &[u8]) -> usize {
        x.iter().zip(y.iter()).filter(|(a, b)| a != b).count()
    }

    fn z_poly(&self, distance: usize) -> u64 {
        let p = self.params.p;
        let ell = self.params.ell;
        let eps = self.params.epsilon;
        (eps..=ell).fold(1u64, |acc, t| {
            let term = mod_sub(distance as u64 % p, t as u64 % p, p);
            mod_mul(acc, term, p)
        })
    }

    fn s_for_chunk(&self, query: &[u8], chunk_idx: usize) -> u64 {
        let p = self.params.p;
        self.db.iter().enumerate().fold(0u64, |acc, (i, db_item)| {
            let d = self.hamming_chunk(query, self.chunk(db_item, chunk_idx));
            let z = self.z_poly(d);
            mod_add(acc, mod_mul(self.gamma[i], z, p), p)
        })
    }

    fn masked_exponent(&self, query: &[u8], chunk_idx: usize) -> u64 {
        mod_add(
            self.s_for_chunk(query, chunk_idx),
            self.r_masks[chunk_idx],
            self.params.p,
        )
    }
}

#[derive(Clone, Debug)]
pub struct MockProof {
    msgid: u64,
    transcript_hash: u64,
    witness_bits: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ClientSubmission {
    pub msgid: u64,
    pub root: u64,
    pub c_d: u64,
    pub res_total: u64,
    pub proof: MockProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerDecision {
    Yes,
    No,
}

/// Client logic from Regime A.
pub fn client_submit(setup: &TtpSetup, d: Vec<u8>, msgid: u64) -> ClientSubmission {
    assert_eq!(d.len(), setup.params.lambda());
    assert!(d.iter().all(|bit| *bit == 0 || *bit == 1));

    let c_d = hash64(&d);
    let root = hash64(&c_d);

    // Group element encoding (additive group model): g^x is represented by x mod p.
    let mut res_total = 0u64;
    for b in 0..setup.params.b_chunks {
        let chunk = setup.chunk(&d, b);
        let res_b = setup.masked_exponent(chunk, b);
        res_total = mod_add(res_total, res_b, setup.params.p);
    }

    let transcript_hash = hash64(&(msgid, root, c_d, res_total));
    let proof = MockProof {
        msgid,
        transcript_hash,
        witness_bits: d,
    };

    ClientSubmission {
        msgid,
        root,
        c_d,
        res_total,
        proof,
    }
}

/// Server verification and decision logic.
pub fn server_verify_and_decide(
    setup: &TtpSetup,
    submission: &ClientSubmission,
) -> Option<ServerDecision> {
    let proof = &submission.proof;

    if proof.msgid != submission.msgid {
        return None;
    }

    if !proof.witness_bits.iter().all(|b| *b == 0 || *b == 1) {
        return None;
    }

    let expected_cd = hash64(&proof.witness_bits);
    if expected_cd != submission.c_d {
        return None;
    }

    let expected_root = hash64(&submission.c_d);
    if expected_root != submission.root {
        return None;
    }

    let mut expected_res_total = 0u64;
    for b in 0..setup.params.b_chunks {
        let chunk = setup.chunk(&proof.witness_bits, b);
        let res_b = setup.masked_exponent(chunk, b);
        expected_res_total = mod_add(expected_res_total, res_b, setup.params.p);
    }

    if expected_res_total != submission.res_total {
        return None;
    }

    let expected_transcript = hash64(&(
        submission.msgid,
        submission.root,
        submission.c_d,
        submission.res_total,
    ));
    if expected_transcript != proof.transcript_hash {
        return None;
    }

    let res_prime_total = mod_sub(submission.res_total, setup.r_sum, setup.params.p);

    if res_prime_total != 0 {
        Some(ServerDecision::Yes)
    } else {
        Some(ServerDecision::No)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regime_a_yes_for_close_neighbor() {
        let params = RegimeAParams::new(8, 4, 3);
        let db = vec![vec![0; params.lambda()], vec![1; params.lambda()]];
        let setup = TtpSetup::setup(db, params.clone(), 7);

        let mut query = vec![0; params.lambda()];
        query[0] = 1;
        query[9] = 1;

        let submission = client_submit(&setup, query, 42);
        assert_eq!(
            server_verify_and_decide(&setup, &submission),
            Some(ServerDecision::Yes)
        );
    }

    #[test]
    fn regime_a_no_when_every_chunk_far() {
        let params = RegimeAParams::new(8, 4, 3);
        let db = vec![vec![0; params.lambda()]];
        let setup = TtpSetup::setup(db, params.clone(), 9);
        let query = vec![1; params.lambda()];

        let submission = client_submit(&setup, query, 11);
        assert_eq!(
            server_verify_and_decide(&setup, &submission),
            Some(ServerDecision::No)
        );
    }
}
