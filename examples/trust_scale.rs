//! Reproducible build/proof measurements; allocation is NOT process RSS.
use calybris_core::merkle::{leaf_hash, verify_consistency, verify_inclusion, MerkleTree};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("leaves,build_ms,root_us,inclusion_us,consistency_us,allocated_hash_bytes");
    for size in [100_000_u64, 1_000_000, 10_000_000] {
        let mut tree = MerkleTree::new();
        let start = Instant::now();
        for i in 0..size {
            tree.push(leaf_hash(&i.to_le_bytes()));
        }
        let build = start.elapsed().as_secs_f64() * 1000.0;
        let start = Instant::now();
        let head = tree.head(size)?;
        let root = start.elapsed().as_secs_f64() * 1e6;
        let index = size / 3;
        let start = Instant::now();
        let proof = tree.inclusion_proof(index, size)?;
        let inclusion = start.elapsed().as_secs_f64() * 1e6;
        verify_inclusion(&head, index, &leaf_hash(&index.to_le_bytes()), &proof)?;
        let old = tree.head(size / 2)?;
        let start = Instant::now();
        let proof = tree.consistency_proof(old.size, size)?;
        let consistency = start.elapsed().as_secs_f64() * 1e6;
        verify_consistency(&old, &head, &proof)?;
        println!(
            "{size},{build:.3},{root:.3},{inclusion:.3},{consistency:.3},{}",
            tree.allocated_hash_bytes()
        );
    }
    Ok(())
}
