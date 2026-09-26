//! Canonical OTS bytes for comparison with python-opentimestamps.
use calybris_core::ots::DetachedTimestamp;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let input = args.next().ok_or("input .ots required")?;
    let output = args.next().ok_or("output .ots required")?;
    let proof = DetachedTimestamp::parse(&std::fs::read(input)?)?;
    std::fs::write(output, proof.serialize())?;
    Ok(())
}
