use bitcoin::consensus::encode;
use bitcoin::Transaction;

/// Decode a hex-encoded Bitcoin transaction
pub fn decode_transaction(hex: &str) -> Result<Transaction, String> {
    let tx_bytes = hex::decode(hex.trim()).map_err(|e| format!("Invalid hex string: {}", e))?;

    encode::deserialize(&tx_bytes).map_err(|e| format!("Failed to decode transaction: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY_TX: &str = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000006b48304502210085e06b2d9e8cd4f2e88e60f5d4a69ff8e28fad7e8aecb8ab5c4ab34e3c42f044022028de87e6bb9dab5c6b8a88e4c8ef11b3d7d35a36e38ec4ba41c15d5b6e8713580121035ddc8e7f9e1e8f6b7b5f1b8c0b3e1e5d9e9f8b0b1b1b1b1b1b1b1b1b1b1b1b1bffffffff0200e1f505000000001976a914ab68025513c3dbd2f7b92a94e0581f5d50f654e788acd0ef8100000000001976a9148d1c5f69c46a73328b5f23f82a2de5e6b50e1e7588ac00000000";

    #[test]
    fn test_decode_valid_transaction() {
        let result = decode_transaction(LEGACY_TX);
        assert!(result.is_ok());

        let tx = result.unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.version.0, 1);
    }

    #[test]
    fn test_decode_invalid_hex() {
        let result = decode_transaction("not_valid_hex");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid hex string"));
    }

    #[test]
    fn test_decode_invalid_transaction() {
        let result = decode_transaction("deadbeef");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to decode"));
    }

    #[test]
    fn test_transaction_properties() {
        let tx = decode_transaction(LEGACY_TX).unwrap();

        // Check version
        assert_eq!(tx.version.0, 1);

        // Check lock time
        assert_eq!(tx.lock_time.to_consensus_u32(), 0);

        // Check inputs
        assert_eq!(tx.input.len(), 1);
        let input = &tx.input[0];
        assert_eq!(input.previous_output.vout, 0);
        assert_eq!(input.sequence.0, 0xffffffff);

        // Check outputs
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value.to_sat(), 100000000);
        assert_eq!(tx.output[1].value.to_sat(), 25833200);
    }
}
