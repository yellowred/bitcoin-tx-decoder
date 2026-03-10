// Copyright (c) 2025 Oleg Kubrakov

use bitcoin::{Transaction, consensus::encode};
use clap::Parser;
use colored::*;
use prettytable::{Cell, Row, Table, format};
use std::fs;

#[derive(Parser, Debug)]
#[command(name = "Bitcoin Transaction Decoder")]
#[command(author, version, about = "Decode and visualize Bitcoin transactions beautifully", long_about = None)]
struct Args {
    /// Hex-encoded transaction string
    #[arg(short, long, value_name = "HEX", conflicts_with = "file")]
    tx: Option<String>,

    /// File containing hex-encoded transaction
    #[arg(short, long, value_name = "FILE", conflicts_with = "tx")]
    file: Option<String>,
}

fn main() {
    let args = Args::parse();

    // Get transaction hex from either argument or file
    let tx_hex = if let Some(hex_str) = args.tx {
        hex_str
    } else if let Some(file_path) = args.file {
        fs::read_to_string(&file_path)
            .unwrap_or_else(|_| {
                eprintln!("{} Failed to read file: {}", "✗".red().bold(), file_path);
                std::process::exit(1);
            })
            .trim()
            .to_string()
    } else {
        eprintln!(
            "{}",
            "Error: Please provide either --tx <HEX> or --file <FILE>"
                .red()
                .bold()
        );
        eprintln!("\nUsage examples:");
        eprintln!("  btc-tx-decoder --tx <hex-string>");
        eprintln!("  btc-tx-decoder --file transaction.txt");
        std::process::exit(1);
    };

    // Decode transaction
    let tx = decode_transaction(&tx_hex).unwrap_or_else(|e| {
        eprintln!("{} {}", "✗".red().bold(), e);
        std::process::exit(1);
    });

    display_transaction(&tx);
}

/// Decode a hex-encoded Bitcoin transaction
pub fn decode_transaction(hex: &str) -> Result<Transaction, String> {
    let tx_bytes = hex::decode(hex.trim()).map_err(|e| format!("Invalid hex string: {}", e))?;

    encode::deserialize(&tx_bytes).map_err(|e| format!("Failed to decode transaction: {}", e))
}

/// Calculate the byte length of a Bitcoin compact size (varint) encoding
fn compact_size_len(n: usize) -> usize {
    if n <= 0xfc {
        1
    } else if n <= 0xffff {
        3
    } else if n <= 0xffff_ffff {
        5
    } else {
        9
    }
}

/// Calculate the virtual size of a single input (including its witness data)
fn input_vsize(input: &bitcoin::TxIn) -> usize {
    // Non-witness (base) data:
    // previous_output: txid (32) + vout (4) = 36
    // script_sig: compact_size(len) + script bytes
    // sequence: 4
    let script_sig_len = input.script_sig.len();
    let base_size = 36 + compact_size_len(script_sig_len) + script_sig_len + 4;

    // Witness data (scaled at 1/4 weight)
    let witness_size = if !input.witness.is_empty() {
        let mut size = compact_size_len(input.witness.len()); // number of witness items
        for item in input.witness.iter() {
            size += compact_size_len(item.len()) + item.len();
        }
        size
    } else {
        0
    };

    let weight = base_size * 4 + witness_size;
    (weight + 3) / 4 // ceil(weight / 4)
}

/// Calculate the virtual size of a single output
fn output_vsize(output: &bitcoin::TxOut) -> usize {
    // Outputs are entirely non-witness data:
    // value: 8 bytes
    // script_pubkey: compact_size(len) + script bytes
    let script_len = output.script_pubkey.len();
    8 + compact_size_len(script_len) + script_len
}

fn decode_witness_item(witness: &[u8]) -> String {
    let len = witness.len();

    match len {
        0 => "Empty witness".to_string(),
        1..=75 => {
            // Likely a signature or public key
            if len == 33 || len == 65 {
                "Public Key".to_string()
            } else if len >= 70 && len <= 73 {
                "Signature (DER)".to_string()
            } else if len == 64 {
                "Signature (Schnorr)".to_string()
            } else {
                format!("Data ({} bytes)", len)
            }
        }
        _ => {
            // Could be a script
            if len > 100 {
                format!("Script or Data ({} bytes)", len)
            } else {
                format!("Data ({} bytes)", len)
            }
        }
    }
}

/// Check if an output is a Pay-to-Anchor (P2A) / Ephemeral Anchor output
/// P2A is OP_1 <0x4e73> (witness v1 with 2-byte program 0x4e73)
fn is_ephemeral_anchor(output: &bitcoin::TxOut) -> bool {
    let script_bytes = output.script_pubkey.as_bytes();
    // P2A: OP_1 (0x51) followed by push of 2 bytes (0x02) then 0x4e73
    script_bytes.len() == 4
        && script_bytes[0] == 0x51  // OP_1 (witness version 1)
        && script_bytes[1] == 0x02  // Push 2 bytes
        && script_bytes[2] == 0x4e
        && script_bytes[3] == 0x73
}

/// Detect the input type based on witness data
fn detect_input_type(input: &bitcoin::TxIn) -> String {
    // Check if it's a SegWit input by examining witness data
    if !input.witness.is_empty() {
        let witness_count = input.witness.len();

        // P2WPKH (Pay-to-Witness-Public-Key-Hash)
        // Witness stack: <signature> <pubkey>
        if witness_count == 2 {
            let pubkey_len = input.witness.nth(1).map(|w| w.len()).unwrap_or(0);
            if pubkey_len == 33 || pubkey_len == 65 {
                return "P2WPKH (Pay-to-Witness-Public-Key-Hash)".to_string();
            }
        }

        // P2WSH (Pay-to-Witness-Script-Hash)
        // Witness stack: <item1> <item2> ... <witness_script>
        // Last item is the actual script being satisfied
        if witness_count >= 2 {
            let last_item_len = input.witness.last().map(|w| w.len()).unwrap_or(0);
            // P2WSH witness scripts are typically larger
            if last_item_len > 33 {
                return "P2WSH (Pay-to-Witness-Script-Hash)".to_string();
            }
        }

        // P2TR (Pay-to-Taproot)
        // Key path spend: single 64-65 byte signature
        // Script path spend: multiple items with control block
        if witness_count == 1 {
            let sig_len = input.witness.nth(0).map(|w| w.len()).unwrap_or(0);
            if sig_len == 64 || sig_len == 65 {
                return "P2TR (Pay-to-Taproot) - Key Path Spend".to_string();
            }
        } else if witness_count >= 2 {
            // Check for control block (starts with 0xc0 or 0xc1)
            if let Some(last_item) = input.witness.last() {
                if !last_item.is_empty() && (last_item[0] == 0xc0 || last_item[0] == 0xc1) {
                    return "P2TR (Pay-to-Taproot) - Script Path Spend".to_string();
                }
            }
        }

        return "SegWit (Unknown type)".to_string();
    }

    // Legacy input types
    if !input.script_sig.is_empty() {
        let script_len = input.script_sig.len();

        // P2PKH typically has ~107 byte scriptSig
        if script_len > 100 && script_len < 150 {
            return "P2PKH (Pay-to-Public-Key-Hash) - Legacy".to_string();
        }

        // P2SH can vary widely
        if script_len > 0 {
            return "P2SH or Legacy".to_string();
        }
    }

    "Unknown".to_string()
}

/// Get the address type as a human-readable string
fn get_address_type(address: &bitcoin::Address) -> &'static str {
    use bitcoin::address::AddressType;

    match address.address_type() {
        Some(AddressType::P2pkh) => "P2PKH",
        Some(AddressType::P2sh) => "P2SH",
        Some(AddressType::P2wpkh) => "P2WPKH",
        Some(AddressType::P2wsh) => "P2WSH",
        Some(AddressType::P2tr) => "P2TR",
        Some(AddressType::P2a) => "P2A",
        _ => "Unknown",
    }
}

fn display_transaction(tx: &Transaction) {
    // Transaction Overview
    println!(
        "\n{} {}",
        "📋".bold(),
        "TRANSACTION OVERVIEW".green().bold()
    );
    println!("{}", "─".repeat(70).green());

    let mut overview = Table::new();
    overview.set_format(*format::consts::FORMAT_CLEAN);

    overview.add_row(Row::new(vec![
        Cell::new("Transaction ID (txid)").style_spec("Fb"),
        Cell::new(&tx.compute_txid().to_string()).style_spec("Fc"),
    ]));
    overview.add_row(Row::new(vec![
        Cell::new("Version").style_spec("Fb"),
        Cell::new(&format!("{}", tx.version.0)).style_spec("Fw"),
    ]));
    overview.add_row(Row::new(vec![
        Cell::new("Lock Time").style_spec("Fb"),
        Cell::new(&format!("{}", tx.lock_time)).style_spec("Fw"),
    ]));
    overview.add_row(Row::new(vec![
        Cell::new("Size").style_spec("Fb"),
        Cell::new(&format!("{} bytes", tx.total_size())).style_spec("Fw"),
    ]));
    overview.add_row(Row::new(vec![
        Cell::new("Virtual Size").style_spec("Fb"),
        Cell::new(&format!("{} vBytes", tx.vsize())).style_spec("Fw"),
    ]));
    overview.add_row(Row::new(vec![
        Cell::new("Weight").style_spec("Fb"),
        Cell::new(&format!("{} WU", tx.weight().to_wu())).style_spec("Fw"),
    ]));

    overview.printstd();

    // Inputs
    println!(
        "\n{} {} ({})",
        "📥".bold(),
        "INPUTS".blue().bold(),
        tx.input.len().to_string().yellow().bold()
    );
    println!("{}", "─".repeat(70).blue());

    for (idx, input) in tx.input.iter().enumerate() {
        println!(
            "\n{} {}",
            "Input".blue().bold(),
            format!("#{}", idx).yellow()
        );

        let mut input_table = Table::new();
        input_table.set_format(*format::consts::FORMAT_CLEAN);

        // Detect and display input type
        let input_type = detect_input_type(input);
        input_table.add_row(Row::new(vec![
            Cell::new("  Type").style_spec("Fb"),
            Cell::new(&input_type).style_spec("Fc"),
        ]));

        input_table.add_row(Row::new(vec![
            Cell::new("  Previous TX").style_spec("Fb"),
            Cell::new(&input.previous_output.txid.to_string()).style_spec("Fw"),
        ]));
        input_table.add_row(Row::new(vec![
            Cell::new("  Output Index").style_spec("Fb"),
            Cell::new(&format!("{}", input.previous_output.vout)).style_spec("Fw"),
        ]));
        input_table.add_row(Row::new(vec![
            Cell::new("  Script Length").style_spec("Fb"),
            Cell::new(&format!("{} bytes", input.script_sig.len())).style_spec("Fw"),
        ]));
        input_table.add_row(Row::new(vec![
            Cell::new("  Script Sig").style_spec("Fb"),
            Cell::new(&hex::encode(input.script_sig.as_bytes())).style_spec("Fd"),
        ]));
        input_table.add_row(Row::new(vec![
            Cell::new("  Sequence").style_spec("Fb"),
            Cell::new(&format!("{}", input.sequence,)).style_spec("Fw"),
        ]));

        if let Some(timelock) = input.sequence.to_relative_lock_time() {
            input_table.add_row(Row::new(vec![
                Cell::new("  Timelock").style_spec("Fb"),
                Cell::new(&format!("{:?}", timelock)).style_spec("Fw"),
            ]));
        }

        input_table.add_row(Row::new(vec![
            Cell::new("  Virtual Size").style_spec("Fb"),
            Cell::new(&format!("{} vBytes", input_vsize(input))).style_spec("Fw"),
        ]));

        // Witness data if present
        if !input.witness.is_empty() {
            input_table.add_row(Row::new(vec![
                Cell::new("  Witness Items").style_spec("Fb"),
                Cell::new(&format!("{}", input.witness.len())).style_spec("Fy"),
            ]));

            for (i, witness_item) in input.witness.iter().enumerate() {
                let decoded = decode_witness_item(witness_item);
                input_table.add_row(Row::new(vec![
                    Cell::new(&format!("  Witness [{}]", i)).style_spec("Fb"),
                    Cell::new(&format!(
                        "{}\n    Type: {}",
                        hex::encode(witness_item),
                        decoded
                    ))
                    .style_spec("Fy"),
                ]));
            }
        }

        input_table.printstd();
    }

    // Outputs
    println!(
        "\n{} {} ({})",
        "📤".bold(),
        "OUTPUTS".magenta().bold(),
        tx.output.len().to_string().yellow().bold()
    );
    println!("{}", "─".repeat(70).magenta());

    let total_output: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();

    for (idx, output) in tx.output.iter().enumerate() {
        println!(
            "\n{} {}",
            "Output".magenta().bold(),
            format!("#{}", idx).yellow()
        );

        let mut output_table = Table::new();
        output_table.set_format(*format::consts::FORMAT_CLEAN);

        let btc_value = output.value.to_sat() as f64 / 100_000_000.0;
        output_table.add_row(Row::new(vec![
            Cell::new("  Value").style_spec("Fb"),
            Cell::new(&format!(
                "{:.8} BTC ({} satoshis)",
                btc_value,
                output.value.to_sat()
            ))
            .style_spec("Fy"),
        ]));

        // Try to extract address from script
        if let Ok(address) =
            bitcoin::Address::from_script(&output.script_pubkey, bitcoin::Network::Bitcoin)
        {
            let addr_type = get_address_type(&address);
            output_table.add_row(Row::new(vec![
                Cell::new("  Address").style_spec("Fb"),
                Cell::new(&format!("{} ({})", address, addr_type)).style_spec("Fc"),
            ]));
        } else if let Ok(address) =
            bitcoin::Address::from_script(&output.script_pubkey, bitcoin::Network::Testnet)
        {
            let addr_type = get_address_type(&address);
            output_table.add_row(Row::new(vec![
                Cell::new("  Address (Testnet)").style_spec("Fb"),
                Cell::new(&format!("{} ({})", address, addr_type)).style_spec("Fc"),
            ]));
        }

        // Check if this is an ephemeral anchor (P2A)
        if is_ephemeral_anchor(output) {
            output_table.add_row(Row::new(vec![
                Cell::new("  Type").style_spec("Fb"),
                Cell::new("⚓ Ephemeral Anchor (P2A) - Pay-to-Anchor").style_spec("Fy"),
            ]));
            output_table.add_row(Row::new(vec![
                Cell::new("  Address").style_spec("Fb"),
                Cell::new("bc1pfeessrawgf").style_spec("Fc"),
            ]));
            output_table.add_row(Row::new(vec![
                Cell::new("  Purpose").style_spec("Fb"),
                Cell::new("Anyone-can-spend anchor for CPFP fee bumping").style_spec("Fd"),
            ]));
        }
        output_table.add_row(Row::new(vec![
            Cell::new("  Script Length").style_spec("Fb"),
            Cell::new(&format!("{} bytes", output.script_pubkey.len())).style_spec("Fw"),
        ]));
        output_table.add_row(Row::new(vec![
            Cell::new("  Script PubKey").style_spec("Fb"),
            Cell::new(&format!("{}", output.script_pubkey.to_asm_string())).style_spec("Fg"),
        ]));
        output_table.add_row(Row::new(vec![
            Cell::new("  Script Hex").style_spec("Fb"),
            Cell::new(&hex::encode(output.script_pubkey.as_bytes())).style_spec("Fg"),
        ]));
        output_table.add_row(Row::new(vec![
            Cell::new("  Virtual Size").style_spec("Fb"),
            Cell::new(&format!("{} vBytes", output_vsize(output))).style_spec("Fw"),
        ]));

        output_table.printstd();
    }

    // Summary
    println!("\n{} {}", "💰".bold(), "SUMMARY".yellow().bold());
    println!("{}", "─".repeat(70).yellow());

    let mut summary = Table::new();
    summary.set_format(*format::consts::FORMAT_CLEAN);

    let total_btc = total_output as f64 / 100_000_000.0;
    summary.add_row(Row::new(vec![
        Cell::new("Total Output Value").style_spec("Fb"),
        Cell::new(&format!("{:.8} BTC ({} satoshis)", total_btc, total_output)).style_spec("Fy"),
    ]));
    summary.add_row(Row::new(vec![
        Cell::new("Number of Inputs").style_spec("Fb"),
        Cell::new(&tx.input.len().to_string()).style_spec("Fw"),
    ]));
    summary.add_row(Row::new(vec![
        Cell::new("Number of Outputs").style_spec("Fb"),
        Cell::new(&tx.output.len().to_string()).style_spec("Fw"),
    ]));

    summary.printstd();

    println!("\n{}", "═".repeat(70).cyan().bold());
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    // P2WPKH segwit transaction with 1 input and 3 outputs
    const SEGWIT_TX_HEX: &str = "020000000001010eeb61beeddeaab8a7bb024efcac1fa3faecb7c96c4127782e6bc7cd59fc51490200000000fffffffd03afd701000000000017a914715a091837e1340c8f4d11c20a16a4c92cee9af187ce22000000000000225120a76dcc4ffe5f6120fb0e78332d02272de196d2bc75fbb2f31908ea68fc88208aef780800000000001600148db324a5c4bf820717091087769dee302809ccb202483045022100fea069372ab582b1edfa863c3affdf691064bd892a14173a1f3bc7285497f3140220283339f2abbd165bbc6b4b305db28b9a064f051c2b097f318c2fa507bf320bc3012103cc976f202ab9e2d0bbe3ed8e728aadd6042294f223ff665516c114733647b6ba00000000";

    // Coinbase segwit transaction with 1 input and 2 outputs
    const COINBASE_TX_HEX: &str = "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502e8030101ffffffff0200f2052a0100000016001496d5599e55dfb1d6a2adc94e4f7e3b0f6b3b6b100000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn test_compact_size_len() {
        assert_eq!(compact_size_len(0), 1);
        assert_eq!(compact_size_len(1), 1);
        assert_eq!(compact_size_len(252), 1);
        assert_eq!(compact_size_len(253), 3);
        assert_eq!(compact_size_len(0xffff), 3);
        assert_eq!(compact_size_len(0x10000), 5);
        assert_eq!(compact_size_len(0xffff_ffff), 5);
        assert_eq!(compact_size_len(0x1_0000_0000), 9);
    }

    #[test]
    fn test_input_vsize_segwit() {
        let tx = decode_transaction(SEGWIT_TX_HEX).unwrap();
        // P2WPKH input: 41 bytes base (36 + 1 + 0 + 4), witness ~107 bytes
        // Weight = 41*4 + 107 = 271, vsize = ceil(271/4) = 68
        assert_eq!(input_vsize(&tx.input[0]), 68);
    }

    #[test]
    fn test_input_vsize_coinbase() {
        let tx = decode_transaction(COINBASE_TX_HEX).unwrap();
        // Coinbase input: base = 36 + 1 + 5 + 4 = 46, witness = 1 + 1 + 32 = 34
        // Weight = 46*4 + 34 = 218, vsize = ceil(218/4) = 55
        assert_eq!(input_vsize(&tx.input[0]), 55);
    }

    #[test]
    fn test_output_vsize_p2sh() {
        let tx = decode_transaction(SEGWIT_TX_HEX).unwrap();
        // P2SH output: 8 + 1 + 23 = 32
        assert_eq!(output_vsize(&tx.output[0]), 32);
    }

    #[test]
    fn test_output_vsize_p2tr() {
        let tx = decode_transaction(SEGWIT_TX_HEX).unwrap();
        // P2TR output: 8 + 1 + 34 = 43
        assert_eq!(output_vsize(&tx.output[1]), 43);
    }

    #[test]
    fn test_output_vsize_p2wpkh() {
        let tx = decode_transaction(SEGWIT_TX_HEX).unwrap();
        // P2WPKH output: 8 + 1 + 22 = 31
        assert_eq!(output_vsize(&tx.output[2]), 31);
    }

    #[test]
    fn test_vsize_sum_plus_overhead_equals_tx_vsize() {
        let tx = decode_transaction(SEGWIT_TX_HEX).unwrap();

        let inputs_vsize: usize = tx.input.iter().map(|i| input_vsize(i)).sum();
        let outputs_vsize: usize = tx.output.iter().map(|o| output_vsize(o)).sum();

        // Transaction overhead:
        // base: version(4) + input_count(1) + output_count(1) + locktime(4) = 10
        // witness: marker(1) + flag(1) = 2
        // overhead weight = 10*4 + 2 = 42, overhead vsize = ceil(42/4) = 11
        let overhead_base = 4 + compact_size_len(tx.input.len()) + compact_size_len(tx.output.len()) + 4;
        let overhead_witness = 2; // segwit marker + flag
        let overhead_weight = overhead_base * 4 + overhead_witness;
        let overhead_vsize = (overhead_weight + 3) / 4;

        assert_eq!(inputs_vsize + outputs_vsize + overhead_vsize, tx.vsize());
    }
}
