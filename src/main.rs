mod lib;

use bitcoin::Transaction;
use clap::Parser;
use colored::*;
use prettytable::{format, Cell, Row, Table};
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
    let tx = lib::decode_transaction(&tx_hex).unwrap_or_else(|e| {
        eprintln!("{} {}", "✗".red().bold(), e);
        std::process::exit(1);
    });

    display_transaction(&tx);
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
