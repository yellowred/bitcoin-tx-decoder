# Bitcoin Transaction Decoder

Learn about a Bitcoin transaction in your terminal.

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![Bitcoin](https://img.shields.io/badge/Bitcoin-000?style=for-the-badge&logo=bitcoin&logoColor=white)

<img width="1471" height="1058" alt="Image" src="https://github.com/user-attachments/assets/86efad8e-5e99-4835-9a01-fa8ba1ed7041" />

## Features

- **Visual transaction breakdown** showing metadata, inputs, outputs,
- **Input type detection** - identifies P2WPKH, P2WSH, P2TR (key path & script path), and legacy inputs
- **Ephemeral Anchor detection** - identifies P2A outputs for CPFP fee bumping
- **TimeLock** extraction


## Installation

### Install via cargo

```bash
cargo install --path .
```

## Usage

### Decode from hex string

```bash
btc-tx-decoder --tx <HEX_TRANSACTION>
```

### Decode from file

```bash
btc-tx-decoder --file transaction.txt
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details

## Acknowledgments

- [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) for the excellent Bitcoin library

