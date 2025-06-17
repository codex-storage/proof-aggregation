# GNARK-Plonky2 Verifier CLI

This repository provides a Go-based CLI for compiling, proving, and verifying Plonky2-wrapped circuits using GNARK (either Plonk or Groth16). It automates:

- **Compilation** of the plonky2 verifier circuit (R1CS, PK, VK).
- **Proof generation** for compiled circuits.
- **Proof verification**.

---

## Prerequisites

- **Go 1.22+** installed.
---

## Installation

Clone this repository:

```bash
git clone https://github.com/codex-storage/proof-aggregation.git
cd proof-aggregation/gnark-wrapper
go mod tidy
chmod +x compile.sh prove.sh verify.sh test.sh
```

## Building the Verifier Binary
```bash
go build -o verifier .
```

## CLI Usage
The verifier binary has three modes:

`-compile`: Compiles circuit (outputs R1CS, PK, VK, Solidity contract).

`-prove`: Generates a proof for the compiled circuit.

`-verify`: Verifies an existing proof.

### Flags:
| Flag            | Description                             | Default            |
| --------------- | --------------------------------------- | ------------------ |
| `-circuit`      | Directory containing Plonky2 JSON files | `./testdata/dummy` |
| `-data`         | Output directory                        | `./gnark_output`   |
| `-proof-system` | `"plonk"` or `"groth16"`                | `"groth16"`        |
| `-dummy`        | Dummy setup (Groth16 only)              | `"false"`          |
| `-contract`     | Generate Solidity verifier              | `"true"`           |

## Workflow
1. Prepare your Plonky2 JSON folder
This folder `testdata/dummy` must contain:
- `verifier_only_circuit_data.json`
- `proof_with_public_inputs.json`
- `common_circuit_data.json`

2. **Create or edit your `params.sh`**
Define your defaults (circuit folder, output dir, proof system, dummy mode) in `params.sh`
```bash
export CIRCUIT_DIR="$PWD/testdata/dummy"     # path to Plonky2 JSON files
export DATA_DIR="$PWD/gnark_output"          # where to save gnark outputs
export PROOF_SYSTEM="groth16"                # "plonk" or "groth16"
export DUMMY="false"                         # dummy or real setup
```

3. **Run the full end-to-end using defaults in `params.sh`**
```bash
./run_gnark_cli.sh
```
If you don’t supply any of `--compile`, `--prove` or `--verify` flags, it will run all three compile → prove → verify in sequence.

4. **Run individual steps**
Append any combination of:
- `--compile`
- `--prove`
- `--verify`

```bash
# Compile only
./run_gnark_cli.sh --compile

# Prove and then verify
./run_gnark_cli.sh --prove --verify
```

5. **Use a custom params.sh location**
Pass -P or --params-file before any other flags:
```bash
./run_gnark_cli.sh \
  -P /path/to/your/params.sh \
  --compile --prove
```
