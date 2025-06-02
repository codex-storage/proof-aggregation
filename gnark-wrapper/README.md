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

2. Compile:
```bash
./compile.sh ./testdata/dummy ./gnark_output groth16 false
```
Produces ./gnark_output/groth16/r1cs.bin, pk.bin, vk.bin, and Verifier.sol.

3. Prove:
```bash
./prove.sh ./testdata/dummy ./gnark_output groth16 false
```
Produces ./gnark_output/groth16/proof.json and public_witness.bin.

4. Verify:
```bash
./verify.sh ./testdata/dummy ./gnark_output groth16 false
```
Checks proof.json + vk.bin + public_witness.bin.

5. (Optional) Full end-to-end
```bash
./test.sh ./testdata/dummy ./gnark_output groth16 false
```
Calls compile → prove → verify in sequence.
