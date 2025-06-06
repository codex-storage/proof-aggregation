package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark/backend/groth16"
	"io"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/logger"
)

func LoadPlonkVerifierKey(path string) (plonk.VerifyingKey, error) {
	log := logger.Logger()
	vkFile, err := os.Open(path + "/vk.bin")
	if err != nil {
		return nil, fmt.Errorf("failed to open vk file: %w", err)
	}
	vk := plonk.NewVerifyingKey(ecc.BN254)
	start := time.Now()
	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read vk file: %w", err)
	}
	vkFile.Close()
	elapsed := time.Since(start)
	log.Debug().Msg("Successfully loaded verifying key, time: " + elapsed.String())

	return vk, nil
}

func LoadGroth16VerifierKey(path string) (groth16.VerifyingKey, error) {
	log := logger.Logger()
	vkFile, err := os.Open(path + "/vk.bin")
	if err != nil {
		return nil, fmt.Errorf("failed to open vk file: %w", err)
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	start := time.Now()
	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read vk file: %w", err)
	}
	vkFile.Close()
	elapsed := time.Since(start)
	log.Debug().Msg("Successfully loaded verifying key, time: " + elapsed.String())

	return vk, nil
}

func LoadPublicWitness(dataPath string) (witness.Witness, error) {
	log := logger.Logger()
	witnessFile, err := os.Open(dataPath + "/public_witness.bin")
	if err != nil {
		return nil, fmt.Errorf("failed to open public witness file: %w", err)
	}
	publicWitness, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create public witness: %w", err)
	}
	publicWitness.ReadFrom(witnessFile)
	witnessFile.Close()
	log.Debug().Msg("Successfully loaded public witness")

	return publicWitness, nil
}

func LoadPlonkProof(dataPath string) (plonk.Proof, error) {
	log := logger.Logger()
	proofFile, err := os.Open(dataPath + "/proof.json")
	if err != nil {
		return nil, fmt.Errorf("failed to open proof file: %w", err)
	}
	proof := plonk.NewProof(ecc.BN254)
	jsonProof, err := io.ReadAll(proofFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read proof file: %w", err)
	}
	err = json.Unmarshal(jsonProof, proof)
	if err != nil {
		return nil, fmt.Errorf("failed to read proof file: %w", err)
	}
	proofFile.Close()
	log.Debug().Msg("Successfully loaded proof")

	return proof, nil
}

func LoadGroth16Proof(dataPath string) (groth16.Proof, error) {
	log := logger.Logger()
	proofFile, err := os.Open(dataPath + "/proof.json")
	if err != nil {
		return nil, fmt.Errorf("failed to open proof file: %w", err)
	}
	proof := groth16.NewProof(ecc.BN254)
	jsonProof, err := io.ReadAll(proofFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read proof file: %w", err)
	}
	err = json.Unmarshal(jsonProof, proof)
	if err != nil {
		return nil, fmt.Errorf("failed to read proof file: %w", err)
	}
	proofFile.Close()
	log.Debug().Msg("Successfully loaded proof")

	return proof, nil
}

type solidityExporter interface {
	ExportSolidity(io.Writer, ...solidity.ExportOption) error
}

func ExportIFunctionVerifierSolidity(path string, vk solidityExporter) error {
	log := logger.Logger()
	// Create a new buffer and export the VerifyingKey into it as a Solidity contract and
	// convert the buffer content to a string for further manipulation.
	buf := new(bytes.Buffer)
	err := vk.ExportSolidity(buf)
	if err != nil {
		log.Err(err).Msg("failed to export verifying key to solidity")
		return err
	}
	content := buf.String()

	contractFile, err := os.Create(path + "/Verifier.sol")
	if err != nil {
		return err
	}
	w := bufio.NewWriter(contractFile)
	// write the new content to the writer
	_, err = w.Write([]byte(content))
	if err != nil {
		return err
	}

	contractFile.Close()
	return err
}
