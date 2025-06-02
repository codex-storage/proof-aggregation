package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"

	"os"
	"time"

	gnark_verifier_types "github.com/codex-storage/gnark-plonky2-verifier/types"
	"github.com/codex-storage/gnark-plonky2-verifier/variables"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/logger"
)

func loadR1CS(path string) (constraint.ConstraintSystem, error) {
	log := logger.Logger()
	r1csFile, err := os.Open(path + "/r1cs.bin")
	if err != nil {
		return nil, fmt.Errorf("failed to open r1cs file: %w", err)
	}
	r1cs := plonk.NewCS(ecc.BN254)
	start := time.Now()
	r1csReader := bufio.NewReader(r1csFile)
	_, err = r1cs.ReadFrom(r1csReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read r1cs file: %w", err)
	}
	r1csFile.Close()
	elapsed := time.Since(start)
	log.Debug().Msg("Successfully loaded constraint system, time: " + elapsed.String())
	return r1cs, nil
}

func LoadPlonkProverData(path string) (constraint.ConstraintSystem, plonk.ProvingKey, error) {
	log := logger.Logger()

	r1cs, err := loadR1CS(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load r1cs file: %w", err)
	}

	pkFile, err := os.Open(path + "/pk.bin")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open pk file: %w", err)
	}
	pk := plonk.NewProvingKey(ecc.BN254)
	start := time.Now()
	pkReader := bufio.NewReader(pkFile)
	_, err = pk.ReadFrom(pkReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read pk file: %w", err)
	}
	pkFile.Close()
	elapsed := time.Since(start)
	log.Debug().Msg("Successfully loaded proving key, time: " + elapsed.String())

	return r1cs, pk, nil
}

func LoadGroth16ProverData(path string) (constraint.ConstraintSystem, groth16.ProvingKey, error) {
	log := logger.Logger()

	r1cs, err := loadR1CS(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load r1cs file: %w", err)
	}

	pkFile, err := os.Open(path + "/pk.bin")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open pk file: %w", err)
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	start := time.Now()
	pkReader := bufio.NewReader(pkFile)
	_, err = pk.ReadFrom(pkReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read pk file: %w", err)
	}
	pkFile.Close()
	elapsed := time.Since(start)
	log.Debug().Msg("Successfully loaded proving key, time: " + elapsed.String())

	return r1cs, pk, nil
}

func GetWitness(circuitPath string) (witness.Witness, error) {
	log := logger.Logger()

	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(
		gnark_verifier_types.ReadVerifierOnlyCircuitData(circuitPath + "/verifier_only_circuit_data.json"),
	)
	proofWithPis := gnark_verifier_types.ReadProofWithPublicInputs(circuitPath + "/proof_with_public_inputs.json")
	proofWithPisVariable := variables.DeserializeProofWithPublicInputs(proofWithPis)

	// Circuit assignment
	assignment := &Plonky2VerifierCircuit{
		Proof:        proofWithPisVariable.Proof,
		PublicInputs: proofWithPisVariable.PublicInputs,
		VerifierData: verifierOnlyCircuitData,
	}

	log.Debug().Msg("Generating witness")
	start := time.Now()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to generate witness: %w", err)
	}
	elapsed := time.Since(start)
	log.Debug().Msg("Successfully generated witness, time: " + elapsed.String())

	return witness, nil
}

func ProvePlonk(dataPath string, r1cs constraint.ConstraintSystem, pk plonk.ProvingKey, witness witness.Witness) (plonk.Proof, error) {
	log := logger.Logger()

	log.Debug().Msg("Creating proof")
	start := time.Now()
	proof, err := plonk.Prove(r1cs, pk, witness)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof: %w", err)
	}
	elapsed := time.Since(start)
	log.Info().Msg("Successfully created proof, time: " + elapsed.String())

	// export proof
	err = ExportPlonkProof(dataPath, proof)
	if err != nil {
		return nil, err
	}
	// export witness
	publicWitness, err := witness.Public()
	err = ExportWitness(dataPath, publicWitness)
	if err != nil {
		return nil, err
	}

	return proof, nil
}

func ProveGroth16(dataPath string, r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, witness witness.Witness) (groth16.Proof, error) {
	log := logger.Logger()

	log.Debug().Msg("Creating proof")
	start := time.Now()
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof: %w", err)
	}
	elapsed := time.Since(start)
	log.Info().Msg("Successfully created proof, time: " + elapsed.String())

	// export proof
	err = ExportGroth16Proof(dataPath, proof)
	if err != nil {
		return nil, err
	}
	// export witness
	publicWitness, err := witness.Public()
	err = ExportWitness(dataPath, publicWitness)
	if err != nil {
		return nil, err
	}

	return proof, nil
}

func ExportWitness(circuitPath string, witness witness.Witness) error {
	log := logger.Logger()

	publicWitness, err := witness.Public()
	if err != nil {
		return fmt.Errorf("failed to get public witness: %w", err)
	}

	log.Info().Msg("Saving public witness to public_witness.bin")
	witnessFile, err := os.Create(circuitPath + "/public_witness.bin")
	if err != nil {
		return fmt.Errorf("failed to create public witness file: %w", err)
	}
	_, err = publicWitness.WriteTo(witnessFile)
	if err != nil {
		return fmt.Errorf("failed to write public witness file: %w", err)
	}
	witnessFile.Close()
	log.Info().Msg("Successfully saved public witness")

	return nil
}

func ExportPlonkProof(circuitPath string, proof plonk.Proof) error {
	log := logger.Logger()

	_proof := proof.(*plonk_bn254.Proof)
	log.Info().Msg("Saving proof to proof.json")
	jsonProof, err := json.Marshal(_proof.MarshalSolidity())
	if err != nil {
		return fmt.Errorf("failed to marshal proof: %w", err)
	}
	proofFile, err := os.Create(circuitPath + "/proof.json")
	if err != nil {
		return fmt.Errorf("failed to create proof file: %w", err)
	}
	_, err = proofFile.Write(jsonProof)
	if err != nil {
		return fmt.Errorf("failed to write proof file: %w", err)
	}
	proofFile.Close()
	log.Info().Msg("Successfully saved proof")

	return nil
}

func ExportGroth16Proof(circuitPath string, proof groth16.Proof) error {
	log := logger.Logger()

	_proof := proof.(*groth16_bn254.Proof)
	log.Info().Msg("Saving proof to proof.json")
	jsonProof, err := json.Marshal(_proof)
	if err != nil {
		return fmt.Errorf("failed to marshal proof: %w", err)
	}
	proofFile, err := os.Create(circuitPath + "/proof.json")
	if err != nil {
		return fmt.Errorf("failed to create proof file: %w", err)
	}
	_, err = proofFile.Write(jsonProof)
	if err != nil {
		return fmt.Errorf("failed to write proof file: %w", err)
	}
	proofFile.Close()
	log.Info().Msg("Successfully saved proof")

	return nil
}
