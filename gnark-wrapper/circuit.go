package main

import (
	"fmt"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test/unsafekzg"
	"io"
	"os"
	"time"

	gl "github.com/codex-storage/gnark-plonky2-verifier/goldilocks"
	"github.com/codex-storage/gnark-plonky2-verifier/trusted_setup"
	"github.com/codex-storage/gnark-plonky2-verifier/types"
	"github.com/codex-storage/gnark-plonky2-verifier/variables"
	"github.com/codex-storage/gnark-plonky2-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	bn_kzg "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	gnark_kzg "github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/logger"
)

type Plonky2VerifierCircuit struct {
	// inputs to the circuit
	PublicInputs []gl.Variable                     `gnark:"PublicInput,public"`
	Proof        variables.Proof                   `gnark:"-"`
	VerifierData variables.VerifierOnlyCircuitData `gnark:"PublicInput,public"`

	// Circuit configuration - common data
	CommonCircuitData types.CommonCircuitData
}

func (c *Plonky2VerifierCircuit) Define(api frontend.API) error {
	// initialize the verifier chip
	verifierChip := verifier.NewVerifierChip(api, c.CommonCircuitData)
	// verify the plonky2 proof
	verifierChip.Verify(c.Proof, c.PublicInputs, c.VerifierData)

	return nil
}

func CompileVerifierCircuitPlonk(CircuitPath string, IsDummy bool) (constraint.ConstraintSystem, plonk.ProvingKey, plonk.VerifyingKey, error) {
	log := logger.Logger()
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(
		types.ReadVerifierOnlyCircuitData(CircuitPath + "/verifier_only_circuit_data.json"),
	)
	proofWithPis := variables.DeserializeProofWithPublicInputs(
		types.ReadProofWithPublicInputs(CircuitPath + "/proof_with_public_inputs.json"),
	)
	commonCircuitData := types.ReadCommonCircuitData(CircuitPath + "/common_circuit_data.json")

	circuit := Plonky2VerifierCircuit{
		PublicInputs:      proofWithPis.PublicInputs,
		Proof:             proofWithPis.Proof,
		VerifierData:      verifierOnlyCircuitData,
		CommonCircuitData: commonCircuitData,
	}
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to compile circuit: %w", err)
	}
	log.Info().Msg("Successfully compiled verifier circuit")

	log.Info().Msg("Running circuit setup - this will take some time")

	spr, ok := r1cs.(constraint.SparseR1CS)
	if !ok {
		panic("plonkProof: expected a constraint.SparseR1CS, got something else")
	}
	var (
		canonicalSrs gnark_kzg.SRS
		lagrangeSrs  gnark_kzg.SRS
	)
	if IsDummy {
		fmt.Println("Using dummy setup")

		canonicalSrs, lagrangeSrs, err = unsafekzg.NewSRS(spr)
		if err != nil {
			panic(fmt.Errorf("unsafekzg.NewSRS: %w", err))
		}
	} else {
		fmt.Println("Using real setup")

		fileName := CircuitPath + "srs_setup"
		if _, err := os.Stat(fileName); os.IsNotExist(err) {
			trusted_setup.DownloadAndSaveAztecIgnitionSrs(174, fileName)
		}
		fSRS, err := os.Open(fileName)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to open srs file: %w", err)
		}

		BnCanonicalSrs := bn_kzg.SRS{}
		_, err = canonicalSrs.ReadFrom(fSRS)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to read srs file: %w", err)
		}
		fSRS.Close()

		canonicalSrs = &BnCanonicalSrs
		BnLagrangeSrs := bn_kzg.SRS{}

		n := spr.GetNbCoefficients()
		lagG1, err := bn_kzg.ToLagrangeG1(BnCanonicalSrs.Pk.G1[:n])
		if err != nil {
			panic(fmt.Errorf("bn_kzg.ToLagrangeG1: %w", err))
		}
		BnLagrangeSrs.Pk.G1 = lagG1
		lagrangeSrs = &BnLagrangeSrs
	}
	log.Info().Msg("Successfully loaded SRS")

	log.Info().Msg("Running circuit setup")
	start := time.Now()
	pk, vk, err := plonk.Setup(r1cs, canonicalSrs, lagrangeSrs)
	if err != nil {
		return nil, nil, nil, err
	}
	elapsed := time.Since(start)
	log.Info().Msg("Successfully ran circuit setup, time: " + elapsed.String())

	return r1cs, pk, vk, nil
}

func CompileVerifierCircuitGroth16(CircuitPath string, IsDummy bool) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	log := logger.Logger()
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(
		types.ReadVerifierOnlyCircuitData(CircuitPath + "/verifier_only_circuit_data.json"),
	)
	proofWithPis := variables.DeserializeProofWithPublicInputs(
		types.ReadProofWithPublicInputs(CircuitPath + "/proof_with_public_inputs.json"),
	)
	commonCircuitData := types.ReadCommonCircuitData(CircuitPath + "/common_circuit_data.json")

	circuit := Plonky2VerifierCircuit{
		PublicInputs:      proofWithPis.PublicInputs,
		Proof:             proofWithPis.Proof,
		VerifierData:      verifierOnlyCircuitData,
		CommonCircuitData: commonCircuitData,
	}
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to compile circuit: %w", err)
	}
	log.Info().Msg("Successfully compiled verifier circuit")

	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	fmt.Println("Running circuit setup")
	start := time.Now()
	if IsDummy {
		fmt.Println("Using dummy setup")
		pk, err = groth16.DummySetup(r1cs)
	} else {
		fmt.Println("Using real setup")
		pk, vk, err = groth16.Setup(r1cs)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	elapsed := time.Since(start)
	log.Info().Msg("Successfully ran circuit setup, time: " + elapsed.String())

	return r1cs, pk, vk, nil
}

type rawKeyWriter interface {
	WriteRawTo(io.Writer) (int64, error)
}

// SaveVerifierCircuit will write out
//   - r1cs (via WriteTo)
//   - pk  (via WriteRawTo)
//   - vk  (via WriteRawTo)
//
// It works for both Plonk and Groth16 proving/verifying keys.
func SaveVerifierCircuit[PK, VK rawKeyWriter](
	path string,
	r1cs constraint.ConstraintSystem,
	pk PK,
	vk VK,
	isDummy bool,
) error {
	log := logger.Logger()

	// make sure directory exists
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", path, err)
	}

	// rics constraints
	log.Info().Msgf("Saving circuit constraints to %s/r1cs.bin", path)
	r1csF, err := os.Create(path + "/r1cs.bin")
	if err != nil {
		return fmt.Errorf("create r1cs.bin: %w", err)
	}
	start := time.Now()
	if _, err := r1cs.WriteTo(r1csF); err != nil {
		r1csF.Close()
		return fmt.Errorf("write r1cs: %w", err)
	}
	r1csF.Close()
	log.Debug().Msg("Successfully saved circuit constraints, time: " + time.Since(start).String())

	// proving key
	log.Info().Msgf("Saving proving key to %s/pk.bin", path)
	pkF, err := os.Create(path + "/pk.bin")
	if err != nil {
		return fmt.Errorf("create pk.bin: %w", err)
	}
	start = time.Now()
	if _, err := pk.WriteRawTo(pkF); err != nil {
		pkF.Close()
		return fmt.Errorf("write pk: %w", err)
	}
	pkF.Close()
	log.Debug().Msg("Successfully saved proving key, time: " + time.Since(start).String())

	// verifying key - only saved if not using dummy setup
	if !isDummy {
		log.Info().Msgf("Saving verifying key to %s/vk.bin", path)
		vkF, err := os.Create(path + "/vk.bin")
		if err != nil {
			return fmt.Errorf("create vk.bin: %w", err)
		}
		start = time.Now()
		_, err = vk.WriteRawTo(vkF)
		if err != nil {
			vkF.Close()
			return fmt.Errorf("write vk: %w", err)
		}
		vkF.Close()
		log.Debug().Msg("Successfully saved verifying key, time: " + time.Since(start).String())
	}
	return nil
}
