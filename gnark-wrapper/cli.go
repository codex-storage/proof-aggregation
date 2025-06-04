package main

import (
	_ "embed"
	"flag"
	"fmt"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/logger"
	"github.com/rs/zerolog/log"
	"os"
	"path/filepath"
)

func main() {
	circuitPath := flag.String("circuit", "", "circuit data directory")
	dataPath := flag.String("data", "", "data directory")
	proofSystem := flag.String("proof-system", "groth16", "proof system to benchmark")
	dummySetup := flag.Bool("dummy", true, "use dummy setup")
	proofFlag := flag.Bool("prove", false, "create a proof")
	verifyFlag := flag.Bool("verify", false, "verify a proof")
	compileFlag := flag.Bool("compile", false, "Compile and save the universal verifier circuit")
	contractFlag := flag.Bool("contract", true, "Generate solidity contract")
	flag.Parse()

	log := logger.Logger()

	circuitName := filepath.Base(*circuitPath)
	log.Info().Msgf("Running gnark plonky2 verifier for %s circuit with proof system %s", circuitName, *proofSystem)

	if *circuitPath == "" {
		log.Info().Msg("no circuitPath flag found, please specify one")
		flag.Usage()
		os.Exit(1)
	}

	if *dataPath == "" {
		log.Error().Msg("please specify a path to data dir (where the compiled gnark circuit data will be)")
		flag.Usage()
		os.Exit(1)
	}

	if *proofSystem == "plonk" {
		*dataPath = *dataPath + "/plonk"
	} else if *proofSystem == "groth16" {
		*dataPath = *dataPath + "/groth16"
	} else {
		panic("Please provide a valid proof system to benchmark, we only support plonk and groth16")
	}

	log.Debug().Msg("Circuit path: " + *circuitPath)
	log.Debug().Msg("Data path: " + *dataPath)

	if *compileFlag {
		CompileVerifierCircuit(*circuitPath, *dataPath, *contractFlag, *proofSystem, *dummySetup)
	}

	if *proofFlag {
		ProveCircuit(*circuitPath, *dataPath, *proofSystem, *dummySetup)
	}

	if *verifyFlag {
		if *dummySetup {
			fmt.Println("You're using dummy setup so we skip verification of proof")
			return
		} else {
			VerifyProof(*dataPath, *proofSystem)
		}
	}
}

func CompileVerifierCircuit(circuitPath string, dataPath string, contractFlag bool, proofSystem string, dummySetup bool) {
	log.Info().Msg("compiling verifier circuit")
	if proofSystem == "plonk" {
		r1cs, pk, vk, err := CompileVerifierCircuitPlonk(circuitPath, dummySetup)
		if err != nil {
			log.Error().Msg("failed to compile verifier circuit:" + err.Error())
			os.Exit(1)
		}
		err = SaveVerifierCircuit(dataPath, r1cs, pk, vk, dummySetup)
		if err != nil {
			log.Error().Msg("failed to save verifier circuit:" + err.Error())
			os.Exit(1)
		}

		if contractFlag {
			log.Info().Msg("generating solidity contract")
			err := ExportIFunctionVerifierSolidity(dataPath, vk)
			if err != nil {
				log.Error().Msg("failed to generate solidity contract:" + err.Error())
				os.Exit(1)
			}
		}
	} else if proofSystem == "groth16" {
		r1cs, pk, vk, err := CompileVerifierCircuitGroth16(circuitPath, dummySetup)
		if err != nil {
			log.Error().Msg("failed to compile verifier circuit:" + err.Error())
			os.Exit(1)
		}
		err = SaveVerifierCircuit(dataPath, r1cs, pk, vk, dummySetup)
		if err != nil {
			log.Error().Msg("failed to save verifier circuit:" + err.Error())
			os.Exit(1)
		}

		if contractFlag && !dummySetup {
			log.Info().Msg("generating solidity contract")
			err := ExportIFunctionVerifierSolidity(dataPath, vk)
			if err != nil {
				log.Error().Msg("failed to generate solidity contract:" + err.Error())
				os.Exit(1)
			}
		}
	} else {
		panic("Please provide a valid proof system to benchmark, we only support plonk and groth16")
	}

}

func ProveCircuit(circuitPath string, dataPath string, proofSystem string, isDummy bool) {
	log.Info().Msg("Generating the witness")
	witness, err := GetWitness(circuitPath)
	if err != nil {
		log.Err(err).Msg("failed to create the witness")
		os.Exit(1)
	}
	if proofSystem == "plonk" {
		log.Info().Msg("loading the plonk proving key, circuit data and verifying key")
		r1cs, pk, err := LoadPlonkProverData(dataPath)
		if err != nil {
			log.Err(err).Msg("failed to load the verifier circuit")
			os.Exit(1)
		}
		vk, err := LoadPlonkVerifierKey(dataPath)
		if err != nil {
			log.Err(err).Msg("failed to load the verifier key")
			os.Exit(1)
		}

		log.Info().Msg("Generating the proof")
		proof, err := ProvePlonk(dataPath, r1cs, pk, witness)
		if err != nil {
			log.Err(err).Msg("failed to create the proof")
			os.Exit(1)
		}

		log.Info().Msg("Sanity check: verifying proof")
		publicWitness, err := witness.Public()
		err = plonk.Verify(proof, vk, publicWitness)
		if err != nil {
			log.Err(err).Msg("failed sanity check to verify proof")
			os.Exit(1)
		}
		log.Info().Msg("Successfully passed sanity check - proof verification")
	} else if proofSystem == "groth16" {
		log.Info().Msg("loading the Groth16 proving key, circuit data and verifying key")
		r1cs, pk, err := LoadGroth16ProverData(dataPath)
		if err != nil {
			log.Err(err).Msg("failed to load the verifier circuit")
			os.Exit(1)
		}
		var vk groth16.VerifyingKey
		if !isDummy {
			vk, err = LoadGroth16VerifierKey(dataPath)
			if err != nil {
				log.Err(err).Msg("failed to load the verifier key")
				os.Exit(1)
			}
		}

		log.Info().Msg("Generating the proof")
		proof, err := ProveGroth16(dataPath, r1cs, pk, witness)
		if err != nil {
			log.Err(err).Msg("failed to create the proof")
			os.Exit(1)
		}

		if !isDummy {
			log.Info().Msg("Sanity check: verifying proof")
			publicWitness, err := witness.Public()
			err = groth16.Verify(proof, vk, publicWitness)
			if err != nil {
				log.Err(err).Msg("failed sanity check to verify proof")
				os.Exit(1)
			}
			log.Info().Msgf("number of public input: %s", publicWitness)
			log.Info().Msg("Successfully passed sanity check - proof verification")
		}
	} else {
		panic("Please provide a valid proof system to benchmark, we only support plonk and groth16")
	}
}

func VerifyProof(dataPath string, proofSystem string) {
	log.Info().Msg("loading the proof, verifying key and public inputs")

	publicWitness, err := LoadPublicWitness(dataPath)
	if err != nil {
		log.Err(err).Msg("failed to load the public witness")
		os.Exit(1)
	}

	if proofSystem == "plonk" {
		vk, err := LoadPlonkVerifierKey(dataPath)
		if err != nil {
			log.Err(err).Msg("failed to load the verifier key")
			os.Exit(1)
		}
		proof, err := LoadPlonkProof(dataPath)
		if err != nil {
			log.Err(err).Msg("failed to load the proof")
			os.Exit(1)
		}
		err = plonk.Verify(proof, vk, publicWitness)
		if err != nil {
			log.Err(err).Msg("failed to verify proof")
			os.Exit(1)
		}
		log.Info().Msg("Successfully verified proof")
	} else if proofSystem == "groth16" {
		vk, err := LoadGroth16VerifierKey(dataPath)
		if err != nil {
			log.Err(err).Msg("failed to load the verifier key")
			os.Exit(1)
		}
		proof, err := LoadGroth16Proof(dataPath)
		if err != nil {
			log.Err(err).Msg("failed to load the proof")
			os.Exit(1)
		}
		err = groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			log.Err(err).Msg("failed to verify proof")
			os.Exit(1)
		}
		log.Info().Msg("Successfully verified proof")
	} else {
		panic("Please provide a valid proof system to benchmark, we only support plonk and groth16")
	}
}
