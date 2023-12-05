package main

import (
	"context"
	"fmt"
	"os"
	"path"

	"github.com/stackrox/rox/central/metadata/service"
	"github.com/stackrox/rox/central/tlsconfig"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/pkg/jsonutil"
	"github.com/stackrox/rox/pkg/mtls"
	"github.com/stackrox/rox/pkg/utils"
)

func main() {
	// Check if a command-line argument is provided
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <protobuf_data>") //nolint:forbidigo
		os.Exit(1)
	}

	challengeToken := os.Args[1]
	basePath := os.Args[2]

	utils.Should(os.Setenv(mtls.CAFileEnvName, path.Join(basePath, "central/ca.pem")))
	utils.Should(os.Setenv(tlsconfig.MTLSAdditionalCADirEnvName, path.Join(basePath, "additionalCAs/")))
	utils.Should(os.Setenv(mtls.CertFilePathEnvName, path.Join(basePath, "central/cert.pem")))
	utils.Should(os.Setenv(mtls.KeyFileEnvName, path.Join(basePath, "central/key.pem")))

	metadataService := service.New()
	message, err := metadataService.TLSChallenge(context.TODO(), &v1.TLSChallengeRequest{
		ChallengeToken: challengeToken,
	})
	if err != nil {
		fmt.Printf("Failed executing TLSChallenge: %v\n", err) //nolint:forbidigo
		os.Exit(1)
	}

	result, err := jsonutil.ProtoToJSON(message)
	if err != nil {
		fmt.Printf("Error unmarshalling Protobuf data: %v\n", err) //nolint:forbidigo
		os.Exit(1)
	}

	fmt.Printf("%+v\n", result) //nolint:forbidigo
}
