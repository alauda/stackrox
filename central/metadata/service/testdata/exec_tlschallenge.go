package main

import (
	"context"
	"os"
	"path"

	"github.com/stackrox/rox/central/metadata/service"
	"github.com/stackrox/rox/central/tlsconfig"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/pkg/jsonutil"
	"github.com/stackrox/rox/pkg/mtls"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/rox/roxctl/common/environment"
)

func main() {
	// Check if a command-line argument is provided
	if len(os.Args) < 3 {
		environment.CLIEnvironment().Logger().ErrfLn("Usage: go run main.go <challenge_token> <path_to_test_dir>")
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
		environment.CLIEnvironment().Logger().ErrfLn("Failed executing TLSChallenge: %v", err)
		os.Exit(1)
	}

	result, err := jsonutil.ProtoToJSON(message)
	if err != nil {
		environment.CLIEnvironment().Logger().ErrfLn("Error unmarshalling Protobuf data: %v", err)
		os.Exit(1)
	}

	if _, err := environment.CLIEnvironment().InputOutput().Out().Write([]byte(result)); err != nil {
		environment.CLIEnvironment().Logger().ErrfLn("Error unmarshalling Protobuf data: %v", err)
		os.Exit(1)
	}
}
