package main

import (
	"fmt"
	"os"

	"github.com/gogo/protobuf/proto"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/pkg/jsonutil"
)

// This script is used to parse a TLSChallengeResponse to validate that the correct CA was returned in ./update-testdata.sh
func main() {
	// Check if a command-line argument is provided
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <protobuf_data>")
		os.Exit(1)
	}

	// Extract the first command-line argument, the trust info passed from the command
	protobufData := os.Args[1]

	// Unmarshal the Protobuf data
	message := &v1.TLSChallengeResponse{}
	if err := jsonutil.JSONToProto(protobufData, message); err != nil {
		fmt.Printf("Error unmarshalling Protobuf data: %v\n", err)
		os.Exit(1)
	}

	trustInfo := &v1.TrustInfo{}
	if err := proto.Unmarshal(message.TrustInfoSerialized, trustInfo); err != nil {
		fmt.Printf("Error unmarshalling TrustInfo data: %v\n", err)
		os.Exit(1)
	}

	result, err := jsonutil.ProtoToJSON(trustInfo)
	if err != nil {
		fmt.Printf("Error unmarshalling Protobuf data: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%+v\n", result)
}
