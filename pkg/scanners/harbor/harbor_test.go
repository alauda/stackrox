package harbor

import (
	"testing"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/images/types"
	"github.com/stackrox/rox/pkg/images/utils"
	"github.com/stackrox/rox/pkg/registries/harbor"
	"github.com/stretchr/testify/require"
)

func TestHarbor(t *testing.T) {

	integration := &storage.ImageIntegration{
		IntegrationConfig: &storage.ImageIntegration_Harbor{
			Harbor: &storage.HarborConfig{
				Endpoint: "192-168-176-24-harbor.alauda.cn",
				Username: "admin",
				Password: "xxx",
				// Insecure: true,
			},
		},
	}

	_, creator := harbor.Creator()

	registry, err := creator(integration)
	require.NoError(t, err)

	scanner, err := newScanner(integration)
	require.NoError(t, err)

	var images = []string{
		"192-168-176-24-harbor.alauda.cn/public/alpine:3.16.2",
	}

	for _, i := range images {
		containerImage, err := utils.GenerateImageFromString(i)
		require.NoError(t, err)

		img := types.ToImage(containerImage)
		metadata, err := registry.Metadata(img)
		require.NoError(t, err)
		img.Metadata = metadata
		img.Id = utils.GetSHA(img)

		scan, err := scanner.GetScan(img)
		require.NoError(t, err)
		// t.Logf("scan: %+v", scan.GetComponents())

		require.NotEmpty(t, scan.GetComponents())
		for _, c := range scan.GetComponents() {
			for _, v := range c.Vulns {
				require.NotEmpty(t, v.Cve)
			}
		}
	}
}
