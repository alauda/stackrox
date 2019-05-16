package common

import (
	"bytes"
	"compress/gzip"

	"github.com/mailru/easyjson"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/central/compliance/framework"
	"github.com/stackrox/rox/generated/internalapi/compliance"
	"github.com/stackrox/rox/pkg/docker/types"
)

func getDockerData(ret *compliance.ComplianceReturn) (*types.Data, error) {
	reader := bytes.NewReader(ret.GetDockerData().GetGzip())
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, err
	}

	var dockerData types.Data
	if err := easyjson.UnmarshalFromReader(gzReader, &dockerData); err != nil {
		return nil, err
	}
	return &dockerData, nil
}

// PerNodeCheckWithDockerData returns a check that runs on each node with access to docker data.
func PerNodeCheckWithDockerData(f func(ctx framework.ComplianceContext, data *types.Data)) framework.CheckFunc {
	return PerNodeCheck(func(ctx framework.ComplianceContext, ret *compliance.ComplianceReturn) {
		data, err := getDockerData(ret)
		if err != nil {
			framework.Abort(ctx, errors.Wrap(err, "could not process scraped data"))
		}
		f(ctx, data)
	})
}
