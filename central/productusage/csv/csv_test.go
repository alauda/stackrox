package usagecsv

import (
	"net/url"
	"testing"
	"time"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/csv"
	"github.com/stackrox/rox/pkg/protoconv"
	"github.com/stretchr/testify/assert"
)

func TestGetTimeParam(t *testing.T) {
	t.Run("good from, bad to", func(t *testing.T) {
		from, _ := time.Parse(time.RFC3339Nano, "2023-07-24T10:13:21.702316Z")
		formValues := url.Values{
			"from": {from.Format(time.RFC3339Nano)},
			"to":   {"not a time"},
		}
		v, err := getTimeParameter(formValues, "from", zeroTime)
		assert.NoError(t, err)
		assert.Equal(t, from.Unix(), v.GetSeconds())
		assert.Equal(t, int32(from.Nanosecond()), v.GetNanos())
	})
	t.Run("bad from", func(t *testing.T) {
		formValues := url.Values{
			"from": {"not a time"},
		}
		_, err := getTimeParameter(formValues, "from", zeroTime)
		assert.Error(t, err)
		now := time.Now()
		to, err := getTimeParameter(formValues, "to", now)
		assert.NoError(t, err)
		assert.Equal(t, now.Unix(), to.GetSeconds())
	})
}

func TestSecuredUnitsConverter(t *testing.T) {
	converter := getSecuredUnitsConverter()
	first := converter(nil)
	assert.Equal(t, csv.Row{"0001-01-01T00:00:00Z", "0", "0"}, first)

	now := time.Now()
	su := &storage.SecuredUnits{
		Timestamp:   protoconv.ConvertTimeToTimestamp(now),
		NumNodes:    10,
		NumCpuUnits: 20,
	}
	second := converter(su)
	assert.Equal(t, csv.Row{now.UTC().Format(time.RFC3339), "10", "20"}, second)
	assert.Equal(t, 3, cap(second))

	assert.Equal(t, &first, &second, "converter should reuse the same array")
}
