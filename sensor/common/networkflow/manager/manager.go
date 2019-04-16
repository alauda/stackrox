package manager

import (
	"github.com/stackrox/rox/generated/internalapi/central"
	"github.com/stackrox/rox/generated/internalapi/sensor"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/timestamp"
)

var (
	log = logging.LoggerForModule()
)

// Manager processes network connections coming in from collector, enriches them and sends them to Central
type Manager interface {
	Start()
	Stop()
	FlowUpdates() <-chan *central.NetworkFlowUpdate
	UnregisterCollector(hostname string, sequenceID int64)
	RegisterCollector(hostname string) (HostNetworkInfo, int64)
}

// HostNetworkInfo processes network connections from a single host aka collector.
type HostNetworkInfo interface {
	Process(networkInfo *sensor.NetworkConnectionInfo, nowTimestamp timestamp.MicroTS, sequenceID int64) error
}
