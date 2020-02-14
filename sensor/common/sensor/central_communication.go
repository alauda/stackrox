package sensor

import (
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/sensor/common"
	"github.com/stackrox/rox/sensor/common/config"
	"google.golang.org/grpc"
)

// CentralCommunication interface allows you to start and stop the consumption/production loops.
type CentralCommunication interface {
	Start(centralConn *grpc.ClientConn, centralReachable *concurrency.Flag, handler config.Handler)
	Stop(error)
	Stopped() concurrency.ReadOnlyErrorSignal
}

// NewCentralCommunication returns a new CentralCommunication.
func NewCentralCommunication(components ...common.SensorComponent) CentralCommunication {
	return &centralCommunicationImpl{
		receiver:   NewCentralReceiver(components...),
		sender:     NewCentralSender(components...),
		components: components,

		stopC:    concurrency.NewErrorSignal(),
		stoppedC: concurrency.NewErrorSignal(),
	}
}
