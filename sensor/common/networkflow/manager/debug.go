package manager

import (
	"encoding/json"
	"net/http"

	"github.com/stackrox/rox/pkg/timestamp"
)

func (m *networkFlowManager) startDebugServer() *http.Server {
	handler := http.NewServeMux()
	handler.HandleFunc("/debug/connections", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data, err := json.Marshal(m.connectionsByHost)
		if err != nil {
			log.Errorf("marshalling error: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, err = w.Write(data)
		if err != nil {
			log.Errorf("data writing error: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Addr: "127.0.0.1:6067", Handler: handler}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Warnf("Closing debugging server 6067: %v", err)
		}
	}()
	return srv
}

type dbgHostConnections struct {
	Hostname              string
	Connections           map[string]*connStatus
	Endpoints             map[string]*connStatus
	LastKnownTimestamp    timestamp.MicroTS
	ConnectionsSequenceID int64
	CurrentSequenceID     int64
}

func (h *hostConnections) MarshalJSON() ([]byte, error) {
	dbg := dbgHostConnections{
		Hostname:              h.hostname,
		Connections:           make(map[string]*connStatus),
		Endpoints:             make(map[string]*connStatus),
		LastKnownTimestamp:    h.lastKnownTimestamp,
		ConnectionsSequenceID: h.connectionsSequenceID,
		CurrentSequenceID:     h.connectionsSequenceID,
	}
	for c, status := range h.connections {
		dbg.Connections[c.String()] = status
	}
	for ce, status := range h.endpoints {
		dbg.Endpoints[ce.String()] = status
	}
	return json.Marshal(dbg)
}

func (cs *connStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"used":        cs.used,
		"lastSeen":    cs.lastSeen,
		"rotten":      cs.rotten,
		"firstSeen":   cs.firstSeen,
		"usedProcess": cs.usedProcess,
	})
}
