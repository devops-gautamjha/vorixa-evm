package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"vorixa-agent/config" // replace with your actual module name

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/shirou/gopsutil/v4/process"
)

type SystemdServiceStatus struct {
	Name       string  `json:"name"`
	Running    bool    `json:"running"`
	Uptime     string  `json:"uptime,omitempty"`
	MainPID    int32   `json:"main_pid"`
	CPUPercent float64 `json:"cpu_percent"`
	MemMB      float32 `json:"memory_mb"`
	Enabled    bool    `json:"enabled"`
}

func getServiceInfo(conn *dbus.Conn, name string) (*SystemdServiceStatus, error) {
	unitName := name + ".service"

	// Check if service is enabled
	stateProp, err := conn.GetUnitPropertyContext(context.Background(), unitName, "UnitFileState")
	if err != nil {
		return nil, fmt.Errorf("failed to get UnitFileState for %s: %w", unitName, err)
	}
	isEnabled := strings.Trim(stateProp.Value.String(), `"`) == "enabled"

	// Get all properties of the service unit
	props, err := conn.GetUnitTypePropertiesContext(context.Background(), unitName, "Service")
	if err != nil {
		return nil, err
	}
	var pid int32 = 0
	if val, ok := props["MainPID"]; ok {
		switch v := val.(type) {
		case uint32:
			pid = int32(v)
		case uint64:
			pid = int32(v)
		case int32:
			pid = v
		case int64:
			pid = int32(v)
		default:
			pid = 0
		}
	}

	propsa, errr := conn.GetUnitPropertiesContext(context.Background(), unitName)
	if errr != nil {
		return nil, err
	}

	subStatea, _ := propsa["SubState"].(string)

	running := strings.ToLower(subStatea) == "running"

	status := &SystemdServiceStatus{
		Name:    name,
		Running: running,
		MainPID: pid,
		Enabled: isEnabled,
	}

	// Gather process info if pid valid
	if pid > 0 {
		proc, err := process.NewProcess(pid)
		if err == nil {
			createTime, err := proc.CreateTime()
			if err == nil {
				startTime := time.Unix(0, createTime*int64(time.Millisecond))
				status.Uptime = time.Since(startTime).Round(time.Second).String()
			}

			cpu, _ := proc.CPUPercent()
			mem, _ := proc.MemoryInfo()
			status.CPUPercent = cpu
			status.MemMB = float32(mem.RSS) / (1024 * 1024)
		}
	}

	return status, nil
}

func SystemdMonitoringHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !cfg.SystemdMonitoring.Enabled {
			http.Error(w, "systemd monitoring disabled in config", http.StatusForbidden)
			return
		}

		conn, err := dbus.NewSystemdConnectionContext(context.Background())
		if err != nil {
			http.Error(w, "failed to connect to systemd", http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		var results []SystemdServiceStatus
		for _, svc := range cfg.SystemdMonitoring.SystemdNames {
			info, err := getServiceInfo(conn, svc)
			if err != nil {
				log.Printf("error getting service info for %s: %v", svc, err)
				continue
			}
			results = append(results, *info)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	}
}
