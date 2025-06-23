package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"

	"vorixa-agent/config"
	"vorixa-agent/internal/metrics"
	"vorixa-agent/internal/wembed" // updated from `embed` to `webembed` to avoid name conflict
)

// CombinedMetrics represents system metrics structure
type CombinedMetrics struct {
	SystemInfo        *metrics.SystemInformation            `json:"system_info"`
	CPUInfo           *metrics.CPUInformation               `json:"cpu_info"`
	MemoryInfo        *metrics.MemoryInformation            `json:"memory_info"`
	SwapInfo          *metrics.SwapInformation              `json:"swap_info"`
	LoadInfo          *metrics.LoadInformation              `json:"load_info"`
	DiskInfo          []metrics.DiskUsageInformation        `json:"disk_info"`
	FileChecksum      *metrics.FileChecksumInformation      `json:"file_checksum"`
	NetworkInterfaces []metrics.NetworkInterfaceInformation `json:"network_interfaces"`
	NetworkStats      []metrics.NetworkStatsInformation     `json:"network_stats"`
}

// systemMetricsHandler serves system-level metrics
func systemMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	systemInfo, err := metrics.GetSystemInfo()
	if err != nil {
		http.Error(w, "Failed to get system info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cpuInfo, err := metrics.GetCPUInfo()
	if err != nil {
		http.Error(w, "Failed to get CPU info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	memInfo, err := metrics.GetMemoryInfo()
	if err != nil {
		http.Error(w, "Failed to get memory info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	swapInfo, err := metrics.GetSwapInfo()
	if err != nil {
		http.Error(w, "Failed to get swap info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	loadInfo, err := metrics.GetLoadAverage()
	if err != nil {
		http.Error(w, "Failed to get load info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	diskInfo, err := metrics.GetDiskUsage()
	if err != nil {
		http.Error(w, "Failed to get disk usage: "+err.Error(), http.StatusInternalServerError)
		return
	}
	checksum, err := metrics.GetFileChecksum("/etc/passwd")
	if err != nil {
		http.Error(w, "Failed to get file checksum: "+err.Error(), http.StatusInternalServerError)
		return
	}
	interfaces, err := metrics.GetNetworkInterfaces()
	if err != nil {
		http.Error(w, "Failed to get network interfaces: "+err.Error(), http.StatusInternalServerError)
		return
	}
	netStats, err := metrics.GetNetworkStats()
	if err != nil {
		http.Error(w, "Failed to get network stats: "+err.Error(), http.StatusInternalServerError)
		return
	}

	result := CombinedMetrics{
		SystemInfo:        systemInfo,
		CPUInfo:           cpuInfo,
		MemoryInfo:        memInfo,
		SwapInfo:          swapInfo,
		LoadInfo:          loadInfo,
		DiskInfo:          diskInfo,
		FileChecksum:      checksum,
		NetworkInterfaces: interfaces,
		NetworkStats:      netStats,
	}

	json.NewEncoder(w).Encode(result)
}

func main() {
	// Parse config path
	configPath := flag.String("config", "config.yaml", "Path to the config file")
	flag.Parse()

	// Load config
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	mux := http.NewServeMux()

	// Core system metrics
	mux.HandleFunc("/system_metrics", systemMetricsHandler)

	// Optional: systemd monitoring
	if cfg.SystemdMonitoring.Enabled {
		mux.HandleFunc("/systemd_monitoring", metrics.SystemdMonitoringHandler(cfg))
	}

	// Optional: EVM monitoring
	if cfg.EVMMetrics.Enabled {
		metrics.RegisterRoutes(mux, cfg)
	}

	// Serve embedded frontend (Vue SPA)
	mux.Handle("/", wembed.SPAHandler())

	// Start server
	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	log.Printf("🚀 Serving on http://localhost%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
