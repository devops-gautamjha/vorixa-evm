package metrics

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"crypto/sha256"
	"io"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gopsunet "github.com/shirou/gopsutil/v4/net"
)

type SystemInformation struct {
	OperatingSystem    string  `json:"operating_system"`
	Platform           string  `json:"platform"`
	PlatformVersion    string  `json:"platform_version"`
	KernelVersion      string  `json:"kernel_version"`
	Architecture       string  `json:"arch"`
	Hostname           string  `json:"hostname"`
	SystemDescription  string  `json:"system_description"`
	SystemLocalTime    string  `json:"system_local_time"`
	SystemUptime       string  `json:"system_uptime"`
	BootTime           string  `json:"boot_time"`
	MaxFileDescriptors uint64  `json:"max_file_descriptors"`
	MaxProcesses       uint64  `json:"max_processes"`
	SystemTemperature  float64 `json:"system_temp"`
	InstalledPackages  int     `json:"installed_packages"`
	LoggedInUsers      int     `json:"loggedin_users"`
}

type CPUInformation struct {
	CPUModel        string  `json:"cpu_model"`
	CPUCores        int     `json:"cpu_cores"`
	CPUUsagePercent float64 `json:"cpu_usage_percentage"`
	CPUUsageCores   float64 `json:"cpu_usage_cores"`
}

type MemoryInformation struct {
	TotalMemoryGB          float64 `json:"total_memory_gb"`
	AvailableMemoryGB      float64 `json:"available_memory_gb"`
	UsedMemoryGB           float64 `json:"used_memory_gb"`
	UsedMemoryPercent      float64 `json:"used_memory_percent"`
	AvailableMemoryPercent float64 `json:"available_memory_percent"`
}

type SwapInformation struct {
	TotalSwapGB     float64 `json:"total_swap_gb"`
	FreeSwapGB      float64 `json:"free_swap_gb"`
	UsedSwapGB      float64 `json:"used_swap_gb"`
	UsedSwapPercent float64 `json:"used_swap_percent"`
	FreeSwapPercent float64 `json:"free_swap_percent"`
}

type LoadInformation struct {
	LoadAverage1m  float64 `json:"load_average_1m"`
	LoadAverage5m  float64 `json:"load_average_5m"`
	LoadAverage15m float64 `json:"load_average_15m"`
}

type DiskUsageInformation struct {
	MountPoint  string  `json:"mount_point"`
	TotalGB     float64 `json:"total_gb"`
	UsedGB      float64 `json:"used_gb"`
	FreeGB      float64 `json:"free_gb"`
	UsedPercent float64 `json:"used_percent"`
	FileSystem  string  `json:"filesystem"`
}

type DiskIOInformation struct {
	Name       string `json:"device_name"`
	ReadCount  uint64 `json:"read_count"`
	WriteCount uint64 `json:"write_count"`
	ReadBytes  uint64 `json:"read_bytes"`
	WriteBytes uint64 `json:"write_bytes"`
}

type NetworkInterfaceInformation struct {
	Name       string   `json:"name"`
	Addresses  []string `json:"addresses"`
	MTU        int      `json:"mtu"`
	IsLoopback bool     `json:"is_loopback"`
	IsUp       bool     `json:"is_up"`
}

type NetworkStatsInformation struct {
	InterfaceName string `json:"interface_name"`
	BytesSent     uint64 `json:"bytes_sent"`
	BytesRecv     uint64 `json:"bytes_recv"`
	PacketsSent   uint64 `json:"packets_sent"`
	PacketsRecv   uint64 `json:"packets_recv"`
	TotalBytes    uint64 `json:"total_bytes"`
}

type FileChecksumInformation struct {
	FilePath string `json:"file_path"`
	SHA256   string `json:"sha256"`
}

func getCPUTemperature() (float64, error) {
	// Method 1: thermal zone (Linux)
	if data, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp"); err == nil {
		if val, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64); err == nil {
			return val / 1000.0, nil
		}
	}
	// Method 2: use sensors command
	out, err := exec.Command("sensors").Output()
	if err != nil {
		return 0, fmt.Errorf("sensors command failed: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Package id 0") || strings.Contains(line, "Core 0") {
			fields := strings.Fields(line)
			for _, field := range fields {
				if strings.HasPrefix(field, "+") && strings.HasSuffix(field, "°C") {
					valStr := strings.TrimSuffix(strings.TrimPrefix(field, "+"), "°C")
					if val, err := strconv.ParseFloat(valStr, 64); err == nil {
						return val, nil
					}
				}
			}
		}
	}
	return 0, fmt.Errorf("CPU temperature not found")
}

func readUintFromFile(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

func countPackages() (int, error) {
	if out, err := exec.Command("bash", "-c", "dpkg -l | wc -l").Output(); err == nil {
		return strconv.Atoi(strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("bash", "-c", "rpm -qa | wc -l").Output(); err == nil {
		return strconv.Atoi(strings.TrimSpace(string(out)))
	}
	return 0, fmt.Errorf("package count detection failed")
}

func GetSystemInfo() (*SystemInformation, error) {
	uptimeSecs, err := host.Uptime()
	if err != nil {
		return nil, err
	}

	hostInfo, err := host.Info()
	if err != nil {
		return nil, err
	}

	maxFDs, _ := readUintFromFile("/proc/sys/fs/file-max")
	maxProcs, _ := readUintFromFile("/proc/sys/kernel/pid_max")
	temp, _ := getCPUTemperature()
	pkgCount, _ := countPackages()
	users, _ := host.Users()

	return &SystemInformation{
		OperatingSystem:    hostInfo.OS,
		Platform:           hostInfo.Platform,
		PlatformVersion:    hostInfo.PlatformVersion,
		KernelVersion:      hostInfo.KernelVersion,
		Architecture:       hostInfo.KernelArch,
		Hostname:           hostInfo.Hostname,
		SystemDescription:  fmt.Sprintf("%s %s (%s)", hostInfo.Platform, hostInfo.PlatformVersion, hostInfo.KernelVersion),
		SystemLocalTime:    time.Now().Format(time.RFC1123),
		SystemUptime:       fmt.Sprintf("%.2f hours", float64(uptimeSecs)/3600),
		BootTime:           time.Unix(int64(hostInfo.BootTime), 0).Format(time.RFC1123),
		MaxFileDescriptors: maxFDs,
		MaxProcesses:       maxProcs,
		SystemTemperature:  temp,
		InstalledPackages:  pkgCount,
		LoggedInUsers:      len(users),
	}, nil
}

func GetCPUInfo() (*CPUInformation, error) {
	cpuInfo, err := cpu.Info()
	if err != nil || len(cpuInfo) == 0 {
		return nil, fmt.Errorf("error getting CPU info: %w", err)
	}

	cpuCores, err := cpu.Counts(true)
	if err != nil {
		return nil, fmt.Errorf("error getting CPU core count: %w", err)
	}

	cpuPercentArr, err := cpu.Percent(0, false)
	if err != nil || len(cpuPercentArr) == 0 {
		return nil, fmt.Errorf("error getting CPU percent: %w", err)
	}

	return &CPUInformation{
		CPUModel:        cpuInfo[0].ModelName,
		CPUCores:        cpuCores,
		CPUUsagePercent: cpuPercentArr[0],
		CPUUsageCores:   (cpuPercentArr[0] / 100.0) * float64(cpuCores),
	}, nil
}

func GetMemoryInfo() (*MemoryInformation, error) {
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	return &MemoryInformation{
		TotalMemoryGB:          float64(memInfo.Total) / 1e9,
		AvailableMemoryGB:      float64(memInfo.Available) / 1e9,
		UsedMemoryGB:           float64(memInfo.Used) / 1e9,
		UsedMemoryPercent:      memInfo.UsedPercent,
		AvailableMemoryPercent: (float64(memInfo.Available) / float64(memInfo.Total)) * 100,
	}, nil
}

func GetSwapInfo() (*SwapInformation, error) {
	swapInfo, err := mem.SwapMemory()
	if err != nil {
		return nil, err
	}

	freePercent := 0.0
	if swapInfo.Total > 0 {
		freePercent = (float64(swapInfo.Free) / float64(swapInfo.Total)) * 100
	}

	return &SwapInformation{
		TotalSwapGB:     float64(swapInfo.Total) / 1e9,
		FreeSwapGB:      float64(swapInfo.Free) / 1e9,
		UsedSwapGB:      float64(swapInfo.Used) / 1e9,
		UsedSwapPercent: swapInfo.UsedPercent,
		FreeSwapPercent: freePercent,
	}, nil
}

func GetLoadAverage() (*LoadInformation, error) {
	loadAvg, err := load.Avg()
	if err != nil {
		return nil, err
	}

	return &LoadInformation{
		LoadAverage1m:  loadAvg.Load1,
		LoadAverage5m:  loadAvg.Load5,
		LoadAverage15m: loadAvg.Load15,
	}, nil
}

func GetDiskUsage() ([]DiskUsageInformation, error) {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return nil, err
	}

	var usageInfo []DiskUsageInformation
	for _, part := range partitions {
		if strings.HasPrefix(part.Device, "/dev/loop") ||
			strings.Contains(part.Mountpoint, "/snap") ||
			strings.Contains(part.Mountpoint, "/run/user") ||
			strings.Contains(part.Mountpoint, "/proc") ||
			strings.Contains(part.Mountpoint, "/sys") ||
			strings.Contains(part.Mountpoint, "/QHlogs") ||
			strings.Contains(part.Fstype, "squashfs") ||
			strings.Contains(part.Fstype, "tmpfs") ||
			strings.Contains(part.Fstype, "overlay") ||
			strings.Contains(part.Fstype, "fuse") ||
			strings.Contains(part.Fstype, "devtmpfs") ||
			strings.Contains(part.Fstype, "autofs") {
			continue
		}
		usage, err := disk.Usage(part.Mountpoint)
		if err == nil {
			usageInfo = append(usageInfo, DiskUsageInformation{
				MountPoint:  usage.Path,
				TotalGB:     float64(usage.Total) / 1e9,
				UsedGB:      float64(usage.Used) / 1e9,
				FreeGB:      float64(usage.Free) / 1e9,
				UsedPercent: usage.UsedPercent,
				FileSystem:  usage.Fstype,
			})
		}
	}
	return usageInfo, nil
}

func GetDiskIO() ([]DiskIOInformation, error) {
	ioStats, err := disk.IOCounters()
	if err != nil {
		return nil, err
	}

	var result []DiskIOInformation
	for name, stats := range ioStats {
		result = append(result, DiskIOInformation{
			Name:       name,
			ReadCount:  stats.ReadCount,
			WriteCount: stats.WriteCount,
			ReadBytes:  stats.ReadBytes,
			WriteBytes: stats.WriteBytes,
		})
	}
	return result, nil
}

func hasFlag(flags []string, flag string) bool {
	for _, f := range flags {
		if f == flag {
			return true
		}
	}
	return false
}

func GetNetworkInterfaces() ([]NetworkInterfaceInformation, error) {
	interfaces, err := gopsunet.Interfaces()
	if err != nil {
		return nil, err
	}

	var info []NetworkInterfaceInformation
	for _, iface := range interfaces {
		var addrs []string
		for _, addr := range iface.Addrs {
			addrs = append(addrs, addr.Addr)
		}
		info = append(info, NetworkInterfaceInformation{
			Name:       iface.Name,
			Addresses:  addrs,
			MTU:        iface.MTU,
			IsLoopback: hasFlag(iface.Flags, "loopback"),
			IsUp:       hasFlag(iface.Flags, "up"),
		})
	}
	return info, nil
}

func GetNetworkStats() ([]NetworkStatsInformation, error) {
	stats, err := gopsunet.IOCounters(true)
	if err != nil {
		return nil, err
	}

	var result []NetworkStatsInformation
	for _, s := range stats {
		totalBytes := s.BytesSent + s.BytesRecv
		result = append(result, NetworkStatsInformation{
			InterfaceName: s.Name,
			BytesSent:     s.BytesSent,
			BytesRecv:     s.BytesRecv,
			PacketsSent:   s.PacketsSent,
			PacketsRecv:   s.PacketsRecv,
			TotalBytes:    totalBytes,
		})
	}
	return result, nil
}

func GetFileChecksum(path string) (*FileChecksumInformation, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return nil, err
	}

	return &FileChecksumInformation{
		FilePath: path,
		SHA256:   fmt.Sprintf("%x", hasher.Sum(nil)),
	}, nil
}
