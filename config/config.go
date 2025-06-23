package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Port int `yaml:"port"`
	} `yaml:"server"`

	Metrics struct {
		Interval int `yaml:"interval"`
	} `yaml:"metrics"`

	SystemdMonitoring struct {
		Enabled      bool     `yaml:"enabled"`
		SystemdNames []string `yaml:"systemd_names"`
	} `yaml:"systemd_monitoring"`

	EVMMetrics struct {
		Enabled          bool     `yaml:"enabled"`
		RPCURL           string   `yaml:"rpc_url"`
		BeaconURL        string   `yaml:"beacon_url"`
		MonitorAddresses []string `yaml:"monitor_addresses"`
		TokenContracts   []string `yaml:"token_contracts"`
	} `yaml:"evm_monitoring"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &cfg, nil
}
