# 🧠 Vorixa EVM

**Vorixa EVM** is a fast, lightweight monitoring agent for Ethereum (EVM-compatible) node infrastructure. It exposes detailed metrics from system resources, EVM clients (like Erigon & Lighthouse), and optional `systemd` services — all via clean APIs and a built-in, embeddable frontend dashboard.

---

## ✨ Features

- 🔍 **System Metrics** – CPU, Memory, Disk, Load, Uptime, Temperature, Network, etc.
- ⚙️ **EVM Client Metrics** – Latest block, gas usage, txpool stats, peer count, syncing, etc.
- 🔁 **Consensus Layer Support** – Beacon metrics like current slot, epoch, validator count.
- 🧩 **Smart Contract Activity** – ERC20 transfers, deployments, failed txs (last block).
- 🧾 **Account & Token Tracking** – ETH & token balances for configured addresses.
- 🔧 **Systemd Monitoring (Optional)** – Monitor services like `lighthouse`, `erigon`, etc.
- 📦 **Fully Embedded Frontend** – No external Nginx or file server needed.
- 🚀 **Single Binary Deployment** – Ships with UI and backend in a single Go binary.

---

## 🛠️ Configuration

Create a `config.yaml` file in the same directory as your binary or pass `-config` flag.

```yaml
server:
  port: 9080

systemd_monitoring:
  enabled: true
  systemd_names:
    - erigon
    - lighthouse

evm_monitoring:
  enabled: true
  rpc_url: "https://your-erigon-client/rpc"
  beacon_url: "https://your-beacon-client"
  monitor_addresses:
    - "0xYourAddress1"
    - "0xYourAddress2"
  token_contracts:
    - "0xYourToken1"
    - "0xYourToken2"
````

---

## 🔌 API Endpoints

| Endpoint              | Description                       |
| --------------------- | --------------------------------- |
| `/system_metrics`     | System resource usage             |
| `/systemd_monitoring` | (Optional) Monitors systemd units |
| `/evm_metrics`        | Ethereum execution & beacon stats |
| `/`                   | Embedded frontend UI              |

---

## 🚀 Build & Run

### Build (with embedded UI)

```bash
# CGO enabled to reduce binary size
CGO_ENABLED=1 go build -o vorixa-evm ./cmd/main.go
```

> Make sure your `frontend/dist/` is embedded using Go 1.16+ `embed` package.

### Run

```bash
./vorixa-evm -config config.yaml
```

---

## ⚙️ Systemd Service (Optional)

```ini
# /etc/systemd/system/vorixa-evm.service

[Unit]
Description=Vorixa EVM Monitoring Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vorixa-evm -config /etc/vorixa-evm/config.yaml
Restart=always
RestartSec=5
User=root
Environment=CGO_ENABLED=1

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable --now vorixa-evm
```

---

## 📄 License

MIT License © \[Gautam Jha]

---

## 🤝 Contributing

PRs welcome! Feel free to fork and open issues if you'd like to help improve Vorixa EVM.