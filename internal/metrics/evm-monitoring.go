package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"sync"
	"time"

	"vorixa-agent/config"
)

// MetricsResponse defines the JSON structure returned by /evm_metrics
type MetricsResponse struct {
	Network   NetworkMetrics   `json:"network_overview"`
	Chain     ChainMetrics     `json:"chain_metrics"`
	TxPool    TxPoolMetrics    `json:"transaction_pool"`
	Contracts ContractMetrics  `json:"smart_contract_activity"`
	Accounts  AccountMetrics   `json:"account_token_stats"`
	Consensus ConsensusMetrics `json:"consensus_layer"`
	Timestamp time.Time        `json:"timestamp"`
}

// 1. Network Overview
type NetworkMetrics struct {
	ClientVersion string      `json:"client_version"`
	ChainID       string      `json:"chain_id"`
	NetworkID     string      `json:"network_id"`
	Syncing       interface{} `json:"syncing"`
	BlockNumber   uint64      `json:"current_block"`
	FinalizedRoot string      `json:"finalized_root"`
	PeerCount     uint64      `json:"peer_count"`
}

// 2. Block & Chain Metrics
type ChainMetrics struct {
	LatestBlockHash string  `json:"latest_block_hash"`
	AvgBlockTimeSec float64 `json:"avg_block_time_last_10"`
	GasUsed         uint64  `json:"gas_used"`
	GasLimit        uint64  `json:"gas_limit"`
	BaseFee         uint64  `json:"base_fee_per_gas"`
	FeeBurned       uint64  `json:"fee_burned_last_block"`
	UncleCount      int     `json:"uncles_count"`
}

// 3. Transaction Pool / Fee Metrics
type TxPoolMetrics struct {
	PendingCount       uint64  `json:"pending_tx_count"`
	AvgGasPriceWei     uint64  `json:"avg_gas_price_wei"`
	MinPriorityFeeWei  uint64  `json:"min_priority_fee_wei"`
	MaxPriorityFeeWei  uint64  `json:"max_priority_fee_wei"`
	MostExpensiveGas   uint64  `json:"most_expensive_gas_price_wei"`
	MostExpensiveTxHex string  `json:"most_expensive_tx_hash"`
	TPS                float64 `json:"tps_estimate"`
}

// 4. Smart Contract Activity
type ContractMetrics struct {
	ERC20TransfersLastBlock int `json:"erc20_transfers_last_block"`
	DeploymentsLastBlock    int `json:"contract_deployments_last_block"`
	FailedTxLastBlock       int `json:"failed_txs_last_block"`
}

// 5. Account & Token Stats
type AccountMetrics struct {
	BalancesWei      map[string]string            `json:"eth_balances_wei"`
	TokenBalancesWei map[string]map[string]string `json:"token_balances_wei"`
}

// 7. Consensus Layer
type ConsensusMetrics struct {
	CurrentSlot       uint64 `json:"current_slot"`
	CurrentEpoch      uint64 `json:"current_epoch"`
	FinalizedEpoch    uint64 `json:"finalized_epoch"`
	ActiveValidators  uint64 `json:"active_validators"`
	HeadBlockDelaySec int64  `json:"head_block_delay_seconds"`
}

// JSON-RPC helpers
type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func callRPC(ctx context.Context, url, method string, params ...interface{}) (json.RawMessage, error) {
	body, _ := json.Marshal(rpcRequest{"2.0", method, params, 1})
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	b, _ := ioutil.ReadAll(res.Body)
	var rpc rpcResponse
	if err := json.Unmarshal(b, &rpc); err != nil {
		return nil, err
	}
	if rpc.Error != nil {
		return nil, fmt.Errorf(rpc.Error.Message)
	}
	return rpc.Result, nil
}

// parseBigInt handles both "0x..." hex strings and plain decimal strings
func parseBigInt(raw json.RawMessage) (*big.Int, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return big.NewInt(0), err
	}
	i := new(big.Int)
	switch {
	case len(s) > 1 && s[:2] == "0x":
		if _, ok := i.SetString(s[2:], 16); !ok {
			return big.NewInt(0), fmt.Errorf("invalid hex int %q", s)
		}
	default:
		if _, ok := i.SetString(s, 10); !ok {
			return big.NewInt(0), fmt.Errorf("invalid decimal int %q", s)
		}
	}
	return i, nil
}

// RegisterRoutes mounts the /evm_metrics endpoint if enabled
func RegisterRoutes(mux *http.ServeMux, cfg *config.Config) {
	if !cfg.EVMMetrics.Enabled {
		return
	}
	mux.HandleFunc("/evm_metrics", func(w http.ResponseWriter, r *http.Request) {
		handleMetrics(w, r, cfg)
	})
}

func handleMetrics(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	resp := MetricsResponse{Timestamp: time.Now().UTC()}
	wg.Add(6)

	go func() {
		defer wg.Done()
		resp.Network, _ = collectNetwork(ctx, cfg.EVMMetrics.RPCURL, cfg.EVMMetrics.BeaconURL)
	}()
	go func() {
		defer wg.Done()
		resp.Chain, _ = collectChain(ctx, cfg.EVMMetrics.RPCURL)
	}()
	go func() {
		defer wg.Done()
		resp.TxPool, _ = collectTxPool(ctx, cfg.EVMMetrics.RPCURL)
	}()
	go func() {
		defer wg.Done()
		resp.Contracts, _ = collectContracts(ctx, cfg.EVMMetrics.RPCURL)
	}()
	go func() {
		defer wg.Done()
		resp.Accounts, _ = collectAccounts(
			ctx,
			cfg.EVMMetrics.RPCURL,
			cfg.EVMMetrics.MonitorAddresses,
			cfg.EVMMetrics.TokenContracts,
		)
	}()
	go func() {
		defer wg.Done()
		resp.Consensus, _ = collectConsensus(ctx, cfg.EVMMetrics.BeaconURL)
	}()

	wg.Wait()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// 1. Network Overview
func collectNetwork(ctx context.Context, rpcURL, beaconURL string) (NetworkMetrics, error) {
	verRaw, _ := callRPC(ctx, rpcURL, "web3_clientVersion")
	var clientVersion string
	json.Unmarshal(verRaw, &clientVersion)

	cidRaw, _ := callRPC(ctx, rpcURL, "eth_chainId")
	chainID, _ := parseBigInt(cidRaw)

	nidRaw, _ := callRPC(ctx, rpcURL, "net_version")
	var networkID string
	json.Unmarshal(nidRaw, &networkID)

	syncRaw, _ := callRPC(ctx, rpcURL, "eth_syncing")
	var syncing interface{}
	json.Unmarshal(syncRaw, &syncing)

	blkRaw, _ := callRPC(ctx, rpcURL, "eth_blockNumber")
	blockNum, _ := parseBigInt(blkRaw)

	peerRaw, _ := callRPC(ctx, rpcURL, "net_peerCount")
	peerCount, _ := parseBigInt(peerRaw)

	finRoot := getFinalizedHeader(beaconURL)

	return NetworkMetrics{
		ClientVersion: clientVersion,
		ChainID:       chainID.String(),
		NetworkID:     networkID,
		Syncing:       syncing,
		BlockNumber:   blockNum.Uint64(),
		FinalizedRoot: finRoot,
		PeerCount:     peerCount.Uint64(),
	}, nil
}

func getFinalizedHeader(base string) string {
	url := fmt.Sprintf("%s/eth/v1/beacon/headers/finalized", base)
	res, err := http.Get(url)
	if err != nil {
		return ""
	}
	defer res.Body.Close()

	b, _ := ioutil.ReadAll(res.Body)
	var out struct {
		Data struct{ Header struct{ Root string } }
	}
	json.Unmarshal(b, &out)
	return out.Data.Header.Root
}

// 2. Block & Chain Metrics
func collectChain(ctx context.Context, rpcURL string) (ChainMetrics, error) {
	blkRaw, _ := callRPC(ctx, rpcURL, "eth_getBlockByNumber", "latest", false)
	var blk struct {
		Hash      string        `json:"hash"`
		Number    string        `json:"number"`
		Timestamp string        `json:"timestamp"`
		GasUsed   string        `json:"gasUsed"`
		GasLimit  string        `json:"gasLimit"`
		BaseFee   string        `json:"baseFeePerGas"`
		Uncles    []interface{} `json:"uncles"`
	}
	json.Unmarshal(blkRaw, &blk)

	num, _ := parseBigInt(json.RawMessage(fmt.Sprintf("\"%s\"", blk.Number)))
	ts, _ := parseBigInt(json.RawMessage(fmt.Sprintf("\"%s\"", blk.Timestamp)))
	gasUsed, _ := parseBigInt(json.RawMessage(fmt.Sprintf("\"%s\"", blk.GasUsed)))
	gasLimit, _ := parseBigInt(json.RawMessage(fmt.Sprintf("\"%s\"", blk.GasLimit)))
	baseFee, _ := parseBigInt(json.RawMessage(fmt.Sprintf("\"%s\"", blk.BaseFee)))

	// compute average block time over last 10 blocks
	var times []float64
	prevTs := ts
	for i := 1; i <= 10; i++ {
		r, _ := callRPC(ctx, rpcURL, "eth_getBlockByNumber", fmt.Sprintf("0x%x", num.Uint64()-uint64(i)), false)
		var b2 struct {
			Timestamp string `json:"timestamp"`
		}
		json.Unmarshal(r, &b2)
		ts2, _ := parseBigInt(json.RawMessage(fmt.Sprintf("\"%s\"", b2.Timestamp)))
		times = append(times, float64(prevTs.Uint64()-ts2.Uint64()))
		prevTs = ts2
	}
	avg := 0.0
	for _, d := range times {
		avg += d
	}
	if len(times) > 0 {
		avg /= float64(len(times))
	}

	feeBurned := new(big.Int).Mul(baseFee, gasUsed)

	return ChainMetrics{
		LatestBlockHash: blk.Hash,
		AvgBlockTimeSec: avg,
		GasUsed:         gasUsed.Uint64(),
		GasLimit:        gasLimit.Uint64(),
		BaseFee:         baseFee.Uint64(),
		FeeBurned:       feeBurned.Uint64(),
		UncleCount:      len(blk.Uncles),
	}, nil
}

// 3. Transaction Pool / Fee Metrics
func collectTxPool(ctx context.Context, rpcURL string) (TxPoolMetrics, error) {
	stRaw, _ := callRPC(ctx, rpcURL, "txpool_status")
	var status struct{ Pending string }
	json.Unmarshal(stRaw, &status)
	pend, _ := parseBigInt(json.RawMessage(fmt.Sprintf("\"%s\"", status.Pending)))

	gpRaw, _ := callRPC(ctx, rpcURL, "eth_gasPrice")
	gp, _ := parseBigInt(gpRaw)

	return TxPoolMetrics{
		PendingCount:       pend.Uint64(),
		AvgGasPriceWei:     gp.Uint64(),
		MinPriorityFeeWei:  0,
		MaxPriorityFeeWei:  0,
		MostExpensiveGas:   gp.Uint64(),
		MostExpensiveTxHex: "",
		TPS:                0,
	}, nil
}

// 4. Smart Contract Activity (stubs)
func collectContracts(ctx context.Context, rpcURL string) (ContractMetrics, error) {
	return ContractMetrics{0, 0, 0}, nil
}

// 5. Account & Token Stats
func collectAccounts(ctx context.Context, rpcURL string, addrs, toks []string) (AccountMetrics, error) {
	bal := make(map[string]string)
	tokBal := make(map[string]map[string]string)

	for _, addr := range addrs {
		r, _ := callRPC(ctx, rpcURL, "eth_getBalance", addr, "latest")
		b, _ := parseBigInt(r)
		bal[addr] = b.String()
	}

	for _, tc := range toks {
		tokBal[tc] = make(map[string]string)
		for _, addr := range addrs {
			data := "0x70a08231" + fmt.Sprintf("%064s", addr[2:])
			r, _ := callRPC(ctx, rpcURL, "eth_call", map[string]interface{}{"to": tc, "data": data}, "latest")
			b, _ := parseBigInt(r)
			tokBal[tc][addr] = b.String()
		}
	}

	return AccountMetrics{BalancesWei: bal, TokenBalancesWei: tokBal}, nil
}

// 7. Consensus Layer
func collectConsensus(ctx context.Context, beaconURL string) (ConsensusMetrics, error) {
	// fetch head header
	headDelay := int64(0)
	currentSlot := uint64(0)
	currentEpoch := uint64(0)
	finalizedEpoch := uint64(0)
	activeValidators := uint64(0)

	// HEAD
	if head, err := http.Get(fmt.Sprintf("%s/eth/v1/beacon/headers/head", beaconURL)); err == nil {
		defer head.Body.Close()
		if b, err2 := ioutil.ReadAll(head.Body); err2 == nil {
			var hOut struct {
				Data struct{ Header struct{ Slot string } }
			}
			if err3 := json.Unmarshal(b, &hOut); err3 == nil {
				if slotInt, err4 := parseBigInt(json.RawMessage(fmt.Sprintf("\"%s\"", hOut.Data.Header.Slot))); err4 == nil {
					currentSlot = slotInt.Uint64()
					currentEpoch = currentSlot / 32
					headDelay = time.Now().Unix() - int64(currentSlot*12)
					finalizedEpoch = currentEpoch // fallback if validator fetch fails
				}
			}
		}
	}

	// VALIDATORS
	if state, err := http.Get(fmt.Sprintf("%s/eth/v1/beacon/states/head/validators", beaconURL)); err == nil {
		defer state.Body.Close()
		if s, err2 := ioutil.ReadAll(state.Body); err2 == nil {
			var sOut struct{ Data []interface{} }
			if err3 := json.Unmarshal(s, &sOut); err3 == nil {
				activeValidators = uint64(len(sOut.Data))
			}
		}
	}

	return ConsensusMetrics{
		CurrentSlot:       currentSlot,
		CurrentEpoch:      currentEpoch,
		FinalizedEpoch:    finalizedEpoch,
		ActiveValidators:  activeValidators,
		HeadBlockDelaySec: headDelay,
	}, nil
}
