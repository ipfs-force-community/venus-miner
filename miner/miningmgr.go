package miner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"

	"github.com/ipfs-force-community/sophon-miner/types"

	sharedTypes "github.com/filecoin-project/venus/venus-shared/types"
)

func (m *Miner) ManualStart(ctx context.Context, mAddrs []address.Address) error {
	for _, mAddr := range mAddrs {
		minerInfo, err := m.minerManager.OpenMining(ctx, mAddr)
		if err != nil {
			log.Errorf("close mining for %s: %v", mAddr.String(), err)
			continue
		}

		epp, err := NewWinningPoStProver(m.api, m.gatewayNode, minerInfo.Addr)
		if err != nil {
			log.Errorf("create WinningPoStProver for %s: %v", minerInfo.Addr.String(), err)
			continue
		}
		m.lkWPP.Lock()
		m.minerWPPMap[minerInfo.Addr] = &minerWPP{epp: epp, account: minerInfo.Name}
		m.lkWPP.Unlock()
	}

	return nil
}

func (m *Miner) ManualStop(ctx context.Context, mAddrs []address.Address) error {
	for _, mAddr := range mAddrs {
		if err := m.minerManager.CloseMining(ctx, mAddr); err != nil {
			log.Errorf("close mining for %s: %v", mAddr.String(), err)
			continue
		}
		m.lkWPP.Lock()
		delete(m.minerWPPMap, mAddr)
		m.lkWPP.Unlock()
	}

	return nil
}

func (m *Miner) UpdateAddress(ctx context.Context, skip, limit int64) ([]types.MinerInfo, error) {
	miners, err := m.minerManager.Update(ctx, skip, limit)
	if err != nil {
		return nil, err
	}

	minerWPPMap := make(map[address.Address]*minerWPP)
	minerInfos := make([]types.MinerInfo, 0, len(miners))
	for _, minerInfo := range miners {
		if !m.minerManager.IsOpenMining(ctx, minerInfo.Addr) {
			continue
		}

		epp, err := NewWinningPoStProver(m.api, m.gatewayNode, minerInfo.Addr)
		if err != nil {
			log.Errorf("create WinningPoStProver for %s: %v", minerInfo.Addr.String(), err)
			continue
		}

		minerWPPMap[minerInfo.Addr] = &minerWPP{epp: epp, account: minerInfo.Name}
		minerInfos = append(minerInfos, *minerInfo)
	}
	m.lkWPP.Lock()
	m.minerWPPMap = minerWPPMap
	m.lkWPP.Unlock()

	return minerInfos, nil
}

func (m *Miner) ListAddress(ctx context.Context) ([]types.MinerInfo, error) {
	miners, err := m.minerManager.List(ctx)
	if err != nil {
		return nil, err
	}

	minerInfos := make([]types.MinerInfo, 0, len(miners))
	for _, minerInfo := range miners {
		minerInfos = append(minerInfos, *minerInfo)
	}

	return minerInfos, nil
}

func (m *Miner) ListBlocks(ctx context.Context, params *types.BlocksQueryParams) ([]types.MinedBlock, error) {
	return m.sf.ListBlock(ctx, params)
}

func (m *Miner) StatesForMining(ctx context.Context, addrs []address.Address) ([]types.MinerState, error) {
	m.lkWPP.Lock()
	defer m.lkWPP.Unlock()

	res := make([]types.MinerState, 0)
	if len(addrs) > 0 {
		for _, addr := range addrs {
			if val, ok := m.minerWPPMap[addr]; ok {
				res = append(res, types.MinerState{Addr: addr, IsMining: true, Err: val.err})
			} else {
				res = append(res, types.MinerState{Addr: addr, IsMining: false, Err: nil})
			}
		}
	} else {
		minerInfos, err := m.minerManager.List(ctx)
		if err != nil {
			return nil, err
		}
		for _, minerInfo := range minerInfos {
			if val, ok := m.minerWPPMap[minerInfo.Addr]; ok {
				res = append(res, types.MinerState{Addr: minerInfo.Addr, IsMining: true, Err: val.err})
			} else {
				res = append(res, types.MinerState{Addr: minerInfo.Addr, IsMining: false, Err: nil})
			}
		}
	}

	return res, nil
}

func (m *Miner) winCountInRound(ctx context.Context, account string, mAddr address.Address, api SignFunc, epoch abi.ChainEpoch) (*sharedTypes.ElectionProof, error) {
	ts, err := m.api.ChainGetTipSetByHeight(ctx, abi.ChainEpoch(epoch), sharedTypes.EmptyTSK)
	if err != nil {
		return nil, fmt.Errorf("%v (%w)", err, types.CallNodeRPCError)
	}

	var nullRounds abi.ChainEpoch
	if epoch > ts.Height() {
		nullRounds = epoch - ts.Height()
	}
	round := ts.Height() + nullRounds + 1

	mbi, err := m.api.MinerGetBaseInfo(ctx, mAddr, round, ts.Key())
	if err != nil {
		return nil, fmt.Errorf("%v (%w)", err, types.CallNodeRPCError)
	}

	if mbi == nil {
		return nil, fmt.Errorf("can't find base info on chain, addr %s should be a new miner or no sector found before chain finality", mAddr.String())
	}

	if !mbi.EligibleForMining {
		return nil, fmt.Errorf("%s slashed or just have no power yet", mAddr.String())
	}

	rbase := mbi.PrevBeaconEntry
	if len(mbi.BeaconEntries) > 0 {
		rbase = mbi.BeaconEntries[len(mbi.BeaconEntries)-1]
	}

	return IsRoundWinner(ctx, round, account, mAddr, rbase, mbi, api)
}

func (m *Miner) CountWinners(ctx context.Context, addrs []address.Address, start abi.ChainEpoch, end abi.ChainEpoch) ([]types.CountWinners, error) {
	log.Infof("count winners, addrs: %v, start: %v, end: %v", addrs, start, end)

	ts, err := m.api.ChainHead(ctx)
	if err != nil {
		log.Error("get chain head", err)
		return []types.CountWinners{}, err
	}

	if start > ts.Height() || end > ts.Height() {
		return []types.CountWinners{}, fmt.Errorf("start or end greater than cur tipset height: %v", ts.Height())
	}

	res := make([]types.CountWinners, 0)
	var resLk sync.Mutex
	wg := sync.WaitGroup{}

	minerWpps := make(map[address.Address]*minerWPP)
	m.lkWPP.Lock()
	if len(addrs) > 0 {
		for _, addr := range addrs {
			if wpp, ok := m.minerWPPMap[addr]; ok {
				minerWpps[addr] = wpp
			} else {
				res = append(res, types.CountWinners{Msg: "miner not exist", Miner: addr})
			}
		}
	} else {
		for addr, wpp := range m.minerWPPMap {
			minerWpps[addr] = wpp
		}
	}
	m.lkWPP.Unlock()

	controlChan := make(chan struct{}, 100)
	if len(minerWpps) > 0 {
		sign := m.signerFunc(ctx, m.gatewayNode)

		wg.Add(len(minerWpps))
		for addr, wpp := range minerWpps {
			tAddr := addr
			tWpp := wpp
			go func() {
				defer wg.Done()
				wgWin := sync.WaitGroup{}
				winInfo := make([]types.SimpleWinInfo, 0)
				totalWinCount := int64(0)
				var winInfoLk sync.Mutex
				for epoch := start; epoch <= end; epoch++ {
					wgWin.Add(1)
					go func(epoch abi.ChainEpoch) {
						defer func() {
							wgWin.Done()
							<-controlChan
						}()

						controlChan <- struct{}{}

						winner, err := m.winCountInRound(ctx, tWpp.account, tAddr, sign, epoch)
						if err != nil {
							if errors.Is(err, types.ConnectGatewayError) || errors.Is(err, types.WalletSignError) ||
								errors.Is(err, types.CallNodeRPCError) {
								winInfoLk.Lock()
								winInfo = append(winInfo, types.SimpleWinInfo{Epoch: epoch + 1, Msg: err.Error()})
								winInfoLk.Unlock()
							}
							log.Warnf("generate winner met failed: address: %s, epoch: %d, err: %v", tAddr, epoch, err)
							return
						}

						if winner != nil {
							winInfoLk.Lock()
							totalWinCount += winner.WinCount
							winInfo = append(winInfo, types.SimpleWinInfo{Epoch: epoch + 1, WinCount: winner.WinCount})
							winInfoLk.Unlock()
						}
					}(epoch)
				}
				wgWin.Wait()
				resLk.Lock()
				res = append(res, types.CountWinners{Miner: tAddr, TotalWinCount: totalWinCount, WinEpochList: winInfo})
				resLk.Unlock()
			}()
		}
		wg.Wait()
	}
	close(controlChan)

	return res, nil
}

func (m *Miner) pollingMiners(ctx context.Context) {
	tm := time.NewTicker(time.Second * 60)
	defer tm.Stop()

	// just protect from data race
	m.lkWPP.Lock()
	stop := m.stop
	m.lkWPP.Unlock()

	for {
		select {
		case <-stop:
			log.Warnf("stop polling by stop channel")
			return
		case <-ctx.Done():
			log.Warnf("stop polling miners: %v", ctx.Err())
			return
		case <-tm.C:
			_, err := m.UpdateAddress(ctx, 0, 0)
			if err != nil {
				log.Errorf("polling miners: %v", ctx.Err())
			} else {
				log.Debug("polling miners success")
			}
		}
	}
}
