package miner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	logging "github.com/ipfs/go-log/v2"
	"go.opencensus.io/stats"
	"go.opencensus.io/tag"
	"go.opencensus.io/trace"

	proof2 "github.com/filecoin-project/specs-actors/v2/actors/runtime/proof"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/builtin"
	"github.com/filecoin-project/go-state-types/crypto"

	"github.com/ipfs-force-community/sophon-miner/api/client"
	"github.com/ipfs-force-community/sophon-miner/build"
	"github.com/ipfs-force-community/sophon-miner/lib/journal"
	"github.com/ipfs-force-community/sophon-miner/lib/metrics"
	"github.com/ipfs-force-community/sophon-miner/node/config"
	"github.com/ipfs-force-community/sophon-miner/node/modules/helpers"
	recorder "github.com/ipfs-force-community/sophon-miner/node/modules/mine-recorder"
	miner_manager "github.com/ipfs-force-community/sophon-miner/node/modules/miner-manager"
	"github.com/ipfs-force-community/sophon-miner/node/modules/slashfilter"
	"github.com/ipfs-force-community/sophon-miner/types"

	"github.com/filecoin-project/venus/pkg/constants"
	v1api "github.com/filecoin-project/venus/venus-shared/api/chain/v1"
	sharedTypes "github.com/filecoin-project/venus/venus-shared/types"
	"github.com/filecoin-project/venus/venus-shared/types/wallet"
)

var log = logging.Logger("miner")

// Journal event types.
const (
	evtTypeBlockMined = iota
)

var DefaultMaxErrCounts = 20

// waitFunc is expected to pace block mining at the configured network rate.
//
// baseTime is the timestamp of the mining base, i.e. the timestamp
// of the tipset we're planning to construct upon.
//
// Upon each mining loop iteration, the returned callback is called reporting
// whether we mined a block in this round or not.
type waitFunc func(ctx context.Context, baseTime uint64) (func(bool, abi.ChainEpoch, error), abi.ChainEpoch, error)

type signerFunc func(ctx context.Context, node *config.GatewayNode) SignFunc

func randTimeOffset(width time.Duration) time.Duration {
	buf := make([]byte, 8)
	rand.Reader.Read(buf) //nolint:errcheck
	val := time.Duration(binary.BigEndian.Uint64(buf) % uint64(width))

	return val - (width / 2)
}

// NewMiner instantiates a miner with a concrete WinningPoStProver and a miner
// address (which can be different from the worker's address).
func NewMiner(
	metricsCtx helpers.MetricsCtx,
	api v1api.FullNode,
	cfg *config.MinerConfig,
	minerManager miner_manager.MinerManageAPI,
	sf slashfilter.SlashFilterAPI,
	j journal.Journal) (*Miner, error) {
	networkParams, err := api.StateGetNetworkParams(metricsCtx)
	if err != nil {
		return nil, err
	}

	miner := &Miner{
		api:                  api,
		networkParams:        networkParams,
		PropagationDelaySecs: cfg.PropagationDelaySecs,
		MinerOnceTimeout:     time.Duration(cfg.MinerOnceTimeout),
		MpoolSelectDelaySecs: cfg.MpoolSelectDelaySecs,
		gatewayNode:          cfg.Gateway,
		submitNodes:          cfg.SubmitNodes,
		waitFunc: func(ctx context.Context, baseTime uint64) (func(bool, abi.ChainEpoch, error), abi.ChainEpoch, error) {
			// wait around for half the block time in case other parents come in
			//
			// if we're mining a block in the past via catch-up/rush mining,
			// such as when recovering from a network halt, this sleep will be
			// for a negative duration, and therefore **will return
			// immediately**.
			//
			// the result is that we WILL NOT wait, therefore fast-forwarding
			// and thus healing the chain by backfilling it with null rounds
			// rapidly.
			deadline := baseTime + cfg.PropagationDelaySecs
			baseT := time.Unix(int64(deadline), 0)

			baseT = baseT.Add(randTimeOffset(time.Second))

			build.Clock.Sleep(build.Clock.Until(baseT))

			return func(bool, abi.ChainEpoch, error) {}, 0, nil
		},
		signerFunc: func(ctx context.Context, cfg *config.GatewayNode) SignFunc {
			return func(ctx context.Context, signer address.Address, accounts []string, toSign []byte, meta sharedTypes.MsgMeta) (*crypto.Signature, error) {
				walletAPI, closer, err := client.NewGatewayRPC(ctx, cfg)
				if err != nil {
					return nil, fmt.Errorf("new gateway rpc failed:%v (%w)", err, types.ConnectGatewayError)
				}
				defer closer()

				sig, err := walletAPI.WalletSign(ctx, signer, accounts, toSign, meta)
				if err != nil {
					return nil, fmt.Errorf("wallet sign failed:%v (%w)", err, types.CallNodeRPCError)
				}
				return sig, nil
			}
		},

		sf: sf,

		evtTypes: [...]journal.EventType{
			evtTypeBlockMined: j.RegisterEventType("miner", "block_mined"),
		},
		journal: j,

		minerManager: minerManager,
		minerWPPMap:  make(map[address.Address]*minerWPP),
		metricsCtx:   metricsCtx,
	}

	if networkParams.NetworkName == "2k" {
		miner.MinerOnceTimeout = time.Millisecond * 2800
	}

	return miner, nil
}

type syncStatus struct {
	heightDiff int64
	err        error
}

type minerWPP struct {
	account string
	epp     WinningPoStProver
	err     []string
}

type Miner struct {
	api           v1api.FullNode
	networkParams *sharedTypes.NetworkParams

	PropagationDelaySecs uint64
	MinerOnceTimeout     time.Duration
	MpoolSelectDelaySecs uint64

	gatewayNode *config.GatewayNode
	submitNodes []*config.APIInfo

	lk       sync.Mutex
	stop     chan struct{}
	stopping chan struct{}

	waitFunc   waitFunc
	signerFunc signerFunc

	lastWork *MiningBase

	sf slashfilter.SlashFilterAPI

	evtTypes [1]journal.EventType
	journal  journal.Journal

	st syncStatus

	lkWPP        sync.Mutex
	minerWPPMap  map[address.Address]*minerWPP
	minerManager miner_manager.MinerManageAPI
	metricsCtx   context.Context
}

func (m *Miner) Start(ctx context.Context) error {
	m.lk.Lock()
	defer m.lk.Unlock()
	if m.stop != nil {
		return fmt.Errorf("miner already started")
	}

	// init miners
	miners, err := m.minerManager.List(ctx)
	if err != nil {
		return err
	}
	for _, minerInfo := range miners {
		if !m.minerManager.IsOpenMining(ctx, minerInfo.Addr) {
			continue
		}

		epp, err := NewWinningPoStProver(m.api, m.gatewayNode, minerInfo.Addr)
		if err != nil {
			log.Errorf("create WinningPoStProver for [%v], err: %v", minerInfo.Addr.String(), err)
			continue
		}
		m.minerWPPMap[minerInfo.Addr] = &minerWPP{epp: epp, account: minerInfo.Name}
	}

	m.stop = make(chan struct{})
	go m.mine(context.TODO())
	go m.pollingMiners(ctx)
	go m.SyncStatus(ctx)
	return nil
}

// Stop stops the mining operation. It is not idempotent, and multiple adjacent
// calls to Stop will fail.
func (m *Miner) Stop(ctx context.Context) error {
	m.lk.Lock()

	m.stopping = make(chan struct{})
	stopping := m.stopping
	close(m.stop)

	m.lk.Unlock()

	select {
	case <-stopping:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Miner) niceSleep(d time.Duration) bool {
	select {
	case <-build.Clock.After(d):
		return true
	case <-m.stop:
		log.Infow("received interrupt while trying to sleep in mining cycle")
		return false
	}
}

func (m *Miner) numberOfMiners() int {
	m.lkWPP.Lock()
	defer m.lkWPP.Unlock()

	return len(m.minerWPPMap)
}

// mine runs the mining loop. It performs the following:
//
//  1. Queries our current best currently-known mining candidate (tipset to
//     build upon).
//  2. Waits until the propagation delay of the network has elapsed (currently
//     6 seconds). The waiting is done relative to the timestamp of the best
//     candidate, which means that if it's way in the past, we won't wait at
//     all (e.g. in catch-up or rush mining).
//  3. After the wait, we query our best mining candidate. This will be the one
//     we'll work with.
//  4. Sanity check that we _actually_ have a new mining base to mine on. If
//     not, wait one epoch + propagation delay, and go back to the top.
//  5. We attempt to mine a block, by calling mineOne (refer to godocs). This
//     method will either return a block if we were eligible to mine, or nil
//     if we weren't.
//     6a. If we mined a block, we update our state and push it out to the network
//     via gossipsub.
//     6b. If we didn't mine a block, we consider this to be a nil round on top of
//     the mining base we selected. If other miner or miners on the network
//     were eligible to mine, we will receive their blocks via gossipsub and
//     we will select that tipset on the next iteration of the loop, thus
//     discarding our null round.
func (m *Miner) mine(ctx context.Context) {
	log.Info("start to do winning poster")
	ctx, span := trace.StartSpan(ctx, "/mine")
	defer span.End()

	go m.doWinPoStWarmup(ctx)

	var lastBase MiningBase
	for {
		select {
		case <-m.stop:
			stopping := m.stopping
			m.stop = nil
			m.stopping = nil
			close(stopping)
			return

		default:
		}

		log.Infow("sync status", "HeightDiff", m.st.heightDiff, "err:", m.st.err)

		// if there is no miner to be mined, wait
		if m.numberOfMiners() == 0 {
			log.Warn("no miner is configured for mining, please check ... ")
			m.niceSleep(time.Second * 5)
			continue
		}

		base, td, err := m.getLatestBase(ctx)
		if err != nil {
			log.Warnf("failed to get latest base, %s", err)
			m.niceSleep(td)
			continue
		}

		if base.TipSet.Equals(lastBase.TipSet) && lastBase.NullRounds == base.NullRounds {
			log.Warnf("BestMiningCandidate from the previous round: %s (nulls:%d)", lastBase.TipSet.Cids(), lastBase.NullRounds)
			m.niceSleep(time.Duration(m.networkParams.BlockDelaySecs) * time.Second)
			continue
		}

		// mining once for all miners
		winPoSts := m.mineOneForAll(ctx, base)
		log.Infow("mining compute", "number of wins", len(winPoSts), "total miner", m.numberOfMiners())

		// get the base again in order to get all the blocks in the previous round as much as possible
		ts, err := m.api.ChainHead(ctx)
		//isChainForked := false
		if err == nil {
			// rule:
			//
			//  1.  ts include more blocks(maybe unequal is more appropriate, for chain forked)
			//  2.  ts.At(0) == base.TipSet.At(0), blocks[0] is used to calculate IsRoundWinner
			if ts.Height() == base.TipSet.Height() && !ts.Equals(base.TipSet) {
				if ts.MinTicket().Compare(base.TipSet.MinTicket()) == 0 {
					log.Infow("there are better bases here", "new base", types.LogCids(ts.Cids()), "base", types.LogCids(base.TipSet.Cids()))
					base.TipSet = ts
				} else {
					//isChainForked = true
					log.Warnw("base changed, chain may be forked", "new base", types.LogCids(ts.Cids()), "base", types.LogCids(base.TipSet.Cids()))

					// Record chain forked
					for _, res := range winPoSts {
						if err := m.sf.PutBlock(ctx, &sharedTypes.BlockHeader{
							Height: base.TipSet.Height() + base.NullRounds + 1,
							Miner:  res.addr,
						}, base.TipSet.Height(), time.Time{}, types.ChainForked); err != nil {
							log.Errorf("failed to record chain forked: %s", err)
						}

						ctx, _ = tag.New(
							ctx,
							tag.Upsert(metrics.MinerID, res.addr.String()),
						)
						stats.Record(ctx, metrics.NumberOfMiningChainFork.M(1))
					}
				}
			}
		}
		lastBase = *base

		// when the head of the sync is converted to: base01-> base02-> base01, the chain polymerization multiple times,
		// get base02 here as a fork, will miss the block.
		// therefore, no matter whether there is a fork, we all try to create block.
		if len(winPoSts) > 0 {
			// get pending messages early
			ticketQualitys := make([]float64, len(winPoSts))
			for idx, res := range winPoSts {
				ticketQualitys[idx] = res.ticket.Quality()
			}
			log.Infow("select message", "tickets", len(ticketQualitys))

			var (
				tCtx    context.Context
				tCancel context.CancelFunc
			)
			if m.MpoolSelectDelaySecs > 0 {
				tCtx, tCancel = context.WithTimeout(ctx, time.Duration(m.MpoolSelectDelaySecs)*time.Second)
			} else {
				tCtx, tCancel = context.WithCancel(ctx)
			}
			msgs, err := m.api.MpoolSelects(tCtx, base.TipSet.Key(), ticketQualitys)
			if err != nil {
				log.Errorf("failed to select messages: %s", err)
			}
			tCancel()

			tSelMsg := build.Clock.Now()

			height := base.TipSet.Height() + base.NullRounds + 1

			// create blocks
			var blks []*sharedTypes.BlockMsg
			for idx, res := range winPoSts {
				tRes := res
				rcd := recorder.Sub(res.addr, height)
				rcd.Record(ctx, recorder.Records{"selectMessage": tSelMsg.Sub(res.timetable.tProof).String()})

				var b *sharedTypes.BlockMsg
				if msgs != nil && len(msgs) > idx {
					b, err = m.createBlock(ctx, base, tRes.addr, tRes.waddr, tRes.ticket, tRes.winner, tRes.bvals, tRes.postProof, msgs[idx])
				} else {
					b, err = m.createBlock(ctx, base, tRes.addr, tRes.waddr, tRes.ticket, tRes.winner, tRes.bvals, tRes.postProof, []*sharedTypes.SignedMessage{})
				}
				if err != nil {
					log.Errorf("failed to create block: %s", err)
					rcd.Record(ctx, recorder.Records{"error": fmt.Sprintf("failed to create block: %s", err), "end": build.Clock.Now().String()})
					continue
				}
				blks = append(blks, b)

				tCreateBlock := build.Clock.Now()
				dur := tCreateBlock.Sub(tRes.timetable.tStart)
				parentMiners := make([]address.Address, len(base.TipSet.Blocks()))
				for i, header := range base.TipSet.Blocks() {
					parentMiners[i] = header.Miner
				}
				log.Infow("mined new block", "cid", b.Cid(), "height", b.Header.Height, "miner", b.Header.Miner, "parents", parentMiners, "wincount", b.Header.ElectionProof.WinCount, "weight", b.Header.ParentWeight, "took", dur)
				log.Infow("mining time consuming",
					"miner", tRes.addr,
					"tMinerBaseInfo", tRes.timetable.tMBI.Sub(tRes.timetable.tStart),
					"tTicket", tRes.timetable.tTicket.Sub(tRes.timetable.tMBI),
					"tIsWinner", tRes.timetable.tIsWinner.Sub(tRes.timetable.tTicket),
					"tSeed", tRes.timetable.tSeed.Sub(tRes.timetable.tIsWinner),
					"tProof", tRes.timetable.tProof.Sub(tRes.timetable.tSeed),
					"tSelMsg", tSelMsg.Sub(tRes.timetable.tProof),
					"tCreateBlock", tCreateBlock.Sub(tSelMsg))

				m.journal.RecordEvent(m.evtTypes[evtTypeBlockMined], func() interface{} {
					return map[string]interface{}{
						"parents":   base.TipSet.Cids(),
						"nulls":     base.NullRounds,
						"epoch":     b.Header.Height,
						"timestamp": b.Header.Timestamp,
						"cid":       b.Header.Cid(),
						"miner":     b.Header.Miner,
					}
				})

				rcd.Record(ctx, recorder.Records{"createBlock": tCreateBlock.Sub(tSelMsg).String(), "end": build.Clock.Now().String()})
			}

			if len(blks) > 0 {
				btime := time.Unix(int64(base.TipSet.MinTimestamp()+m.networkParams.BlockDelaySecs*(uint64(base.NullRounds)+1)), 0)
				now := build.Clock.Now()
				switch {
				case btime == now:
					// block timestamp is perfectly aligned with time.
				case btime.After(now):
					if !m.niceSleep(build.Clock.Until(btime)) {
						log.Warnf("received interrupt while waiting to broadcast block, will shutdown after block is sent out")
						build.Clock.Sleep(build.Clock.Until(btime))
					}
				default:
					if now.Sub(btime) > time.Duration(m.PropagationDelaySecs)*time.Second {
						log.Warnw("mined block in the past",
							"block-time", btime, "time", build.Clock.Now(), "difference", build.Clock.Since(btime))
					}
				}

				// broadcast all blocks
				for _, b := range blks {
					go m.broadCastBlock(ctx, *base, b) //copy base to avoid data race
				}
			}
		} else {
			log.Info("no block and increase nullround")
		}

		// Wait until the next epoch, plus the propagation delay, so a new tipset
		// has enough time to form.
		m.untilNextEpoch(base)

		if len(winPoSts) == 0 {
			base.NullRounds++
		}

		go m.tryGetBeacon(ctx, *base)
	}
}

func (m *Miner) tryGetBeacon(ctx context.Context, base MiningBase) {
	delay := 3
	next := time.Unix(int64(base.TipSet.MinTimestamp()+m.networkParams.BlockDelaySecs*uint64(base.NullRounds+1))+int64(delay), 0)

	select {
	case <-build.Clock.After(build.Clock.Until(next)):
		head, err := m.api.ChainHead(ctx)
		if err != nil {
			log.Infof("got head failed: %v", err)
			return
		}

		round := head.Height() + base.NullRounds + 1
		nodes := m.submitNodes

		log.Infof("try get beacon at: %d", round)

		call := func(api v1api.FullNode) {
			start := time.Now()
			// Nodes will cache beacons to avoid slow beacon acquisition
			if _, err = api.StateGetBeaconEntry(ctx, round); err != nil {
				log.Infof("got beacon failed: %v", err)
				return
			}
			took := time.Since(start)
			if took > time.Second*6 {
				log.Infof("got beacon slow: %v", took)
			}
		}

		go call(m.api)

		for _, node := range nodes {
			api, closer, err := client.NewFullNodeRPC(ctx, node)
			if err != nil {
				log.Warnf("new node rpc failed: %v", err)
				continue
			}
			go func() {
				defer closer()

				call(api)
			}()
		}
	case <-ctx.Done():
	}
}

func (m *Miner) submitBlock(ctx context.Context, bm *sharedTypes.BlockMsg, apiInfo *config.APIInfo) error {
	submitAPI, closer, err := client.NewFullNodeRPC(ctx, apiInfo)
	if err != nil {
		return fmt.Errorf("conn to submit-node %v failed: %w", apiInfo.Addr, err)
	}
	defer closer()

	return submitAPI.SyncSubmitBlock(ctx, bm)
}

func (m *Miner) broadCastBlock(ctx context.Context, base MiningBase, bm *sharedTypes.BlockMsg) {
	var err error
	if exists, err := m.sf.HasBlock(ctx, bm.Header); err != nil {
		log.Errorf("<!!> SLASH FILTER ERROR: %s", err)
		return
	} else if exists {
		log.Error("created a block at the same height as another block we've created")
		return
	}

	if err := m.sf.MinedBlock(ctx, bm.Header, base.TipSet.Height()); err != nil {
		log.Errorf("<!!> SLASH FILTER ERROR: %s", err)
		if err = m.sf.PutBlock(ctx, bm.Header, base.TipSet.Height(), time.Time{}, types.Error); err != nil {
			log.Errorf("failed to put block: %s", err)
		}

		mtsMineBlockFailCtx, _ := tag.New(
			ctx,
			tag.Upsert(metrics.MinerID, bm.Header.Miner.String()),
		)
		stats.Record(mtsMineBlockFailCtx, metrics.NumberOfMiningError.M(1))
		return
	}

	if err := m.api.SyncSubmitBlock(ctx, bm); err != nil {
		log.Warnf("failed to submit newly mined block: %s, will try to broadcast to other nodes", err)

		bSubmitted := false
		for _, sn := range m.submitNodes {
			err := m.submitBlock(ctx, bm, sn)
			if err == nil {
				bSubmitted = true
				break
			}
		}

		if !bSubmitted {
			log.Error("try to submit blocks to all nodes failed")
			if err = m.sf.PutBlock(ctx, bm.Header, base.TipSet.Height()+base.NullRounds, time.Time{}, types.Error); err != nil {
				log.Errorf("failed to put block: %s", err)
			}
			return
		}
	}

	// metrics: blocks
	metricsCtx, _ := tag.New(
		m.metricsCtx,
		tag.Upsert(metrics.MinerID, bm.Header.Miner.String()),
	)
	stats.Record(metricsCtx, metrics.NumberOfBlock.M(1))

	if err = m.sf.PutBlock(ctx, bm.Header, base.TipSet.Height()+base.NullRounds, time.Time{}, types.Success); err != nil {
		log.Errorf("failed to put block: %s", err)
	}
}

func (m *Miner) getLatestBase(ctx context.Context) (*MiningBase, time.Duration, error) {
	var base *MiningBase
	var onDone func(bool, abi.ChainEpoch, error)
	var injectNulls abi.ChainEpoch

	// overlapCount is used to avoid getting stuck in an endless loop
	overlapCount := 0

	for {
		prebase, err := m.GetBestMiningCandidate(ctx)
		if err != nil {
			return nil, time.Second * 5, fmt.Errorf("get best mining candidate: %w", err)
		}

		if base != nil {
			if base.TipSet.Height() == prebase.TipSet.Height() && base.NullRounds == prebase.NullRounds {
				base = prebase
				break
			} else {
				if overlapCount >= 5 {
					log.Warnf("wait to long (about %d epochs) to get mining base, please check your config of PropagationDelaySecs and network", base.TipSet.Height()+base.NullRounds-prebase.TipSet.Height()+prebase.NullRounds)
					overlapCount = 0
				} else {
					overlapCount++
				}
			}
		}

		if base != nil {
			onDone(false, 0, nil)
		}

		// TODO: need to change the orchestration here. the problem is that
		// we are waiting *after* we enter this loop and selecta mining
		// candidate, which is almost certain to change in multiminer
		// tests. Instead, we should block before entering the loop, so
		// that when the test 'MineOne' function is triggered, we pull our
		// best mining candidate at that time.

		// Wait until propagation delay period after block we plan to mine on
		onDone, injectNulls, err = m.waitFunc(ctx, prebase.TipSet.MinTimestamp())
		if err != nil {
			log.Error(err)
			continue
		}

		start := time.Now()
		// just wait for the beacon entry to become available before we select our final mining base
		_, err = m.api.StateGetBeaconEntry(ctx, prebase.TipSet.Height()+prebase.NullRounds+1)
		if err != nil {
			return nil, time.Second, fmt.Errorf("getting beacon entry: %w", err)
		}
		took := time.Since(start)
		if took > time.Second*3 {
			log.Infof("got beacon slow: %v", took)
		}

		base = prebase
	}

	base.NullRounds += injectNulls // testing

	return base, 0, nil
}

func (m *Miner) mineOneForAll(ctx context.Context, base *MiningBase) []*winPoStRes {
	m.lkWPP.Lock()
	defer m.lkWPP.Unlock()

	var (
		winPoSts  []*winPoStRes
		wg        sync.WaitGroup
		winPoStLk sync.Mutex
	)

	for addr, mining := range m.minerWPPMap {
		wg.Add(1)
		tMining := mining
		tAddr := addr
		height := base.TipSet.Height() + base.NullRounds + 1

		rcd := recorder.Sub(tAddr, height)

		go func() {
			defer wg.Done()
			defer func() {
				rcd.Record(ctx, recorder.Records{"end": build.Clock.Now().String()})
			}()

			// set timeout for miner once
			tCtx, tCtxCancel := context.WithTimeout(ctx, m.MinerOnceTimeout)
			defer tCtxCancel()

			resChan := m.mineOne(tCtx, base, tMining.account, tAddr, tMining.epp)

			// waiting for mining results
			select {
			case <-tCtx.Done():
				log.Errorf("mining timeout for %s", tAddr.String())

				// Timeout may not be the winner when it happens
				if err := m.sf.PutBlock(ctx, &sharedTypes.BlockHeader{
					Height: height,
					Miner:  tAddr,
				}, base.TipSet.Height()+base.NullRounds, time.Time{}, types.Timeout); err != nil {
					log.Errorf("failed to record mining timeout: %s", err)
				}

				ctx, _ = tag.New(
					ctx,
					tag.Upsert(metrics.MinerID, tAddr.String()),
				)
				stats.Record(ctx, metrics.NumberOfMiningTimeout.M(1))

				if len(tMining.err) >= DefaultMaxErrCounts {
					tMining.err = tMining.err[:DefaultMaxErrCounts-2]
				}
				tMining.err = append(tMining.err, time.Now().Format("2006-01-02 15:04:05 ")+"mining timeout!")
				rcd.Record(ctx, recorder.Records{"error": "mining timeout!", "end": time.Now().String()})
				return
			case res := <-resChan:
				if res != nil {
					if res.err != nil {
						if res.winner != nil {
							// record to db only use mysql
							if err := m.sf.PutBlock(ctx, &sharedTypes.BlockHeader{
								Height: base.TipSet.Height() + base.NullRounds + 1,
								Miner:  tAddr,
							}, base.TipSet.Height()+base.NullRounds, time.Time{}, types.Error); err != nil {
								log.Errorf("failed to record winner: %s", err)
							}

							ctx, _ = tag.New(
								ctx,
								tag.Upsert(metrics.MinerID, tAddr.String()),
							)
							stats.Record(ctx, metrics.NumberOfMiningError.M(1))
						}
						if len(tMining.err) > DefaultMaxErrCounts {
							tMining.err = tMining.err[:DefaultMaxErrCounts-2]
						}
						tMining.err = append(tMining.err, time.Now().Format("2006-01-02 15:04:05 ")+res.err.Error())
						rcd.Record(ctx, recorder.Records{"error": res.err.Error()})
						log.Errorf("failed to mined block, miner %s, height: %d, error %v", tAddr.String(), height, res.err)
					} else if res.winner != nil {
						winPoStLk.Lock()
						winPoSts = append(winPoSts, res) //nolint:staticcheck
						winPoStLk.Unlock()
					}
				}
			}
		}()
	}

	wg.Wait()

	return winPoSts
}

func (m *Miner) untilNextEpoch(base *MiningBase) {
	nextRound := time.Unix(int64(base.TipSet.MinTimestamp()+m.networkParams.BlockDelaySecs*uint64(base.NullRounds+1))+int64(m.PropagationDelaySecs), 0)

	select {
	case <-build.Clock.After(build.Clock.Until(nextRound)):
	case <-m.stop:
	}
}

// MiningBase is the tipset on top of which we plan to construct our next block.
type MiningBase struct {
	TipSet     *sharedTypes.TipSet
	NullRounds abi.ChainEpoch
}

// GetBestMiningCandidate implements the fork choice rule from a miner's
// perspective.
//
// It obtains the current chain head (HEAD), and compares it to the last tipset
// we selected as our mining base (LAST). If HEAD's weight is larger than
// LAST's weight, it selects HEAD to build on. Else, it selects LAST.
func (m *Miner) GetBestMiningCandidate(ctx context.Context) (*MiningBase, error) {
	m.lk.Lock()
	defer m.lk.Unlock()

	bts, err := m.api.ChainHead(ctx)
	if err != nil {
		return nil, err
	}

	if m.lastWork == nil || !m.lastWork.TipSet.Equals(bts) {
		m.lastWork = &MiningBase{TipSet: bts}
	}

	return m.lastWork, nil
}

type miningTimetable struct {
	tStart, tMBI, tTicket, tIsWinner, tSeed, tProof time.Time
}

type winPoStRes struct {
	addr      address.Address
	waddr     address.Address
	ticket    *sharedTypes.Ticket
	winner    *sharedTypes.ElectionProof
	bvals     []sharedTypes.BeaconEntry
	postProof []proof2.PoStProof
	dur       time.Duration
	timetable miningTimetable
	err       error
}

// mineOne attempts to mine a single block, and does so synchronously, if and
// only if we are eligible to mine.
//
// {hint/landmark}: This method coordinates all the steps involved in mining a
// block, including the condition of whether mine or not at all depending on
// whether we win the round or not.
//
// This method does the following:
//
//	1.
func (m *Miner) mineOne(ctx context.Context, base *MiningBase, account string, addr address.Address, epp WinningPoStProver) <-chan *winPoStRes {
	ctx, _ = tag.New(ctx, tag.Upsert(metrics.MinerID, addr.String()))
	log.Infow("attempting to mine a block", "tipset", types.LogCids(base.TipSet.Cids()), "miner", addr)
	start := build.Clock.Now()

	round := base.TipSet.Height() + base.NullRounds + 1
	out := make(chan *winPoStRes)

	isLate := uint64(start.Unix()) > (base.TipSet.MinTimestamp() + uint64(base.NullRounds*builtin.EpochDurationSeconds) + m.PropagationDelaySecs)

	rcd := recorder.Sub(addr, round)
	rcd.Record(ctx, recorder.Records{"start": start.String(), "baseEpoch": base.TipSet.Height().String(), "nullRounds": base.NullRounds.String(), "baseDelta": start.Sub(time.Unix(int64(base.TipSet.MinTimestamp()), 0)).String()})

	go func() {
		res := &winPoStRes{addr: addr}

		// GetBaseInfo
		stopCountGetBaseInfo := metrics.GetBaseInfoDuration.Start()
		mbi, err := m.api.MinerGetBaseInfo(ctx, addr, round, base.TipSet.Key())
		if err != nil {
			log.Errorf("failed to get mining base info: %s, miner: %s", err, addr)
			res.err = err
			out <- res
			return
		}
		if mbi == nil {
			log.Infow("get nil MinerGetBaseInfo", "miner", addr)
			rcd.Record(ctx, recorder.Records{"info": "get nil MinerGetBaseInfo"})
			out <- res
			return
		}

		rcd.Record(ctx, recorder.Records{
			"worker":       mbi.WorkerKey.String(),
			"minerPower":   mbi.MinerPower.String(),
			"networkPower": mbi.NetworkPower.String(),
			"isEligible":   fmt.Sprintf("%t", mbi.EligibleForMining),
			"lateStart":    fmt.Sprintf("%t", isLate),
		})

		res.waddr = mbi.WorkerKey

		if !mbi.EligibleForMining {
			// slashed or just have no power yet
			log.Warnw("slashed or just have no power yet", "miner", addr)
			out <- res
			return
		}

		tMBI := build.Clock.Now()
		stopCountGetBaseInfo(ctx)
		log.Infow("mine one", "miner", addr, "get base info", tMBI.Sub(start))

		stopCountForComputeTicket := metrics.ComputeTicketDuration.Start()

		beaconPrev := mbi.PrevBeaconEntry
		bvals := mbi.BeaconEntries

		log.Infof("Time delta between now and our mining base: %ds (nulls: %d), miner: %s", uint64(build.Clock.Now().Unix())-base.TipSet.MinTimestamp(), base.NullRounds, addr)

		rbase := beaconPrev
		if len(bvals) > 0 {
			rbase = bvals[len(bvals)-1]
		}
		res.bvals = bvals

		rcd.Record(ctx, recorder.Records{"getBaseInfo": tMBI.Sub(start).String(), "beaconEpoch": fmt.Sprint(rbase.Round)})

		ticket, err := m.computeTicket(ctx, &rbase, round, base.TipSet.MinTicket(), mbi, addr)
		if err != nil {
			log.Errorf("scratching ticket for %s failed: %s", addr, err.Error())
			res.err = err
			out <- res
			return
		}

		tTicket := build.Clock.Now()
		log.Infow("mine one", "miner", addr, "compute ticket", tTicket.Sub(tMBI))
		rcd.Record(ctx, recorder.Records{"computeTicket": tTicket.Sub(tMBI).String()})

		res.ticket = ticket
		stopCountForComputeTicket(ctx)

		stopCountForCheckRoundWinner := metrics.CheckRoundWinnerDuration.Start()
		val, ok := m.minerWPPMap[addr]
		if !ok {
			log.Errorf("[%v] not exist", addr)
			res.err = fmt.Errorf("miner : %s not exist", addr)
			out <- res
			return
		}
		winner, err := IsRoundWinner(ctx, round, val.account, addr, rbase, mbi, m.signerFunc(ctx, m.gatewayNode))
		if err != nil {
			log.Errorf("failed to check for %s if we win next round: %s", addr, err)
			res.err = err
			out <- res
			return
		}

		if winner == nil {
			log.Infow("not to be winner", "miner", addr)
			rcd.Record(ctx, recorder.Records{"info": "not to be winner"})
			out <- res
			return
		}

		res.winner = winner

		tIsWinner := build.Clock.Now()
		log.Infow("mine one", "miner", addr, "is winner", tIsWinner.Sub(tTicket), "win count", winner.WinCount)
		stopCountForCheckRoundWinner(ctx)
		rcd.Record(ctx, recorder.Records{"computeElectionProof": tIsWinner.Sub(tTicket).String(), "winCount": fmt.Sprintf("%d", winner.WinCount)})

		// metrics: wins
		metricsCtx, _ := tag.New(
			m.metricsCtx,
			tag.Upsert(metrics.MinerID, addr.String()),
		)
		stats.Record(metricsCtx, metrics.NumberOfIsRoundWinner.M(1))
		// record to db only use mysql
		if err := m.sf.PutBlock(ctx, &sharedTypes.BlockHeader{
			Height:  base.TipSet.Height() + base.NullRounds + 1,
			Miner:   addr,
			Parents: base.TipSet.Key().Cids(),
		}, base.TipSet.Height()+base.NullRounds, time.Now(), types.Mining); err != nil {
			log.Errorf("failed to record winner: %s", err)
		}

		buf := new(bytes.Buffer)
		if err := addr.MarshalCBOR(buf); err != nil {
			res.err = fmt.Errorf("failed to marshal miner address: %s", err)
			log.Error(res.err)
			out <- res
			return
		}

		stopCountForComputeProof := metrics.ComputeProofDuration.Start()
		defer func() {
			stopCountForComputeProof(ctx)
		}()

		r, err := DrawRandomness(rbase.Data, crypto.DomainSeparationTag_WinningPoStChallengeSeed, round, buf.Bytes())
		if err != nil {
			res.err = fmt.Errorf("failed to get randomness for winning post: %s, miner: %s", err, addr)
			log.Error(res.err)
			out <- res
			return
		}
		prand := abi.PoStRandomness(r)

		tSeed := build.Clock.Now()
		log.Infow("mine one", "miner", addr, "seed", tSeed.Sub(tIsWinner))
		rcd.Record(ctx, recorder.Records{"seed": tSeed.Sub(tIsWinner).String()})

		nv, err := m.api.StateNetworkVersion(ctx, base.TipSet.Key())
		if err != nil {
			res.err = fmt.Errorf("failed to get network version: %s, miner: %s", err, addr)
			log.Error(res.err)
			out <- res
			return
		}

		postProof, err := epp.ComputeProof(ctx, mbi.Sectors, prand, round, nv)
		if err != nil {
			res.err = fmt.Errorf("failed to compute winning post proof: %s, miner: %s", err, addr)
			log.Error(res.err)
			out <- res
			return
		}

		res.postProof = postProof

		tProof := build.Clock.Now()
		log.Infow("mine one", "miner", addr, "compute proof", tProof.Sub(tSeed))
		rcd.Record(ctx, recorder.Records{"computePostProof": tProof.Sub(tSeed).String()})

		dur := build.Clock.Now().Sub(start)
		tt := miningTimetable{
			tStart: start, tMBI: tMBI, tTicket: tTicket, tIsWinner: tIsWinner, tSeed: tSeed, tProof: tProof,
		}
		res.dur = dur
		res.timetable = tt

		out <- res
		log.Infow("mined new block ( -> Proof)", "took", dur, "miner", addr)
	}()

	return out
}

func (m *Miner) computeTicket(ctx context.Context,
	brand *sharedTypes.BeaconEntry,
	round abi.ChainEpoch,
	chainRand *sharedTypes.Ticket,
	mbi *sharedTypes.MiningBaseInfo,
	addr address.Address,
) (*sharedTypes.Ticket, error) {
	buf := new(bytes.Buffer)
	if err := addr.MarshalCBOR(buf); err != nil {
		return nil, fmt.Errorf("failed to marshal address to cbor: %w", err)
	}

	if round > m.networkParams.ForkUpgradeParams.UpgradeSmokeHeight {
		buf.Write(chainRand.VRFProof)
	}

	input := new(bytes.Buffer)
	drp := &wallet.DrawRandomParams{
		Rbase:   brand.Data,
		Pers:    crypto.DomainSeparationTag_TicketProduction,
		Round:   round - constants.TicketRandomnessLookback,
		Entropy: buf.Bytes(),
	}
	err := drp.MarshalCBOR(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal randomness: %w", err)
	}
	//input, err := chain.DrawRandomness(brand.Data, crypto.DomainSeparationTag_TicketProduction, round-constants.TicketRandomnessLookback, buf.Bytes())
	//if err != nil {
	//	return nil, err
	//}

	val, ok := m.minerWPPMap[addr]
	if !ok {
		log.Errorf("[%v] not exist", addr)
		return nil, fmt.Errorf("miner %s not exist", addr)
	}

	vrfOut, err := ComputeVRF(ctx, m.signerFunc(ctx, m.gatewayNode), val.account, mbi.WorkerKey, input.Bytes())
	if err != nil {
		return nil, err
	}

	return &sharedTypes.Ticket{
		VRFProof: vrfOut,
	}, nil
}

func (m *Miner) createBlock(ctx context.Context, base *MiningBase, addr, waddr address.Address, ticket *sharedTypes.Ticket,
	eproof *sharedTypes.ElectionProof, bvals []sharedTypes.BeaconEntry, wpostProof []proof2.PoStProof, msgs []*sharedTypes.SignedMessage) (*sharedTypes.BlockMsg, error) {
	tStart := build.Clock.Now()

	uts := base.TipSet.MinTimestamp() + m.networkParams.BlockDelaySecs*(uint64(base.NullRounds)+1)

	nheight := base.TipSet.Height() + base.NullRounds + 1

	// why even return this? that api call could just submit it for us
	blockMsg, err := m.api.MinerCreateBlock(context.TODO(), &sharedTypes.BlockTemplate{
		Miner:            addr,
		Parents:          base.TipSet.Key(),
		Ticket:           ticket,
		Eproof:           eproof,
		BeaconValues:     bvals,
		Messages:         msgs,
		Epoch:            nheight,
		Timestamp:        uts,
		WinningPoStProof: wpostProof,
	})

	if err != nil {
		return blockMsg, err
	}

	tCreateBlock := build.Clock.Now()

	// block signature check
	if blockMsg.Header.BlockSig == nil {
		m.lkWPP.Lock()
		val, ok := m.minerWPPMap[addr]
		m.lkWPP.Unlock()
		if !ok {
			log.Errorf("[%v] not exist", addr)
			return nil, fmt.Errorf("miner %s not exist", addr)
		}

		nosigbytes, err := blockMsg.Header.SignatureData()
		if err != nil {
			return nil, fmt.Errorf("failed to get SigningBytes: %v", err)
		}

		sig, err := m.signerFunc(ctx, m.gatewayNode)(ctx, waddr, []string{val.account}, nosigbytes, sharedTypes.MsgMeta{
			Type: sharedTypes.MTBlock,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to sign new block: %v", err)
		}
		blockMsg.Header.BlockSig = sig
	}

	tBlockSign := build.Clock.Now()
	log.Infow("create block time consuming",
		"miner", addr,
		"tMinerCreateBlockAPI", tCreateBlock.Sub(tStart),
		"tBlockSIgn", tBlockSign.Sub(tCreateBlock),
	)

	return blockMsg, err
}

func (m *Miner) SyncStatus(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Minute)

	log.Info("check sync start ...")
	for {
		select {
		case <-ticker.C:
			{
				for {
					state, err := m.api.SyncState(ctx)
					if err != nil {
						m.st = syncStatus{heightDiff: -1, err: err}
						break
					}

					if len(state.ActiveSyncs) == 0 {
						time.Sleep(time.Second)
						continue
					}

					head, err := m.api.ChainHead(ctx)
					if err != nil {
						m.st = syncStatus{heightDiff: -1, err: err}
						break
					}

					working := -1
					for i, ss := range state.ActiveSyncs {
						switch ss.Stage {
						case sharedTypes.StageSyncComplete:
						default:
							working = i
						case sharedTypes.StageIdle:
							// not complete, not actively working
						}
					}

					if working == -1 {
						working = len(state.ActiveSyncs) - 1
					}

					ss := state.ActiveSyncs[working]
					var heightDiff int64 = -1
					if ss.Target != nil {
						heightDiff = int64(ss.Target.Height() - head.Height())
					}

					if time.Now().Unix()-int64(head.MinTimestamp()) < int64(m.networkParams.BlockDelaySecs) {
						heightDiff = 0
					}
					m.st = syncStatus{heightDiff: heightDiff}
					break
				}
			}
		case <-ctx.Done():
			log.Info("check sync exit ...")
			return
		}
	}
}

func (m *Miner) QueryRecord(ctx context.Context, params *types.QueryRecordParams) ([]map[string]string, error) {
	return recorder.Query(ctx, params.Miner, params.Epoch, params.Limit)
}
