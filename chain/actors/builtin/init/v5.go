package init

import (
	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/ipfs/go-cid"
	cbg "github.com/whyrusleeping/cbor-gen"
	"golang.org/x/xerrors"

	"github.com/filecoin-project/venus-miner/node/modules/dtypes"
	"github.com/filecoin-project/venus-miner/chain/actors/adt"

	builtin5 "github.com/filecoin-project/specs-actors/v5/actors/builtin"

	init5 "github.com/filecoin-project/specs-actors/v5/actors/builtin/init"
	adt5 "github.com/filecoin-project/specs-actors/v5/actors/util/adt"
)

var _ State = (*state5)(nil)

func load5(store adt.Store, root cid.Cid) (State, error) {
	out := state5{store: store}
	err := store.Get(store.Context(), root, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

type state5 struct {
	init5.State
	store adt.Store
}

func (s *state5) ResolveAddress(address address.Address) (address.Address, bool, error) {
	return s.State.ResolveAddress(s.store, address)
}

func (s *state5) MapAddressToNewID(address address.Address) (address.Address, error) {
	return s.State.MapAddressToNewID(s.store, address)
}

func (s *state5) ForEachActor(cb func(id abi.ActorID, address address.Address) error) error {
	addrs, err := adt5.AsMap(s.store, s.State.AddressMap, builtin5.DefaultHamtBitwidth)
	if err != nil {
		return err
	}
	var actorID cbg.CborInt
	return addrs.ForEach(&actorID, func(key string) error {
		addr, err := address.NewFromBytes([]byte(key))
		if err != nil {
			return err
		}
		return cb(abi.ActorID(actorID), addr)
	})
}

func (s *state5) NetworkName() (dtypes.NetworkName, error) {
	return dtypes.NetworkName(s.State.NetworkName), nil
}

func (s *state5) SetNetworkName(name string) error {
	s.State.NetworkName = name
	return nil
}

func (s *state5) Remove(addrs ...address.Address) (err error) {
	m, err := adt5.AsMap(s.store, s.State.AddressMap, builtin5.DefaultHamtBitwidth)
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		if err = m.Delete(abi.AddrKey(addr)); err != nil {
			return xerrors.Errorf("failed to delete entry for address: %s; err: %w", addr, err)
		}
	}
	amr, err := m.Root()
	if err != nil {
		return xerrors.Errorf("failed to get address map root: %w", err)
	}
	s.State.AddressMap = amr
	return nil
}

func (s *state5) addressMap() (adt.Map, error) {
	return adt5.AsMap(s.store, s.AddressMap, builtin5.DefaultHamtBitwidth)
}