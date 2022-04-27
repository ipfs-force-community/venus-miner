package main

import (
	"fmt"

	builtinactors "github.com/filecoin-project/venus/venus-shared/builtin-actors"

	"golang.org/x/xerrors"

	logging "github.com/ipfs/go-log/v2"
	"github.com/urfave/cli/v2"

	"github.com/filecoin-project/venus-miner/build"
	lcli "github.com/filecoin-project/venus-miner/cli"
	"github.com/filecoin-project/venus-miner/lib/blockstore"
	"github.com/filecoin-project/venus-miner/lib/venuslog"
	"github.com/filecoin-project/venus-miner/node/config"
	"github.com/filecoin-project/venus-miner/node/repo"
	"github.com/filecoin-project/venus/venus-shared/actors"
	"github.com/filecoin-project/venus/venus-shared/types"
)

var log = logging.Logger("main")

const FlagMinerRepo = "miner-repo"

// TODO remove after deprecation period
const FlagMinerRepoDeprecation = "storagerepo"

func main() {
	venuslog.SetupLogLevels()

	local := []*cli.Command{
		initCmd,
		runCmd,
		stopCmd,
		addressCmd,
		winnerCmd,
		configCmd,
	}

	for _, cmd := range local {
		cmd := cmd
		originBefore := cmd.Before
		cmd.Before = func(cctx *cli.Context) error {
			if originBefore != nil {
				if err := originBefore(cctx); err != nil {
					return err
				}
			}
			return loadActorsWithCmdBefore(cctx)
		}
	}

	app := &cli.App{
		Name:                 "venus-miner",
		Usage:                "Filecoin decentralized storage network miner",
		Version:              build.UserVersion(),
		EnableBashCompletion: true,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name: "color",
			},
			&cli.StringFlag{
				Name:    FlagMinerRepo,
				Aliases: []string{FlagMinerRepoDeprecation},
				EnvVars: []string{"VENUS_MINER_PATH"},
				Value:   "~/.venusminer", // TODO: Consider XDG_DATA_HOME
				Usage:   fmt.Sprintf("Specify miner repo path. flag(%s) and env(VENUS_MINER_PATH) are DEPRECATION, will REMOVE SOON", FlagMinerRepoDeprecation),
			},
		},

		Commands: append(local, lcli.CommonCommands...),
	}
	app.Setup()
	app.Metadata["repoType"] = repo.Miner

	lcli.RunApp(app)
}

var loadActorsWithCmdBefore = func(cctx *cli.Context) error {
	networkName := types.NetworkName(cctx.String("nettype"))
	if len(networkName) == 0 && cctx.Command.Name != "init" {
		defCfg := config.DefaultMinerConfig()
		currCfg, err := config.FromFile(cctx.String(FlagMinerRepo), defCfg)
		if err != nil {
			return err
		}
		cfg := currCfg.(*config.MinerConfig)

		fullNodeAPI, closer, err := lcli.GetFullNodeAPIV1(cctx, cfg.FullNode)
		if err != nil {
			return err
		}
		defer closer()

		networkName, err = fullNodeAPI.StateNetworkName(cctx.Context)
		if err != nil {
			return err
		}
	}

	nt, err := networkNameToNetworkType(networkName)
	if err != nil {
		return err
	}
	if err := builtinactors.SetActorsBundle(build.Actorsv7FS, build.Actorsv8FS, nt); err != nil {
		return err
	}

	// preload manifest so that we have the correct code CID inventory for cli since that doesn't
	// go through CI
	if len(builtinactors.BuiltinActorsV8Bundle()) > 0 {
		bs := blockstore.NewMemory()

		if err := actors.LoadManifestFromBundle(cctx.Context, bs, actors.Version8, builtinactors.BuiltinActorsV8Bundle()); err != nil {
			panic(fmt.Errorf("error loading actor manifest: %w", err))
		}
	}
	return nil
}

func networkNameToNetworkType(networkName types.NetworkName) (types.NetworkType, error) {
	switch networkName {
	case "":
		return types.NetworkDefault, xerrors.Errorf("network name is empty")
	case "mainnet":
		return types.NetworkMainnet, nil
	case "calibrationnet", "calibnet":
		return types.NetworkCalibnet, nil
	case "butterflynet", "butterfly":
		return types.NetworkButterfly, nil
	case "interopnet", "interop":
		return types.NetworkInterop, nil
	default:
		// include 2k force
		return types.Network2k, nil
	}
}
