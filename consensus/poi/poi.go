package poi

import (
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/crypto/sha3"
)

type PoI struct {
	config *params.PoIConfig // Consensus engine configuration parameters
	db     ethdb.Database    // Database to store and retrieve snapshot checkpoints
}

// New creates a PoI proof-of-authority consensus engine with the initial
// signers set to the ones provided by the user.
func New(config *params.PoIConfig, db ethdb.Database) *PoI {
	// Set any missing consensus parameters to their defaults
	conf := *config
	if conf.NumberOfRobots == 0 {
		conf.NumberOfRobots = 10
	}

	return &PoI{
		config: &conf,
		db:     db,
	}
}

// Author implements consensus.Engine, returning the header's coinbase as the
// proof-of-work verified author of the block.
func (poi *PoI) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

func (poi *PoI) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {

	log.Info("will verifyHeader")

	return nil

}
func (poi *PoI) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {

	log.Info("will verifyHeaders")

	abort := make(chan struct{})

	results := make(chan error, len(headers))
	go func() {

		for _, header := range headers {

			err := poi.VerifyHeader(chain, header, false)

			select {

			case <-abort:

				return

			case results <- err:

			}

		}

	}()

	return abort, results

}
func (poi *PoI) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {

	log.Info("will verfiy uncles")

	return nil

}
func (poi *PoI) VerifySeal(chain consensus.ChainReader, header *types.Header) error {

	log.Info("will verfiy VerifySeal")

	return nil

}
func (poi *PoI) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {

	log.Info("will prepare the block")

	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)

	if parent == nil {

		return consensus.ErrUnknownAncestor

	}
	header.Difficulty = poi.CalcDifficulty(chain, header.Time, parent)

	return nil

}
func (poi *PoI) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {

	return parent.Difficulty

}

func (poi *PoI) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,

	uncles []*types.Header) {

	log.Info("will Finalize the block")

	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))

}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
// nor block rewards given, and returns the final block.
func (poi *PoI) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// Finalize block
	poi.Finalize(chain, header, state, txs, uncles)

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil)), nil
}

func (poi *PoI) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {

	log.Info("will Seal the block")

	//time.Sleep(15 * time.Second)

	header := block.Header()

	go func() {
		select {
		case results <- block.WithSeal(header):
		case <-stop:
			return
		default:
			log.Warn("Sealing result is not read by miner", "sealhash", SealHash(header))
		}
	}()

	return nil
}

// SealHash returns the hash of a block prior to it being sealed.
func (poi *PoI) SealHash(header *types.Header) (hash common.Hash) {
	return SealHash(header)
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header)
	hasher.(crypto.KeccakState).Read(hash[:])
	return hash
}

func encodeSigHeader(w io.Writer, header *types.Header) {
	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra,
		header.MixDigest,
		header.Nonce,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	if err := rlp.Encode(w, enc); err != nil {
		panic("can't encode: " + err.Error())
	}
}

// APIs implements consensus.Engine, returning the user facing RPC APIs.
func (poi *PoI) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{{
		Namespace: "proof-of-identity",
		Version:   "1.0",
		Service:   &API{poi},
		Public:    false,
	}}
}

// Close implements consensus.Engine. It's a noop for clique as there are no background threads.
func (poi *PoI) Close() error {
	return nil
}
