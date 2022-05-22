package poi

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	gethCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/crypto/sha3"
)

type PoI struct {
	config    *params.PoIConfig // Consensus engine configuration parameters
	db        ethdb.Database    // Database to store and retrieve snapshot checkpoints
	signature []byte            //Signature of the account
	publicKey *rsa.PublicKey    //public key of the swarm controller
}

type PublicKeyResponse struct {
	PublicKey string `json:"publicKey"`
}

type SignatureResponse struct {
	Signature string `json:"signature"`
}

func decodePublicKey(key string) *rsa.PublicKey {
	r := strings.NewReader(key)
	pemBytes, err := ioutil.ReadAll(r)

	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		panic(errors.New("failed to decode PEM block containing the key"))
	}

	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key
	}

	panic(err)
}

func verifySign(signature []byte, coinbase string, publicKey *rsa.PublicKey) bool {
	log.Info(coinbase)
	msgHash := sha256.New()
	msgHash.Write([]byte(coinbase))
	msgHashSum := msgHash.Sum(nil)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, msgHashSum, signature) == nil
}

func getPublicKey(uri string) *rsa.PublicKey {
	resp, err := http.Get(uri + "/getPublicKey/")
	if err != nil {
		panic(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	var key PublicKeyResponse
	err = json.Unmarshal(body, &key)

	if err != nil {
		panic(err)
	}

	return decodePublicKey(key.PublicKey)
}

func (poi *PoI) SetSignature(signature []byte) {
	poi.signature = signature
}

// New creates a PoI proof-of-authority consensus engine with the initial
// signers set to the ones provided by the user.
func New(config *params.PoIConfig, db ethdb.Database) *PoI {
	// Set any missing consensus parameters to their defaults
	//log.Info("New PoI created")

	conf := *config
	if conf.NumberOfRobots == 0 {
		conf.NumberOfRobots = 10
	}

	return &PoI{
		config:    &conf,
		db:        db,
		publicKey: getPublicKey(config.SwarmControllerURI),
	}
}

// Author implements consensus.Engine, returning the header's coinbase as the
// proof-of-work verified author of the block.
func (poi *PoI) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

func (poi *PoI) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {

	//log.Info("Verifying Header")

	if !poi.VerifySignature(header) {
		return errors.New("signature verification failed")
	}

	log.Info("Signature Verified!")

	return nil
}
func (poi *PoI) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {

	//log.Info("Verifying Headers")

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

	//log.Info("Verifying Uncles")

	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}

	return nil
}
func (poi *PoI) VerifySignature(header *types.Header) bool {
	if verifySign(header.Extra, strings.ToLower((header.Coinbase.String())), poi.publicKey) {
		log.Info("Signature Verified!")
		return true
	}

	log.Error("Signature Verification Failed")
	return false
}
func (poi *PoI) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {

	//log.Info("Preparing the block")

	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)

	if parent == nil {

		return consensus.ErrUnknownAncestor

	}
	header.Difficulty = poi.CalcDifficulty(chain, header.Time, parent)
	if poi.signature == nil {
		log.Error("the miner has no signature")
	}
	header.Extra = poi.signature
	poi.calculateTime(chain, header)

	return nil
}

func (poi *PoI) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {

	return parent.Difficulty

}

func (poi *PoI) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,

	uncles []*types.Header) {

	//log.Info("Finalizing the block")

	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)

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

	//log.Info("Sealing the block")

	/* if len(block.Transactions()) == 0 {
		return errors.New("sealing paused while waiting for transactions")
	} */
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
	//log.Info("Sealing Hash")
	return SealHash(header)
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header)
	hasher.(gethCrypto.KeccakState).Read(hash[:])
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
		Namespace: "poi",
		Version:   "1.0",
		Service:   &API{poi},
		Public:    false,
	}}
}

func (poi *PoI) Close() error {
	log.Info("Closing PoI")
	return nil
}

func (poi *PoI) calculateTime(chain consensus.ChainHeaderReader, header *types.Header) {
	var offset uint64 = 0
	alpha := 0.8

	for i := poi.config.NumberOfRobots; i > 0; i-- {
		prevHeader := chain.GetHeaderByNumber(header.Number.Uint64() - uint64(i))
		if prevHeader == nil {
			break
		}
		if prevHeader.Coinbase == header.Coinbase {
			offset += (1 / i) * poi.config.NumberOfRobots
		}
	}

	randomOffset := rand.Int63n(int64(poi.config.NumberOfRobots))

	offsetTime := uint64((alpha * float64(offset)) + ((1 - alpha) * float64(randomOffset)))

	parent := chain.GetHeaderByNumber(header.Number.Uint64() - 1)

	var blockTime uint64 = 0
	if parent.Time >= uint64(time.Now().Unix())+offsetTime {
		blockTime = parent.Time + offsetTime
	} else {
		blockTime = uint64(time.Now().Unix()) + offsetTime
	}

	header.Time = blockTime
}
