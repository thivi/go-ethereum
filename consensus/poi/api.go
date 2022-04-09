package poi

import (
	"github.com/ethereum/go-ethereum/log"
)

type API struct {
	poi *PoI
}

func (api *API) Echo(text string) {
	log.Info(text)
}
