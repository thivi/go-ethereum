package poi

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

type API struct {
	poi *PoI
}

func (api *API) GetSignature(coinbase string) {
	resp, err := http.Get("http://localhost:8080/getSignature/" + coinbase)
	if err != nil {
		panic(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	var sign SignatureResponse
	err = json.Unmarshal(body, &sign)

	if err != nil {
		panic(err)
	}

	signData, err := base64.StdEncoding.DecodeString(sign.Signature)

	if err != nil {
		panic(err)
	}

	api.poi.SetSignature(signData)
}
