package mock

import "github.com/TerraDharitri/drt-go-chain-proxy/data"

// TransactionCostHandlerStub -
type TransactionCostHandlerStub struct {
	RezolveCostRequestCalled func(tx *data.Transaction) (*data.TxCostResponseData, error)
}

// ResolveCostRequest -
func (tchs *TransactionCostHandlerStub) ResolveCostRequest(tx *data.Transaction) (*data.TxCostResponseData, error) {
	if tchs.RezolveCostRequestCalled != nil {
		return tchs.RezolveCostRequestCalled(tx)
	}

	return nil, nil
}
