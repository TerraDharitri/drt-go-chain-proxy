package factory

import (
	"github.com/TerraDharitri/drt-go-chain-proxy/data"
)

// ApiConfigParser defines the actions that an api config parser should be able to do
type ApiConfigParser interface {
	GetConfigForVersion(version string) (*data.ApiRoutesConfig, error)
}
