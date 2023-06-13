package eciesgo

import (
	"crypto/elliptic"
)

func getCurve() elliptic.Curve {
	return elliptic.P521()
}
