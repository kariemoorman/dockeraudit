package scanner

import (
	"context"

	"github.com/kariemoorman/dockeraudit/internal/types"
)

// Scanner is the common interface implemented by all scan engines.
// Each implementation (ImageScanner, K8sScanner, TerraformScanner) accepts
// configuration via its constructor and then exposes a single Scan entry-point.
type Scanner interface {
	Scan(ctx context.Context) (*types.ScanResult, error)
}

// Compile-time interface satisfaction checks.
var (
	_ Scanner = (*DockerScanner)(nil)
	_ Scanner = (*ImageScanner)(nil)
	_ Scanner = (*K8sScanner)(nil)
	_ Scanner = (*TerraformScanner)(nil)
)
