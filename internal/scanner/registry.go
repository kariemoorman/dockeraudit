package scanner

import (
	"fmt"
	"sort"
	"sync"
)

// ScannerFactory is a constructor function that creates a Scanner.
// The args slice carries scanner-specific configuration (e.g. image names,
// file paths) and its interpretation is up to each registered factory.
type ScannerFactory func(args []string) Scanner

// registry holds the global scanner registrations. It is safe for
// concurrent access (registrations typically happen in init()).
type registry struct {
	mu       sync.RWMutex
	scanners map[string]ScannerFactory
}

// global is the process-wide scanner registry.
var global = &registry{
	scanners: make(map[string]ScannerFactory),
}

// Register adds a scanner factory under the given name. Names are
// case-sensitive and must be unique; registering the same name twice panics.
// This is intended to be called from init() functions.
func Register(name string, factory ScannerFactory) {
	global.mu.Lock()
	defer global.mu.Unlock()
	if _, exists := global.scanners[name]; exists {
		panic(fmt.Sprintf("scanner: duplicate registration for %q", name))
	}
	global.scanners[name] = factory
}

// Get returns the factory for the named scanner, or nil if not registered.
func Get(name string) ScannerFactory {
	global.mu.RLock()
	defer global.mu.RUnlock()
	return global.scanners[name]
}

// List returns the sorted names of all registered scanners.
func List() []string {
	global.mu.RLock()
	defer global.mu.RUnlock()
	names := make([]string, 0, len(global.scanners))
	for n := range global.scanners {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Registered returns true if a scanner with the given name has been
// registered.
func Registered(name string) bool {
	global.mu.RLock()
	defer global.mu.RUnlock()
	_, ok := global.scanners[name]
	return ok
}

// init registers the built-in scanners. This keeps all registrations
// in a single place rather than scattering init() functions across files.
func init() {
	Register("image", func(args []string) Scanner {
		if len(args) == 0 {
			return NewImageScanner("")
		}
		return NewImageScanner(args[0])
	})

	Register("k8s", func(args []string) Scanner {
		s := NewK8sScanner()
		s.ManifestPaths = args
		return s
	})

	Register("terraform", func(args []string) Scanner {
		return NewTerraformScanner(args)
	})

	Register("docker", func(args []string) Scanner {
		if len(args) == 0 {
			return NewDockerScanner("")
		}
		return NewDockerScanner(args[0])
	})
}
