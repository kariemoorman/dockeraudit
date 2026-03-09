package scanner

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/kariemoorman/dockeraudit/internal/types"
)

func TestConcurrentScanners(t *testing.T) {
	dir := t.TempDir()

	df := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(df, []byte("FROM alpine:3.19\nUSER nobody\n"), 0644); err != nil {
    t.Fatal(err)
}

	cf := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(cf, []byte("version: '3'\nservices:\n  app:\n    image: nginx:latest\n"), 0644); err != nil {
    t.Fatal(err)
}

	manifest := filepath.Join(dir, "deploy.yaml")
	if err := os.WriteFile(manifest, []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: test\n  namespace: default\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx:latest\n"), 0644); err != nil {
    t.Fatal(err)
}

	tf := filepath.Join(dir, "main.tf")
	if err := os.WriteFile(tf, []byte("resource \"aws_ecr_repository\" \"test\" {}"), 0644); err != nil {
    t.Fatal(err)
}

	type scanResult struct {
		scanner  string
		result   *types.ScanResult
		err      error
	}

	const iterations = 5
	var mu sync.Mutex
	var allResults []scanResult
	var wg sync.WaitGroup
	ctx := context.Background()

	for i := 0; i < iterations; i++ {
		wg.Add(4)
		go func() {
			defer wg.Done()
			s := NewDockerScanner(dir)
			r, err := s.Scan(ctx)
			mu.Lock()
			allResults = append(allResults, scanResult{"docker-dir", r, err})
			mu.Unlock()
		}()
		go func() {
			defer wg.Done()
			s := NewDockerfileScanner(df)
			r, err := s.Scan(ctx)
			mu.Lock()
			allResults = append(allResults, scanResult{"dockerfile", r, err})
			mu.Unlock()
		}()
		go func() {
			defer wg.Done()
			s := NewK8sScanner()
			s.ManifestPaths = []string{manifest}
			r, err := s.Scan(ctx)
			mu.Lock()
			allResults = append(allResults, scanResult{"k8s", r, err})
			mu.Unlock()
		}()
		go func() {
			defer wg.Done()
			s := NewTerraformScanner([]string{tf})
			r, err := s.Scan(ctx)
			mu.Lock()
			allResults = append(allResults, scanResult{"terraform", r, err})
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Verify: no errors, all results non-nil with findings
	for _, sr := range allResults {
		if sr.err != nil {
			t.Errorf("%s scanner returned error: %v", sr.scanner, sr.err)
		}
		if sr.result == nil {
			t.Errorf("%s scanner returned nil result", sr.scanner)
			continue
		}
		if len(sr.result.Findings) == 0 {
			t.Errorf("%s scanner returned 0 findings", sr.scanner)
		}
	}

	// Verify: same scanner type returns consistent finding counts across iterations
	findingCounts := make(map[string]int)
	for _, sr := range allResults {
		if sr.result == nil {
			continue
		}
		count := len(sr.result.Findings)
		if prev, ok := findingCounts[sr.scanner]; ok {
			if prev != count {
				t.Errorf("%s scanner inconsistent: got %d and %d findings across runs", sr.scanner, prev, count)
			}
		} else {
			findingCounts[sr.scanner] = count
		}
	}
}
