package scanner

import (
	"testing"
)

func TestBuiltinScannersRegistered(t *testing.T) {
	// Verify all built-in scanners are registered via init().
	expected := []string{"image", "k8s", "terraform"}
	for _, name := range expected {
		if !Registered(name) {
			t.Errorf("built-in scanner %q not registered", name)
		}
	}
}

func TestList(t *testing.T) {
	names := List()
	if len(names) < 3 {
		t.Errorf("List() returned %d names, want at least 3", len(names))
	}
	// Names should be sorted.
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("List() not sorted: %q comes after %q", names[i], names[i-1])
		}
	}
}

func TestGet(t *testing.T) {
	t.Run("existing scanner", func(t *testing.T) {
		f := Get("image")
		if f == nil {
			t.Fatal("Get(\"image\") returned nil")
		}
		s := f([]string{"nginx:latest"})
		if s == nil {
			t.Fatal("factory returned nil scanner")
		}
		// Verify it's an ImageScanner.
		if _, ok := s.(*ImageScanner); !ok {
			t.Errorf("expected *ImageScanner, got %T", s)
		}
	})

	t.Run("k8s scanner", func(t *testing.T) {
		f := Get("k8s")
		if f == nil {
			t.Fatal("Get(\"k8s\") returned nil")
		}
		s := f([]string{"./manifests/"})
		if _, ok := s.(*K8sScanner); !ok {
			t.Errorf("expected *K8sScanner, got %T", s)
		}
	})

	t.Run("terraform scanner", func(t *testing.T) {
		f := Get("terraform")
		if f == nil {
			t.Fatal("Get(\"terraform\") returned nil")
		}
		s := f([]string{"./infra/"})
		if _, ok := s.(*TerraformScanner); !ok {
			t.Errorf("expected *TerraformScanner, got %T", s)
		}
	})

	t.Run("nonexistent scanner", func(t *testing.T) {
		f := Get("nonexistent")
		if f != nil {
			t.Error("Get(\"nonexistent\") should return nil")
		}
	})
}

func TestRegistered(t *testing.T) {
	if !Registered("image") {
		t.Error("Registered(\"image\") should be true")
	}
	if Registered("nonexistent") {
		t.Error("Registered(\"nonexistent\") should be false")
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("Register with duplicate name should panic")
		}
	}()
	// "image" is already registered by init().
	Register("image", func(args []string) Scanner {
		return NewImageScanner("")
	})
}

func TestImageFactoryNoArgs(t *testing.T) {
	f := Get("image")
	s := f(nil) // no args
	img, ok := s.(*ImageScanner)
	if !ok {
		t.Fatalf("expected *ImageScanner, got %T", s)
	}
	if img.Image != "" {
		t.Errorf("Image = %q, want empty string", img.Image)
	}
}
