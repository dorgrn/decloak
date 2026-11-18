package main

import (
	"testing"

	"github.com/dorgrn/decloak/internal/judge"
)

func TestApplyProviderOpenCode(t *testing.T) {
	opts := &options{provider: "opencode"}
	if err := applyProvider(opts); err != nil {
		t.Fatal(err)
	}
	if opts.baseURL != judge.OpenCodeBaseURL || opts.model != judge.OpenCodeDefaultModel {
		t.Fatalf("baseURL=%q model=%q", opts.baseURL, opts.model)
	}
}

func TestApplyProviderKeepsExplicitValues(t *testing.T) {
	opts := &options{provider: "opencode", baseURL: "http://localhost:11434/v1", model: "local"}
	if err := applyProvider(opts); err != nil {
		t.Fatal(err)
	}
	if opts.baseURL != "http://localhost:11434/v1" || opts.model != "local" {
		t.Fatalf("baseURL=%q model=%q", opts.baseURL, opts.model)
	}
}

func TestApplyProviderRejectsUnknown(t *testing.T) {
	if err := applyProvider(&options{provider: "nope"}); err == nil {
		t.Fatal("expected an error")
	}
}
