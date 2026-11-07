package okta

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Timeout != 6*time.Second {
		t.Errorf("Timeout = %v", cfg.Timeout)
	}
}

func TestConfig_Validate(t *testing.T) {
	valid := Config{
		ClientID:     "id",
		ClientSecret: "secret",
		Issuer:       "https://example.okta.com",
		Callback:     "http://localhost/cb",
		Timeout:      time.Second,
	}
	if err := valid.Validate(); err != nil {
		t.Errorf("Validate() = %v", err)
	}
	if err := (Config{}).Validate(); err == nil {
		t.Error("expected error for empty config")
	}
}

func TestConfig_Validate_Timeout(t *testing.T) {
	cfg := Config{
		ClientID: "id", ClientSecret: "s", Issuer: "https://x", Callback: "http://cb",
		Timeout: 0,
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected timeout error")
	}
}
