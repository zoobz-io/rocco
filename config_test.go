package rocco

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.ReadTimeout != 10*time.Second {
		t.Errorf("expected read timeout 10s, got %v", config.ReadTimeout)
	}
	if config.WriteTimeout != 10*time.Second {
		t.Errorf("expected write timeout 10s, got %v", config.WriteTimeout)
	}
	if config.IdleTimeout != 120*time.Second {
		t.Errorf("expected idle timeout 120s, got %v", config.IdleTimeout)
	}
}
