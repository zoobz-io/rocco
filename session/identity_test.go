package session

import "testing"

func TestIdentity_Fields(t *testing.T) {
	id := &Identity{data: Data{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Email:    "user@example.com",
		Scopes:   []string{"read", "write"},
		Roles:    []string{"admin", "editor"},
	}}

	if id.ID() != "user-1" {
		t.Errorf("expected ID 'user-1', got %q", id.ID())
	}
	if id.TenantID() != "tenant-1" {
		t.Errorf("expected TenantID 'tenant-1', got %q", id.TenantID())
	}
	if id.Email() != "user@example.com" {
		t.Errorf("expected Email 'user@example.com', got %q", id.Email())
	}
	if len(id.Scopes()) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(id.Scopes()))
	}
	if len(id.Roles()) != 2 {
		t.Errorf("expected 2 roles, got %d", len(id.Roles()))
	}
}

func TestIdentity_HasScope(t *testing.T) {
	id := &Identity{data: Data{Scopes: []string{"read", "write"}}}

	if !id.HasScope("read") {
		t.Error("expected HasScope('read') to be true")
	}
	if !id.HasScope("write") {
		t.Error("expected HasScope('write') to be true")
	}
	if id.HasScope("admin") {
		t.Error("expected HasScope('admin') to be false")
	}
}

func TestIdentity_HasRole(t *testing.T) {
	id := &Identity{data: Data{Roles: []string{"admin", "editor"}}}

	if !id.HasRole("admin") {
		t.Error("expected HasRole('admin') to be true")
	}
	if id.HasRole("viewer") {
		t.Error("expected HasRole('viewer') to be false")
	}
}

func TestIdentity_Stats(t *testing.T) {
	id := &Identity{data: Data{}}
	if id.Stats() != nil {
		t.Error("expected nil stats")
	}
}

func TestIdentity_EmptyData(t *testing.T) {
	id := &Identity{data: Data{}}

	if id.ID() != "" {
		t.Errorf("expected empty ID, got %q", id.ID())
	}
	if id.HasScope("anything") {
		t.Error("expected HasScope to be false on empty scopes")
	}
	if id.HasRole("anything") {
		t.Error("expected HasRole to be false on empty roles")
	}
}
