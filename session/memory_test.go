package session

import (
	"context"
	"testing"
)

func TestMemoryStore_State(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	if err := store.CreateState(ctx, "state-123"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First verification should succeed.
	ok, err := store.VerifyState(ctx, "state-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected state to be valid")
	}

	// Second verification should fail (single-use).
	ok, err = store.VerifyState(ctx, "state-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected state to be consumed")
	}
}

func TestMemoryStore_StateUnknown(t *testing.T) {
	store := NewMemoryStore()

	ok, err := store.VerifyState(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected unknown state to be invalid")
	}
}

func TestMemoryStore_SessionCRUD(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	data := Data{
		UserID: "user-1",
		Email:  "user@example.com",
		Roles:  []string{"admin"},
	}

	// Create.
	if err := store.Create(ctx, "sess-1", data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Get.
	got, err := store.Get(ctx, "sess-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UserID != "user-1" {
		t.Errorf("expected UserID 'user-1', got %q", got.UserID)
	}
	if got.Email != "user@example.com" {
		t.Errorf("expected Email 'user@example.com', got %q", got.Email)
	}

	// Refresh (should not error).
	if err := store.Refresh(ctx, "sess-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Delete.
	if err := store.Delete(ctx, "sess-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Get after delete should fail.
	_, err = store.Get(ctx, "sess-1")
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestMemoryStore_DeepCopyIsolation(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	original := Data{
		UserID: "user-1",
		Scopes: []string{"read", "write"},
		Roles:  []string{"admin"},
		Meta:   map[string]any{"plan": "pro"},
	}

	if err := store.Create(ctx, "sess-1", original); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate the original after storing — store should be unaffected.
	original.Scopes[0] = "MUTATED"
	original.Roles[0] = "MUTATED"
	original.Meta["plan"] = "MUTATED"

	got, err := store.Get(ctx, "sess-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Scopes[0] != "read" {
		t.Errorf("expected stored Scopes[0] 'read', got %q", got.Scopes[0])
	}
	if got.Roles[0] != "admin" {
		t.Errorf("expected stored Roles[0] 'admin', got %q", got.Roles[0])
	}
	if got.Meta["plan"] != "pro" {
		t.Errorf("expected stored Meta[plan] 'pro', got %v", got.Meta["plan"])
	}

	// Mutate the returned value — store should be unaffected.
	got.Scopes[0] = "MUTATED"
	got.Roles[0] = "MUTATED"
	got.Meta["plan"] = "MUTATED"

	got2, err := store.Get(ctx, "sess-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got2.Scopes[0] != "read" {
		t.Errorf("expected Scopes[0] 'read' after external mutation, got %q", got2.Scopes[0])
	}
	if got2.Roles[0] != "admin" {
		t.Errorf("expected Roles[0] 'admin' after external mutation, got %q", got2.Roles[0])
	}
	if got2.Meta["plan"] != "pro" {
		t.Errorf("expected Meta[plan] 'pro' after external mutation, got %v", got2.Meta["plan"])
	}
}

func TestMemoryStore_GetNotFound(t *testing.T) {
	store := NewMemoryStore()

	_, err := store.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent session")
	}
}

func TestMemoryStore_RefreshNotFound(t *testing.T) {
	store := NewMemoryStore()

	err := store.Refresh(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent session")
	}
}
