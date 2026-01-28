package session

import (
	"context"
	"errors"
	"sync"
)

// memoryStore is an in-memory [Store] implementation for development and testing.
// Sessions are lost on restart. Not suitable for production.
type memoryStore struct {
	mu       sync.Mutex
	sessions map[string]Data
	states   map[string]struct{}
}

// NewMemoryStore returns an in-memory [Store] for development and testing.
func NewMemoryStore() Store {
	return &memoryStore{
		sessions: make(map[string]Data),
		states:   make(map[string]struct{}),
	}
}

func (s *memoryStore) CreateState(_ context.Context, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state] = struct{}{}
	return nil
}

func (s *memoryStore) VerifyState(_ context.Context, state string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.states[state]; !ok {
		return false, nil
	}
	delete(s.states, state)
	return true, nil
}

func (s *memoryStore) Create(_ context.Context, id string, data Data) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = deepCopyData(data)
	return nil
}

func (s *memoryStore) Get(_ context.Context, id string) (*Data, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.sessions[id]
	if !ok {
		return nil, errors.New("session: not found")
	}
	cp := deepCopyData(data)
	return &cp, nil
}

// deepCopyData returns a deep copy of the given Data, duplicating all slices and maps.
func deepCopyData(d Data) Data {
	cp := d
	if d.Scopes != nil {
		cp.Scopes = make([]string, len(d.Scopes))
		copy(cp.Scopes, d.Scopes)
	}
	if d.Roles != nil {
		cp.Roles = make([]string, len(d.Roles))
		copy(cp.Roles, d.Roles)
	}
	if d.Meta != nil {
		cp.Meta = make(map[string]any, len(d.Meta))
		for k, v := range d.Meta {
			cp.Meta[k] = v
		}
	}
	return cp
}

func (s *memoryStore) Refresh(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[id]; !ok {
		return errors.New("session: not found")
	}
	return nil
}

func (s *memoryStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}
