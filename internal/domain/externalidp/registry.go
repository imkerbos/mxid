package externalidp

import (
	"fmt"
	"sync"
)

// Registry maps Provider Type → Factory. Concrete provider files register
// themselves into the package-default registry via init().
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// NewRegistry returns an empty registry. Tests use this to keep the global
// registry pristine.
func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]Factory)}
}

// Register adds a factory. Panics on duplicate type so wiring bugs surface
// at process start.
func (r *Registry) Register(t string, f Factory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.factories[t]; ok {
		panic(fmt.Sprintf("externalidp: factory for %q already registered", t))
	}
	r.factories[t] = f
}

// Build instantiates a Provider for the given IdP row.
func (r *Registry) Build(idp *ExternalIDP) (Provider, error) {
	r.mu.RLock()
	f, ok := r.factories[idp.Type]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownProvider, idp.Type)
	}
	return f(idp)
}

// Types returns the registered provider type identifiers. Useful for admin
// UI dropdowns.
func (r *Registry) Types() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.factories))
	for k := range r.factories {
		out = append(out, k)
	}
	return out
}

// DefaultRegistry is the global registry used by the gateway. Provider
// files attach themselves to it via init().
var DefaultRegistry = NewRegistry()
