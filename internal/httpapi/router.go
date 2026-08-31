// Package httpapi is the process-wide HTTP boundary.
//
// It owns the routes that describe the node rather than any one bounded
// context — the health probes today, the version and specification endpoints
// tomorrow — and mounts each context underneath. A module speaks for its
// context; this one speaks for the process.
package httpapi

import (
	"github.com/caparicio-esd/alexandria/internal/observability"
	"github.com/gin-gonic/gin"
)

// Module is all this package needs from a bounded context: something that can
// mount itself.
//
// The interface is declared here, where it is consumed, and deliberately
// narrow — a context satisfies it by having a Register method, without
// importing this package or knowing it exists.
type Module interface {
	Register(engine *gin.Engine)
}

// Router composes the whole HTTP surface.
type Router struct {
	health  *observability.Health
	modules []Module
}

// NewRouter takes every module it composes as a parameter, so the wiring of
// concrete implementations happens once, at the composition root.
func NewRouter(health *observability.Health, modules ...Module) *Router {
	return &Router{health: health, modules: modules}
}

// Register mounts the process-wide routes and every bounded context.
//
// The probes sit at the root, outside any module prefix: a kubelet is
// configured with a path and a port, and burying them under a module's prefix
// only invites someone to point the liveness probe at a route that talks to a
// dependency.
func (r *Router) Register(engine *gin.Engine) {
	engine.GET("/healthz", gin.WrapH(r.health.LiveHandler()))
	engine.GET("/readyz", gin.WrapH(r.health.ReadyHandler()))

	for _, module := range r.modules {
		module.Register(engine)
	}
}
