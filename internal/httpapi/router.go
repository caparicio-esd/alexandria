// Package httpapi is the process-wide HTTP boundary.
//
// It owns the routes that describe the node rather than any one bounded
// context — the health probes today, the version and specification endpoints
// tomorrow — and mounts each context's own router underneath. A module router
// speaks for its module; this one speaks for the process.
package httpapi

import (
	"github.com/caparicio-esd/alexandria/internal/observability"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/rest"
	"github.com/gin-gonic/gin"
)

// Router composes the whole HTTP surface.
type Router struct {
	health  *observability.Health
	ssiAuth *rest.CoreRouter
}

// NewRouter takes every subrouter it composes as a parameter, so the wiring of
// concrete implementations happens once, at the composition root.
func NewRouter(health *observability.Health, ssiAuth *rest.CoreRouter) *Router {
	return &Router{health: health, ssiAuth: ssiAuth}
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

	r.ssiAuth.Register(engine)
}
