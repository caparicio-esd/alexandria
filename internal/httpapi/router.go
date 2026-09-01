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

// APIVersion is the version segment every bounded context is mounted under, and
// APIPrefix the path it produces. They live here because the version is a
// property of the process's public contract, not of any one context: a module
// that hard-codes its own prefix is a module that can drift out of step with
// the rest. Introducing v2 means adding a second group here and letting the
// modules that moved register under it — no context edits its own routes.
const (
	APIVersion = "v1"
	APIPrefix  = "/api/" + APIVersion
)

// Module is all this package needs from a bounded context: something that can
// mount itself under the versioned API.
//
// The interface is declared here, where it is consumed, and deliberately
// narrow — a context satisfies it by having a Register method, without
// importing this package or knowing it exists. It takes a group rather than the
// engine so a context cannot mount itself outside the version it was given.
type Module interface {
	Register(api *gin.RouterGroup)
}

// RootModule is optional: a context with routes whose paths are fixed by a
// specification outside this process — /.well-known/did.json, say — implements
// it and mounts those on the engine itself. Versioning a well-known URI would
// make it unresolvable, so the escape hatch is explicit and narrow rather than
// handing every module the engine.
type RootModule interface {
	RegisterRoot(engine *gin.Engine)
}

// Guard is what this package needs from an authentication context: the routes
// that have to answer before a caller has any credential, and the middleware
// everything else passes through.
//
// It is one interface rather than two because the two halves are inseparable:
// the guard that refuses a request is the same component that owns the route
// which fixes it, and mounting one without the other produces an API that
// either cannot be reached or cannot be entered.
//
// Declared here, where it is consumed. A context satisfies it by having the two
// methods, without importing this package.
type Guard interface {
	// Public mounts the routes that precede authentication, on a group taken
	// before the middleware is installed.
	Public(api *gin.RouterGroup)
	// Protect is applied to the versioned API group, and so to every route any
	// module mounts under it.
	Protect() gin.HandlerFunc
}

// Router composes the whole HTTP surface.
type Router struct {
	health  *observability.Health
	guard   Guard
	modules []Module
}

// NewRouter takes every module it composes as a parameter, so the wiring of
// concrete implementations happens once, at the composition root.
//
// A nil guard leaves the API open, which is a development posture and the only
// thing a deployment must not ship. It is a parameter rather than an option so
// that "who protects this API" is answered at the call site, in the open, and
// never by omission.
func NewRouter(health *observability.Health, guard Guard, modules ...Module) *Router {
	return &Router{health: health, guard: guard, modules: modules}
}

// Register mounts the process-wide routes and every bounded context.
//
// The probes sit at the root, outside the API prefix: a kubelet is configured
// with a path and a port, and burying them under a version only invites someone
// to repoint the liveness probe the day v2 lands.
func (r *Router) Register(engine *gin.Engine) {
	engine.GET("/healthz", gin.WrapH(r.health.LiveHandler()))
	engine.GET("/readyz", gin.WrapH(r.health.ReadyHandler()))

	api := engine.Group(APIPrefix)

	// Order is load-bearing. A gin group captures the middleware chain it is
	// created with, so the public authentication routes are taken off `api`
	// before Use installs the guard, and every group taken afterwards — which
	// is every module's — carries it. Mounting the login route after this line
	// would put it behind the check it exists to satisfy.
	if r.guard != nil {
		r.guard.Public(api)
		api.Use(r.guard.Protect())
	}

	for _, module := range r.modules {
		module.Register(api)

		if rooted, ok := module.(RootModule); ok {
			rooted.RegisterRoot(engine)
		}
	}
}
