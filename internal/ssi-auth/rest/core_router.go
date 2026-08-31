package rest

import "github.com/gin-gonic/gin"

// CoreRouter is the ssi-auth HTTP boundary. It owns the /ssi-auth prefix and
// composes the per-module subrouters underneath it.
type CoreRouter struct {
	wallet *WalletRouter
}

// NewCoreRouter takes every subrouter it composes as a parameter, so the wiring
// of concrete implementations happens once, at the composition root (main).
func NewCoreRouter(wallet *WalletRouter) *CoreRouter {
	return &CoreRouter{wallet: wallet}
}

// Register mounts /ssi-auth and its subtrees under the given API group.
//
// The group arrives already versioned — this context names itself and nothing
// more, so the version lives in one place for the whole process.
// It returns nothing on purpose: the group is an implementation detail of this
// context, and handing it out would let a caller mount routes under a prefix
// this router is responsible for.
func (r *CoreRouter) Register(api *gin.RouterGroup) {
	coreRouter := api.Group("/ssi-auth")

	r.wallet.Register(coreRouter)
}

// RegisterRoot mounts the routes whose paths a specification fixes at the root
// of the origin, where no version prefix may stand.
func (r *CoreRouter) RegisterRoot(engine *gin.Engine) {
	r.wallet.RegisterWellKnown(engine)
}
