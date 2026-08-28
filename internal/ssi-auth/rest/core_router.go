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

// Register mounts /ssi-auth and its subtrees on the engine.
func (r *CoreRouter) Register(engine *gin.Engine) *gin.RouterGroup {
	coreRouter := engine.Group("/ssi-auth")

	r.wallet.Register(coreRouter)
	r.wallet.RegisterWellKnown(engine)

	return coreRouter
}
