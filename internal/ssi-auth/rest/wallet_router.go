package rest

import (
	"net/http"

	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
	"github.com/gin-gonic/gin"
)

type WalletRouter struct {
	holder *wallet.Service
}

func NewWalletRouter(holder *wallet.Service) *WalletRouter {
	return &WalletRouter{holder: holder}
}

// Register mounts the wallet routes under the given parent group.
//
//	GET    /wallet/is-linked              asserts the linking state
//	POST   /wallet/link                   links against the external ecosystem directory
//	POST   /wallet/key                    imports raw asymmetric key material
//	GET    /wallet/keys                   lists the registered keys
//	DELETE /wallet/key/:id                purges a key reference
//	GET    /wallet/did                    resolves the primary identity string
//	POST   /wallet/did                    spawns a local DID
//	DELETE /wallet/did/:id                drops a DID mapping
//	POST   /wallet/did/:id/default        promotes a DID to default
//	POST   /wallet/did/:id/key/:key_id    binds a key into a DID
//	DELETE /wallet/did/:id/key/:key_id    unbinds a key from a DID
//	POST   /wallet/did/:id/key/:key_id/default  promotes a key to default within a DID
//	DELETE /wallet/credential/:id         purges a credential record
//	GET    /wallet/info                   resolves runtime telemetry
//	GET    /wallet/vcs                    collects the full credential array
//	POST   /wallet/oid4vci                dispatches an inbound credential offer
//	POST   /wallet/oid4vp                 resolves an outbound presentation request
func (r *WalletRouter) Register(parent *gin.RouterGroup) *gin.RouterGroup {
	walletRouter := parent.Group("/wallet")

	walletRouter.GET("/is-linked", r.isLinked)
	walletRouter.POST("/link", r.link)

	walletRouter.POST("/key", r.registerKey)
	walletRouter.GET("/keys", r.getWalletKeys)
	walletRouter.DELETE("/key/:id", r.deleteKey)

	didRouter := walletRouter.Group("/did")
	didRouter.GET("", r.getWalletDid)
	didRouter.POST("", r.registerDid)
	didRouter.DELETE("/:id", r.deleteDid)
	didRouter.POST("/:id/default", r.setDefaultDid)
	didRouter.POST("/:id/key/:key_id", r.addKeyToDid)
	didRouter.DELETE("/:id/key/:key_id", r.removeKeyFromDid)
	didRouter.POST("/:id/key/:key_id/default", r.setDefaultKey)

	walletRouter.DELETE("/credential/:id", r.deleteCredential)
	walletRouter.GET("/vcs", r.getWalletCredentials)
	walletRouter.GET("/info", r.getWalletInfo)

	walletRouter.POST("/oid4vci", r.processOid4vci)
	walletRouter.POST("/oid4vp", r.processOid4vp)

	return walletRouter
}

func (r *WalletRouter) RegisterWellKnown(engine *gin.Engine) {
	engine.GET("/.well-known/did.json", r.getDidDoc)
}

// ===== HTTP handlers =========================================================

func (r *WalletRouter) link(c *gin.Context) {
	did, err := r.holder.Link(c.Request.Context())
	if err != nil {
		respondError(c, err)

		return
	}

	c.JSON(http.StatusOK, newDidResp(did))
}

func (r *WalletRouter) isLinked(c *gin.Context) {
	if !r.holder.IsLinked(c.Request.Context()) {
		c.Status(http.StatusNotFound)

		return
	}

	c.Status(http.StatusOK)
}

func (r *WalletRouter) registerKey(c *gin.Context) {}

func (r *WalletRouter) deleteKey(c *gin.Context) {}

func (r *WalletRouter) getWalletKeys(c *gin.Context) {}

func (r *WalletRouter) registerDid(c *gin.Context) {}

func (r *WalletRouter) getWalletDid(c *gin.Context) {
	id, err := r.holder.Did(c.Request.Context())
	if err != nil {
		respondError(c, err)

		return
	}

	c.JSON(http.StatusOK, didIDResp{Did: id})
}

func (r *WalletRouter) getDidDoc(c *gin.Context) {
	doc, err := r.holder.DidDoc(c.Request.Context())
	if err != nil {
		respondError(c, err)

		return
	}

	// The pointer matters: did.Doc declares MarshalJSON on the pointer
	// receiver, so passing the value would emit the Go field names.
	c.JSON(http.StatusOK, &doc)
}

func (r *WalletRouter) deleteDid(c *gin.Context) {}

func (r *WalletRouter) setDefaultDid(c *gin.Context) {}

func (r *WalletRouter) addKeyToDid(c *gin.Context) {}

func (r *WalletRouter) removeKeyFromDid(c *gin.Context) {}

func (r *WalletRouter) setDefaultKey(c *gin.Context) {}

func (r *WalletRouter) deleteCredential(c *gin.Context) {}

func (r *WalletRouter) getWalletCredentials(c *gin.Context) {}

func (r *WalletRouter) getWalletInfo(c *gin.Context) {}

func (r *WalletRouter) processOid4vci(c *gin.Context) {}

func (r *WalletRouter) processOid4vp(c *gin.Context) {}
