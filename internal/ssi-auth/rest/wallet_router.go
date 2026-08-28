package rest

import (
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
	"github.com/gin-gonic/gin"
)

// WalletRouter is the HTTP boundary of the wallet module. It exposes the
// administrative endpoints for key and DID lifecycle, the credential inventory
// and the OID4VCI / OID4VP entry points.
type WalletRouter struct {
	holder *wallet.Service
}

// NewWalletRouter wraps the wallet use cases behind their HTTP boundary. The
// dependency is an explicit constructor argument, which is how injection is
// done in Go: no container, no reflection, wired once in main.
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

// RegisterWellKnown mounts the public did:web resolution endpoint. It is kept
// apart from Register so the discovery hook can be bound to a public domain
// without dragging the administrative surface into the open web.
func (r *WalletRouter) RegisterWellKnown(engine *gin.Engine) {
	engine.GET("/.well-known/did.json", r.getDidDoc)
}

// ===== HTTP handlers =========================================================

func (r *WalletRouter) link(c *gin.Context) {}

func (r *WalletRouter) isLinked(c *gin.Context) {}

func (r *WalletRouter) registerKey(c *gin.Context) {}

func (r *WalletRouter) deleteKey(c *gin.Context) {}

func (r *WalletRouter) getWalletKeys(c *gin.Context) {}

// registerDid mints a local DID. The handler only moves data across the
// boundary: bind, map to the domain, call one use case, map the result back.
func (r *WalletRouter) registerDid(c *gin.Context) {
	var req registerDidReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, fmt.Errorf("%w: %w", wallet.ErrInvalidInput, err))

		return
	}

	minted, err := r.holder.RegisterDid(c.Request.Context(),
		req.Builder.toDomain(), req.KeysID, req.Alias, req.toDomainServices())
	if err != nil {
		respondError(c, err)

		return
	}

	c.Header("Location", path.Join(c.Request.URL.Path, url.PathEscape(minted.ID.String())))
	c.JSON(http.StatusCreated, newDidResp(minted))
}

func (r *WalletRouter) getWalletDid(c *gin.Context) {}

func (r *WalletRouter) getDidDoc(c *gin.Context) {}

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
