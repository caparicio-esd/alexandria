package rest

import (
	"encoding/json"
	"net/http"

	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
	"github.com/gin-gonic/gin"
)

// WalletRouter is the driving adapter that exposes the wallet use cases over
// HTTP. It chooses status codes and shapes bodies; it decides nothing else.
type WalletRouter struct {
	holder *wallet.Service
}

// NewWalletRouter wires the router onto the wallet service it drives.
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

// RegisterWellKnown mounts the routes that must answer from the root of the
// host rather than from under the API prefix, because a did:web resolver looks
// for them at a fixed path.
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

func (r *WalletRouter) registerKey(c *gin.Context) {
	var registerKeyReq registerKeyReq

	if err := json.NewDecoder(c.Request.Body).Decode(&registerKeyReq); err != nil {
		respondError(c, err)
		return
	}

	if err := r.holder.RegisterKey(
		c.Request.Context(),
		registerKeyReq.Pem,
		&registerKeyReq.Alias,
		registerKeyReq.ID,
	); err != nil {
		respondError(c, err)
		return
	}

	c.Status(http.StatusCreated)
}

func (r *WalletRouter) deleteKey(_ *gin.Context) {}

func (r *WalletRouter) getWalletKeys(_ *gin.Context) {}

func (r *WalletRouter) registerDid(c *gin.Context) {
	var req registerDidReq

	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil {
		respondError(c, err)
		return
	}

	builder, err := req.Builder.toDomain()
	if err != nil {
		respondError(c, err)
		return
	}

	services, err := servicesToDomain(req.Service)
	if err != nil {
		respondError(c, err)
		return
	}

	err = r.holder.RegisterDid(
		c.Request.Context(),
		builder,
		req.Keys,
		req.Alias,
		services,
	)
	if err != nil {
		respondError(c, err)
		return
	}

	c.Status(http.StatusCreated)
}

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

func (r *WalletRouter) deleteDid(_ *gin.Context) {}

func (r *WalletRouter) setDefaultDid(_ *gin.Context) {}

func (r *WalletRouter) addKeyToDid(_ *gin.Context) {}

func (r *WalletRouter) removeKeyFromDid(_ *gin.Context) {}

func (r *WalletRouter) setDefaultKey(_ *gin.Context) {}

func (r *WalletRouter) deleteCredential(_ *gin.Context) {}

func (r *WalletRouter) getWalletCredentials(_ *gin.Context) {}

func (r *WalletRouter) getWalletInfo(_ *gin.Context) {}

func (r *WalletRouter) processOid4vci(_ *gin.Context) {}

func (r *WalletRouter) processOid4vp(_ *gin.Context) {}
