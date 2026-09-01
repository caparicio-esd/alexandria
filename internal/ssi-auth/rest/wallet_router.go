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
//	GET    /wallet/did/all                lists every DID held
//	POST   /wallet/did                    spawns a local DID
//	GET    /wallet/did/:id                resolves a single DID record
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

	walletRouter.GET("/is-linked", r.isLinked) // ok
	walletRouter.POST("/link", r.link)         // ok

	walletRouter.POST("/keys", r.registerKey)     // ok
	walletRouter.GET("/keys", r.getWalletKeys)    // ok
	walletRouter.DELETE("/keys/:id", r.deleteKey) // ok

	didRouter := walletRouter.Group("/did")
	didRouter.GET("", r.getWalletDid) // ok
	didRouter.GET("/all", r.getAllDids)
	didRouter.POST("", r.registerDid) // ok
	didRouter.GET("/:id", r.getDid)
	didRouter.DELETE("/:id", r.deleteDid) // ok
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

func (r *WalletRouter) deleteKey(c *gin.Context) {
	keyID := c.Params.ByName("id")
	err := r.holder.DeleteKey(c, keyID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusAccepted)
}

func (r *WalletRouter) getWalletKeys(c *gin.Context) {
	keys, err := r.holder.Keys(c)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, newKeyResps(keys))
}

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

// getAllDids renders every DID the wallet holds.
func (r *WalletRouter) getAllDids(c *gin.Context) {
	dids, err := r.holder.GetAllDids(c.Request.Context())
	if err != nil {
		respondError(c, err)

		return
	}

	c.JSON(http.StatusOK, &dids)
}

func (r *WalletRouter) getDidDoc(c *gin.Context) {
	doc, err := r.holder.DidDoc(c.Request.Context())
	if err != nil {
		respondError(c, err)

		return
	}
	c.JSON(http.StatusOK, &doc)
}

// getDid renders a single DID record, or 404 when there is none.
func (r *WalletRouter) getDid(c *gin.Context) {
	didID := c.Params.ByName("id")
	did, err := r.holder.GetDidByID(c.Request.Context(), didID)
	if err != nil {
		respondError(c, err)

		return
	}

	c.JSON(http.StatusOK, &did)
}

func (r *WalletRouter) deleteDid(c *gin.Context) {
	didID := c.Params.ByName("id")
	err := r.holder.DeleteDid(c, didID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusAccepted)
}

// setDefaultDid promotes a DID to be the wallet active identity.
func (r *WalletRouter) setDefaultDid(c *gin.Context) {
	didID := c.Params.ByName("id")
	err := r.holder.SetDefaultDid(c, didID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusAccepted)
}

// addKeyToDid binds a key into the verification methods of a DID.
func (r *WalletRouter) addKeyToDid(c *gin.Context) {
	didID := c.Params.ByName("id")
	keyID := c.Params.ByName("key_id")
	err := r.holder.AddKeyToDid(c, didID, keyID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusCreated)
}

// removeKeyFromDid unbinds a key from the verification methods of a DID.
func (r *WalletRouter) removeKeyFromDid(c *gin.Context) {
	didID := c.Params.ByName("id")
	keyID := c.Params.ByName("key_id")
	err := r.holder.RemoveKeyFromDid(c, didID, keyID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusAccepted)
}

// setDefaultKey promotes a key to be the default verification method of a DID.
func (r *WalletRouter) setDefaultKey(c *gin.Context) {
	didID := c.Params.ByName("id")
	keyID := c.Params.ByName("key_id")
	err := r.holder.SetDefaultKey(c, didID, keyID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusAccepted)
}

func (r *WalletRouter) deleteCredential(_ *gin.Context) {}

func (r *WalletRouter) getWalletCredentials(_ *gin.Context) {}

func (r *WalletRouter) getWalletInfo(_ *gin.Context) {}

func (r *WalletRouter) processOid4vci(_ *gin.Context) {}

func (r *WalletRouter) processOid4vp(_ *gin.Context) {}
