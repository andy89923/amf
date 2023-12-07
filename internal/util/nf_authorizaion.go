package util

import (
	"net/http"

	"github.com/gin-gonic/gin"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/openapi/oauth"
)

// This function would check the OAuth2 token, and the requestNF is in ServiceAllowNfType
func AuthorizationCheck(c *gin.Context, serviceName string) error {
	if amf_context.GetSelf().OAuth2Required {
		oauth_err := oauth.VerifyOAuth(c.Request.Header.Get("Authorization"), serviceName,
			amf_context.GetSelf().NrfCerPem)
		if oauth_err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": oauth_err.Error()})
			return oauth_err
		}
	}
	return nil
}
