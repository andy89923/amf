/*
 * Namf_Communication
 *
 * AMF Communication Service
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package communication

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/amf/internal/logger"
)

// NonUeN2InfoUnSubscribe - Namf_Communication Non UE N2 Info UnSubscribe service Operation
func HTTPNonUeN2InfoUnSubscribe(c *gin.Context) {
	auth_err := authorizationCheck(c)
	if auth_err != nil {
		return
	}

	logger.CommLog.Warnf("Handle Non Ue N2 Info UnSubscribe is not implemented.")
	c.JSON(http.StatusOK, gin.H{})
}
