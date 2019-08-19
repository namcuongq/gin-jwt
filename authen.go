package jwt

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func New(jwt *JWT) (*JWT, error) {
	return jwt, jwt.init()
}

func (jwt *JWT) init() error {
	if len(jwt.SecretKey) < 1 {
		return fmt.Errorf("secret ket must be not null")
	}

	if jwt.ExpiredHour <= 0 {
		jwt.ExpiredHour = EXP_DEFAULT
	}

	if jwt.Authenticator == nil {
		jwt.Authenticator = func(c *gin.Context) (map[string]interface{}, error) {
			return nil, nil
		}
	}

	if jwt.Verification == nil {
		jwt.Verification = func(*gin.Context, map[string]interface{}) (bool, error) {
			return true, nil
		}
	}

	return nil
}

func (jwt *JWT) TokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.Request.Header.Get("Authorization")
		token := ""

		if jwt.TokenHeadName != "" {
			arr := strings.Split(header, " ")
			if len(arr) > 1 && arr[0] == jwt.TokenHeadName {
				token = arr[1]
			}
		} else {
			token = header
		}

		if len(token) < 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]interface{}{
				"code":    http.StatusUnauthorized,
				"message": "API token required",
			})
			return
		}

		payload, err := jwt.parseToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]interface{}{
				"code":    http.StatusUnauthorized,
				"message": err.Error(),
			})
			return
		}
		ok, err := jwt.Verification(c, payload)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, map[string]interface{}{
				"code":    http.StatusInternalServerError,
				"message": ERROR_INTERNAL_SERVER,
			})
			return
		}

		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]interface{}{
				"code":    http.StatusUnauthorized,
				"message": ERROR_UNAUTHORIZED,
			})
			return
		}

		for k, v := range payload {
			c.Set(k, v)
		}

		c.Next()
	}
}
