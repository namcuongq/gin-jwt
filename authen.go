package jwt

import (
	"fmt"

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
		payload, code, err := jwt.validToken(c)
		if err != nil {
			c.AbortWithStatusJSON(code, map[string]interface{}{
				"code":    code,
				"message": err.Error(),
			})
			return
		}

		for k, v := range payload {
			c.Set(k, v)
		}

		c.Next()
	}
}
