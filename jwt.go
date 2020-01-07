package jwt

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	gojwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type Claims struct {
	Payload map[string]interface{} `json:"payload"`
	gojwt.StandardClaims
}

type JWT struct {
	SecretKey     string
	ExpiredHour   uint64
	TokenHeadName string
	Authenticator func(*gin.Context) (map[string]interface{}, error)
	Verification  func(*gin.Context, map[string]interface{}) (bool, error)
}

type JwtResponse struct {
	Expire       time.Time `json:"expire"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
}

const (
	EXP_DEFAULT           = 1
	ERROR_INVALID_TOKEN   = "Invalid token"
	ERROR_TOKEN_EXPIRED   = "Token is expired"
	ERROR_LOGIN_FALIED    = "Incorrect username or password"
	ERROR_INTERNAL_SERVER = "Internal Server Error"
	ERROR_UNAUTHORIZED    = "unauthorized"
)

func (jwt *JWT) RefreshToken(c *gin.Context) {
	payload, code, err := jwt.validToken(c)
	if err != nil {
		c.AbortWithStatusJSON(code, map[string]interface{}{
			"code":    code,
			"message": err.Error(),
		})
		return
	}

	token, err := jwt.genToken(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"code":    http.StatusInternalServerError,
			"message": ERROR_INTERNAL_SERVER,
		})
		return
	}

	c.JSON(http.StatusOK, token)
}

func (jwt *JWT) LoginHandler(c *gin.Context) {
	payload, err := jwt.Authenticator(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": err.Error(),
		})
		return
	}

	token, err := jwt.genToken(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"code":    http.StatusInternalServerError,
			"message": ERROR_INTERNAL_SERVER,
		})
		return
	}

	c.JSON(http.StatusOK, token)

}

func (jwt *JWT) genToken(payload map[string]interface{}) (JwtResponse, error) {
	var res JwtResponse

	now := time.Now()
	exp := now.Add(time.Hour * time.Duration(jwt.ExpiredHour))
	claims := Claims{
		payload,
		gojwt.StandardClaims{
			ExpiresAt: exp.Unix(),
		},
	}

	result := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	token, err := result.SignedString([]byte(jwt.SecretKey))
	if err != nil {
		return res, err
	}

	res.Token = token
	res.Expire = exp

	exp = now.Add(time.Hour * time.Duration(jwt.ExpiredHour+24))
	claims = Claims{
		payload,
		gojwt.StandardClaims{
			ExpiresAt: exp.Unix(),
		},
	}
	result = gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	refreshToken, err := result.SignedString([]byte(jwt.SecretKey))
	if err != nil {
		return res, err
	}

	res.RefreshToken = refreshToken

	return res, err
}

func (jwt *JWT) validToken(c *gin.Context) (map[string]interface{}, int, error) {
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
		return nil, http.StatusUnauthorized, fmt.Errorf("API token required")
	}

	payload, err := jwt.parseToken(token)
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}

	ok, err := jwt.Verification(c, payload)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf(ERROR_INTERNAL_SERVER)
	}

	if !ok {
		return nil, http.StatusUnauthorized, fmt.Errorf(ERROR_UNAUTHORIZED)
	}
	return payload, http.StatusOK, nil
}

func (jwt *JWT) parseToken(ss string) (map[string]interface{}, error) {
	token, err := gojwt.ParseWithClaims(ss, &Claims{}, func(token *gojwt.Token) (interface{}, error) {
		return []byte(jwt.SecretKey), nil
	})

	if err != nil {
		if ve, ok := err.(*gojwt.ValidationError); ok {
			if ve.Errors&gojwt.ValidationErrorMalformed != 0 {
				return nil, fmt.Errorf(ERROR_INVALID_TOKEN)
			} else if ve.Errors&(gojwt.ValidationErrorExpired) != 0 {
				return nil, fmt.Errorf(ERROR_TOKEN_EXPIRED)
			}
		}
		return nil, fmt.Errorf(ERROR_INVALID_TOKEN)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf(ERROR_INVALID_TOKEN)
	}
	return claims.Payload, nil

}
