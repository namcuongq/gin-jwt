# JWT Middleware for Gin Framework

This is a middleware for [Gin](https://github.com/gin-gonic/gin) framework.
## Usage

Download and install it:

```sh
$ go get github.com/namcuongq/gin-jwt
```

Import it in your code:

```go
import "github.com/namcuongq/gin-jwt"
```

## Example

[embedmd]:# (example/basic/server.go go)
```go
package main

import (
	"log"
	"fmt"
	jwt "github.com/namcuongq/gin-jwt"

	"github.com/gin-gonic/gin"
)

func helloHandler(c *gin.Context) {
	id, _ := c.Get("id")
	c.JSON(200, gin.H{
		"userID":   id,
		"text":     "Hello World.",
	})
}

func main() {
	router := gin.New()

	authen, err := jwt.New(&jwt.JWT{
		SecretKey:     "secret-key",
		ExpiredHour:   1, //deault 1 hour
		TokenHeadName: "Bearer", // TokenHeadName is a string in the header. Default value is ""
		Authenticator: func(c *gin.Context) (map[string]interface{}, error) {
			var loginVals map[string]string
			if err := c.ShouldBind(&loginVals); err != nil {
				  return nil, fmt.Errorf("error username or password missing")
			  }
        
			if loginVals["username"] != "admin" || loginVals["password"] != "admin"{
      			  return nil, fmt.Errorf("authentication failed")
			}
      
			var data = map[string]interface{}{
				"id": 1,
			}
      
			return data, nil
		},
		Verification: func(data map[string]interface{}) (bool, error) {
			if fmt.Sprintf("%v",data["username"]) == "admin"{
      			  return true, nil
			}
      
			return false, nil
		},
	})
  
	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}
  
	router.POST("/login", authen.LoginHandler)
  
	router.Use(authen.TokenAuthMiddleware())
	router.GET("/hello", helloHandler)

	router.Run()

}
```
