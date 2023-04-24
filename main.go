package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// TODO: Look at providing a namespace instead of Host, Path, Protocol and
// have the service figure out the route to Argo instead of the console plugin.
// I'm a bit concerned that this service being used to exfiltrate OAuth Tokens
type endpointInfo struct {
	Host     string `json:"host"`
	Path     string `json:"path"`
	Protocol string `json:"protocol"`
}

type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int32  `json:"expires_in"`
}

func main() {
	router := gin.Default()
	router.POST("/token", exchangeToken)

	//router.Run("localhost:8080")
	// TODO: Put certs in better spot like /etc/ssl/certs
	router.RunTLS("localhost:8443", "/mnt/certs/tls.crt", "mnt/certs/tls.key")
}

func exchangeToken(c *gin.Context) {
	var endpoint endpointInfo

	if err := c.BindJSON(&endpoint); err != nil {
		log.Println(fmt.Errorf("Got error %s", err.Error()))
		c.JSON(403, err.Error())
		return
	}

	log.Println(fmt.Printf("Retrieved endpoint\n%s", endpoint))

	token := c.GetHeader("Authorization")[7:]
	if len(token) == 0 {
		c.JSON(403, errors.New("Authorization header expected"))
	}

	log.Println(token)

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("audience", "openshift")
	data.Add("subject_token", token)
	data.Add("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	data.Add("requested_token_type", "urn:ietf:params:oauth:token-type:id_token")
	data.Add("scope", "email groups")
	data.Add("resource", "argo-cd")
	encodedData := data.Encode()

	client := &http.Client{
		Timeout: time.Second * 10,
	}

	req, err := http.NewRequest("POST", endpoint.Protocol+"://"+endpoint.Host+endpoint.Path, strings.NewReader(encodedData))
	if err != nil {
		log.Println(fmt.Errorf("Error constructing request %s", err.Error()))
		c.JSON(500, err)
		return
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	response, err := client.Do(req)
	if err != nil {
		log.Println(fmt.Errorf("Error calling %s", err.Error()))
		c.JSON(500, err)
		return
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Println(fmt.Errorf("Error reading body %s", err.Error()))
		c.JSON(500, err)
		return
	}

	var accessToken tokenResponse
	err = json.Unmarshal(body, &accessToken)
	if err != nil {
		log.Println(fmt.Errorf("Error unmarshalling body %s", err.Error()))
		c.JSON(500, err)
		return
	}

	c.JSON(200, accessToken)
}
