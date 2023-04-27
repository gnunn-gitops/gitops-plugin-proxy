package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int32  `json:"expires_in"`
}

func main() {
	router := gin.Default()

	router.GET("/*ignore", ReverseProxy())
	router.POST("/*ignore", ReverseProxy())

	router.Run("localhost:8080")
	// TODO: Put certs in better spot like /etc/ssl/certs
	//router.RunTLS("0.0.0.0:8443", "/mnt/certs/tls.crt", "mnt/certs/tls.key")

}

// Generic reverse proxy for Argo CD APIs
// Will automatically perform a token exchange for the OAuth token
// that the console is passing in
func ReverseProxy() gin.HandlerFunc {

	return func(c *gin.Context) {
		director := func(req *http.Request) {
			host := getArgoServerHost(c.GetHeader("namespace"), os.Getenv("SUBDOMAIN"))

			log.Println(fmt.Printf("%s https://%s", c.Request.Method, host+c.Request.RequestURI))

			req.URL.Scheme = "https"
			req.URL.Host = host

			token, err := exchangeToken(c)
			if err != nil {
				req.Header.Set("Authentication", "Bearer "+token)
			} else {
				log.Println("Unexpected error retrieving token", err)
			}
			delete(req.Header, "namespace")

		}
		proxy := &httputil.ReverseProxy{Director: director}
		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

// Get location of Argo Server Host based on namespace requested.
// The namespace is passed in by the front-end via a Header
func getArgoServerHost(namespace string, subdomain string) string {
	if namespace == "openshift-gitops" {
		return "openshift-gitops-server-openshift-gitops." + subdomain
	} else {
		// Making instance that argo instance in other instances are called argocd
		// Probably want to look up the route as a better way
		return "argocd-server-" + namespace + "." + subdomain
	}
}

func exchangeToken(c *gin.Context) (string, error) {

	token := c.GetHeader("Authorization")
	if len(token) < 8 {
		return "", errors.New("Invalid authorization header in request")
	}
	token = token[7:]

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

	host := getArgoServerHost(c.GetHeader("namespace"), os.Getenv("SUBDOMAIN"))
	req, err := http.NewRequest("POST", "https://"+host+"/api/dex/token", strings.NewReader(encodedData))
	if err != nil {
		log.Println(fmt.Errorf("Error constructing request %s", err.Error()))
		return "", err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	response, err := client.Do(req)
	if err != nil {
		log.Println(fmt.Errorf("Error calling %s", err.Error()))
		return "", err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Println(fmt.Errorf("Error reading body %s", err.Error()))
		return "", err
	}

	var accessToken tokenResponse
	err = json.Unmarshal(body, &accessToken)
	if err != nil {
		log.Println(fmt.Errorf("Error unmarshalling body %s", err.Error()))
		return "", err
	}

	return accessToken.AccessToken, nil
}
