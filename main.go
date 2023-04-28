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
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jellydator/ttlcache/v3"
)

type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int32  `json:"expires_in"`
}

var cache = ttlcache.New(
	ttlcache.WithDisableTouchOnHit[string, string](),
	ttlcache.WithTTL[string, string](24*time.Hour),
	ttlcache.WithCapacity[string, string](1000),
)

func main() {

	router := gin.Default()

	router.GET("/*ignore", ReverseProxy())
	router.POST("/*ignore", ReverseProxy())

	// TODO: Put certs in better spot like /etc/ssl/certs
	router.RunTLS("0.0.0.0:8443", "/mnt/certs/tls.crt", "mnt/certs/tls.key")
}

// Generic reverse proxy for Argo CD APIs
// Will automatically perform a token exchange for the OAuth token
// that the console is passing in
func ReverseProxy() gin.HandlerFunc {

	return func(c *gin.Context) {
		director := func(req *http.Request) {

			host := getArgoServerHost(c.GetHeader("namespace"))

			log.Printf("%s http://%s", req.Method, host+c.Request.RequestURI)

			req.URL.Scheme = "http"
			req.URL.Host = host
			req.Host = host

			token, err := exchangeToken(c)
			if err == nil {
				req.Header.Set("Authorization", "Bearer "+token)
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
func getArgoServerHost(namespace string) string {
	if namespace == "openshift-gitops" {
		return "openshift-gitops-server." + namespace + ".svc.cluster.local"
	} else {
		// Making instance that argo instance in other instances are called argocd
		// Probably want to look up the service as a more robust option but
		// that would require the pod SA have rights to view other namespaces.
		return "argocd-server." + namespace + ".svc.cluster.local"
	}
}

func exchangeToken(c *gin.Context) (string, error) {

	token := c.GetHeader("Authorization")
	if len(token) < 8 {
		return "", errors.New("Invalid authorization header in request")
	}
	token = token[7:]

	host := getArgoServerHost(c.GetHeader("namespace"))

	// Check if we have token in cache
	var key = token + "@" + host
	item := cache.Get(key)
	if item != nil {
		return item.Value(), nil
	}

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("audience", "openshift")
	data.Add("subject_token", token)
	data.Add("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	data.Add("requested_token_type", "urn:ietf:params:oauth:token-type:id_token")
	data.Add("scope", "email groups")
	data.Add("resource", "argo-cd-cli")
	encodedData := data.Encode()

	client := &http.Client{
		Timeout: time.Second * 10,
	}

	req, err := http.NewRequest("POST", "http://"+host+"/api/dex/token", strings.NewReader(encodedData))
	if err != nil {
		log.Println(fmt.Errorf("Error constructing request %s", err.Error()))
		return "", err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	log.Println("Calling host for token exchange: " + req.Host + req.RequestURI)
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

	expires := time.Duration(int64(accessToken.ExpiresIn) * 1000000000)
	cache.Set(key, accessToken.AccessToken, expires)

	return accessToken.AccessToken, nil
}
