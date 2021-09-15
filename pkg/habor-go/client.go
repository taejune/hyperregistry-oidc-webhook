package harbor_go

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type Config struct {
	ServerUrl string
	CertPath  string
	Insecure  bool
	User      string
	Password  string
}

type RestClient struct {
	client client
}

func NewRestClient(config *Config) *RestClient {
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if !config.Insecure && len(config.CertPath) > 0 {
		// Read in the cert file
		certs, err := ioutil.ReadFile(config.CertPath)
		if err != nil {
			log.Fatalf("Failed to append %q to RootCAs: %v", config.CertPath, err)
		}

		// Append our cert to the system pool
		if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
			log.Println("No certs appended, using system certs only")
		}
	}

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		RootCAs:            rootCAs,
		InsecureSkipVerify: config.Insecure,
	}

	u := strings.TrimSuffix(strings.TrimSpace(config.ServerUrl), "/")
	var scheme, host string
	if strings.HasPrefix(u, "https://") {
		scheme = "https"
		host = strings.TrimPrefix(u, "https://")
	} else if strings.HasPrefix(u, "http://") {
		scheme = "http"
		host = strings.TrimPrefix(u, "http://")
	} else {
		return nil
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &RestClient{
		client: client{u, host, scheme,
			config.User,
			config.Password,
			&http.Client{Transport: transport},
		},
	}
}

type RequestForm struct {
	Method  string
	Path    string
	Params  map[string]string
	Headers map[string]string
	Payload map[string]interface{}
}

type client struct {
	url      string
	host     string
	scheme   string
	user     string
	password string
	client   *http.Client
}

func (c client) Submit(form RequestForm) (*http.Response, error) {

	params := make([]string, 1)
	for k, v := range form.Params {
		params = append(params, fmt.Sprintf("%s=%s", k, v))
	}

	var u string
	paramStr := strings.Join(params, "&")
	if len(paramStr) > 0 {
		u = fmt.Sprintf("%s/api/v2.0/%s?%s", c.url, form.Path, paramStr)
	} else {
		u = fmt.Sprintf("%s/api/v2.0/%s", c.url, form.Path)
	}

	var body io.Reader
	if form.Payload != nil {
		payload, err := json.Marshal(form.Payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewBuffer(payload)
	}

	req, err := http.NewRequest(form.Method, url.QueryEscape(u), body)
	if err != nil {
		return nil, err
	}

	req.Host = c.host
	req.SetBasicAuth(c.user, c.password)

	return c.client.Do(req)
}
