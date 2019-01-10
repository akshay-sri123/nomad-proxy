package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"io"
	"log"

	"crypto/tls"
	"crypto/x509"
	"os"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

// Version of this Proxy.
const Version = "0.1.0"

var (
	prefix    = uuid.NewV4().String()
	port      = kingpin.Flag("port", "Port no.").Short('p').Default("9988").String()
	jobPrefix = kingpin.Flag("job", "Job Prefix").Short('j').
			Default(prefix).Envar("JOB_PREFIX").String()
	serverAddr = kingpin.Flag("server-addr", "Server Addr").
			Short('s').Default("http://127.0.0.1:8080").Envar("SERVER_ADDR").String()
	ts2faConfig = kingpin.Flag("totp-config", "Filepath to 2FA config").File()

	rootFile  = kingpin.Flag("root-ca-file", "RootCA File").Envar("ROOT_CA_FILE").File()
	certFile  = kingpin.Flag("cert-file", "Cert File").Envar("CERT_FILE").File()
	keyFile   = kingpin.Flag("key-file", "Key File").Envar("KEY_FILE").File()
	cabotAddr = kingpin.Flag("cabot-addr", "Cabot addr for alerts").
			Short('c').Default("http://127.0.0.1:5001").Envar("CABOT_ADDR").String()

	ts2faObj *ts2fa.Ts2FA
)

// Transformer accepts a Request and make in-place changes.
type Transformer interface {
	Transform(*http.Request) error
}

// Transformation contains Transformer attached to a path that proxy should interfere with.
// Example: If /v1/jobs is a path that needs some magic to be performed.
// Path is /v1/jobs & magic would be in tx.
type Transformation struct {
	path string
	tx   Transformer
}

type Interceptor struct {
	path string
	in   http.RoundTripper
}

// Sugar so that I don't have to write structs to implement single-func Transformer.
type ruleTransformer func(*http.Request) error

func (f ruleTransformer) Transform(r *http.Request) error {
	return f(r)
}

// following same patter as above
type ruleInterceptor func(*http.Request) (*http.Response, error)

func (f ruleInterceptor) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func newBody(r *http.Request, i interface{}) error {
	nb, err := json.Marshal(i)
	if err != nil {
		return err
	}

	r.ContentLength = int64(len(nb))
	r.Body = ioutil.NopCloser(bytes.NewBuffer(nb))
	return nil
}

var rules = []Transformation{
	{path: "/v1/search", tx: ruleTransformer(search)},
	{path: "/v1/jobs", tx: ruleTransformer(jobs)},
	{path: "/v1/job", tx: ruleTransformer(job)},
	{path: "/v1/system", tx: ruleTransformer(system)},
}

var interceptors = []Interceptor{
	{path: "/v1/acl/token/", in: ruleInterceptor(acl)},
}

// Accept a Request. Walk through the rules.
// The first path that matches apply the corresponding transformer.
func modifyRequest(r *http.Request) error {
	for _, t := range rules {
		if !strings.HasPrefix(r.URL.Path, t.path) {
			continue
		}

		if err := t.tx.Transform(r); err != nil {
			return err
		}
		return nil
	}
	return nil
}

func interceptRequest(r *http.Request) (*http.Response, error) {
	for _, i := range interceptors {
		if !strings.HasPrefix(r.URL.Path, i.path) {
			continue
		}
		return i.in.RoundTrip(r)
	}
	return nil, nil
}

type customTripper struct {
	tripper http.RoundTripper
	origin  *url.URL
}

func (c *customTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("X-Forwarded-Host", req.Host)
	req.Header.Add("X-Origin-Host", c.origin.Host)
	req.URL.Scheme = c.origin.Scheme
	req.URL.Host = c.origin.Host

	//Check for Intercepted endpoints
	if resp, err := interceptRequest(req); err != nil || resp != nil {
		return resp, err
	}

	// check for 2fa token
	if err := validateToken(req.URL.Path, req.Method, req.Header.Get(NomadToken)); err != nil {
		log.Printf("2fa authentication failed for %v, %v", req.URL.Path, req.Method)
		return newResponse(req, http.StatusInternalServerError, []byte(err.Error())), nil
	}

	if err := modifyRequest(req); err != nil {
		log.Printf("error while modifying request: %+v", err)
		return newResponse(req, http.StatusInternalServerError, []byte(err.Error())), nil
	}
	log.Println("Hitting: ", req.Method, " ", req.URL)

	resp, err := c.tripper.RoundTrip(req)
	return resp, err
}

func initTs2fa(r io.ReadCloser) error {
	if *ts2faConfig == nil {
		log.Println("2FA is not enabled")
		return nil
	}

	confBytes, err := ioutil.ReadAll(*ts2faConfig)
	if err != nil {
		return err
	}

	defer r.Close()

	var conf ts2fa.Ts2FAConf
	if err := json.Unmarshal(confBytes, &conf); err != nil {
		return err
	}

	ts2faObj = ts2fa.New(&conf)
	return nil
}

func validateToken(path, method, token string) error {
	if ts2faObj == nil {
		log.Println("2FA is not enabled")
		return nil
	}

	// Only validate for these methods generically
	if method != http.MethodPut && method != http.MethodPost && method != http.MethodDelete {
		return nil
	}

	if token == "" {
		return fmt.Errorf("token not found")
	}

	tokens := strings.Split(token, ",")
	ts2fa.NewPayload(path, method, tokens...)

	ok, err := ts2faObj.Verify(ts2fa.NewPayload(path, method, tokens...))
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("tokens did match, please check values or the order")
	}

	return nil
}

// Main Engine function.
func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	// Setup and Parse Kingpin.
	kingpin.Version(Version)
	kingpin.Parse()

	// Parse the Backend URL, ensure it works, panic if it doesnt.
	origin, err := url.Parse(*serverAddr)
	if err != nil {
		log.Fatal(err)
	}

	if *ts2faConfig != nil {
		if err := initTs2fa(*ts2faConfig); err != nil {
			log.Fatal(err)
		}
	}

	// Create a new SingleHost Proxy
	reverseProxy := httputil.NewSingleHostReverseProxy(origin)

	t, tErr := makeTransport(*certFile, *keyFile, *rootFile)
	if tErr != nil {
		log.Fatal(tErr)
	}

	reverseProxy.Transport = &customTripper{t, origin}

	// Start the Server. Listen to the specified Port.
	if err := http.ListenAndServe(fmt.Sprintf(":%v", *port), reverseProxy); err != nil {
		panic(err)
	}
}

func makeTransport(certFile, keyFile, rootFile *os.File) (http.RoundTripper, error) {
	if certFile == nil || keyFile == nil || rootFile == nil {
		log.Println("Falling back to default Transport")
		return http.DefaultTransport, nil
	}

	cert, err := tls.LoadX509KeyPair(certFile.Name(), keyFile.Name())
	if err != nil {
		return nil, err
	}

	caCert, err := ioutil.ReadAll(rootFile)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	tlsConfig.BuildNameToCertificate()

	return &http.Transport{TLSClientConfig: tlsConfig}, nil
}
