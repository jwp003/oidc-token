package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

func main() {
	var idp, clientID, clientSecret, listen string
	var verbose bool

	flag.StringVar(&idp, "idp", "", "URL of OIDC identity provider")
	flag.StringVar(&clientID, "client", "", "client-id")
	flag.StringVar(&clientSecret, "secret", "", "client-secret")
	flag.StringVar(&listen, "listen", "localhost:8888", "address to listen on for auth redirect")
	flag.BoolVar(&verbose, "v", false, "verbose mode")
	flag.Parse()

	log := nullLog
	if verbose {
		log = verboseLog
	}

	// Init OIDC client
	provider, err := oidc.NewProvider(context.Background(), idp)
	if err != nil {
		exit("init idp: %s", err)
	}

	// Generate tokens
	state := generate(16)
	verifier := generate(43)
	challenge := challengify(verifier)

	// Code will be sent down this channel when received
	pendingCode := make(chan string, 0)

	// Setup auth redirect handler
	http.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		log("got redirect: %s", r.URL.String())

		w.WriteHeader(200)

		if r.URL.Query().Get("state") != state {
			log("bad state: ignoring")
			return
		}

		pendingCode <- r.URL.Query().Get("code")
	})

	// Start background webserver
	go http.ListenAndServe(listen, nil)
	log("started web server on %s", listen)

	oauth := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid"},
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://" + listen + "/redirect",
	}

	// Generate login URL
	options := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", challenge),
	}
	login := oauth.AuthCodeURL(state, options...)
	log("redirecting to login: %s", login)

	// Open auth page in browser
	// TODO: Support other OS
	cmd := exec.Command("open", login)
	stderr := bytes.NewBuffer(nil)
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		log("stderr: %s", stderr.String())
		exit("error opening browser: %s", err)
	}

	// Make POST request to retrieve access_token
	token, err := oauth.Exchange(context.Background(), <-pendingCode, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		exit("error exchanging token: %s", err)
	}

	// TODO: Cache and reuse access_token
	// TODO: Cache and use refresh_token

	log("got access token: valid to %s", token.Expiry)

	fmt.Print(token.AccessToken)
}

var chars = []rune(`abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`)

func generate(length uint) string {
	result := make([]rune, length)
	for i := 0; int64(i) < int64(length); i++ {
		result[i] = chars[rand.Int()%len(chars)]
	}
	return string(result)
}

func challengify(s string) string {
	hash := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func nullLog(_ string, _ ...interface{}) {
	return
}

func verboseLog(format string, a ...interface{}) {
	if format[len(format)-1] != '\n' {
		format += "\n"
	}
	fmt.Fprintf(os.Stderr, format, a...)
}

func exit(format string, a ...interface{}) {
	verboseLog(format, a...)
	os.Exit(1)
}
