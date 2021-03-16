package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/BurntSushi/toml"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var config = struct {
	ListenAddress string
	Providers     []struct {
		Name         string
		URL          string
		ClientID     string
		ClientSecret string
		Scopes       []string
	}
}{
	ListenAddress: "localhost:8888",
}

func main() {
	var name string
	var verbose bool

	home, err := os.UserHomeDir()
	if err != nil {
		exit("error getting config dir: %s", err)
	}
	dir := filepath.Join(home, ".config", "oidc-token")

	flag.BoolVar(&verbose, "v", false, "verbose mode")
	flag.Parse()

	log := nullLog
	if verbose {
		log = verboseLog
	}

	if _, err := toml.DecodeFile(filepath.Join(dir, "config.toml"), &config); err != nil {
		exit("error loading config: %s", err)
	}

	log("config loaded with %d providers", len(config.Providers))

	if len(config.Providers) < 1 {
		exit("no providers configured")
	}

	p := config.Providers[0]
	name = flag.Arg(0)

	if name != "" {
		for _, v := range config.Providers {
			if name == v.Name {
				p = v
				goto done
			}
		}
		exit("no provider: %s", name)
	}
done:

	cachefile := filepath.Join(dir, p.Name+".token")

	// Init OIDC client
	provider, err := oidc.NewProvider(context.Background(), p.URL)
	if err != nil {
		exit("init idp: %s", err)
	}

	oauth := &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Scopes:       p.Scopes,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://" + config.ListenAddress + "/redirect",
	}

	// Try to use cached refresh token
	if token, err := loadCachedToken(cachefile); err != nil {
		log("couldn't load cached token: %s", err)
	} else {
		source := oauth.TokenSource(context.Background(), token)
		if token, err := source.Token(); err != nil {
			log("couldn't use cached token: %s", err)
		} else {
			log("using cached token")
			if err := cacheToken(cachefile, token); err != nil {
				log("couldn't cache token: %s", err)
			}
			fmt.Println(token.AccessToken)
			return
		}
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
	go http.ListenAndServe(config.ListenAddress, nil)
	log("started web server on %s", config.ListenAddress)

	// Generate login URL
	options := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", challenge),
	}
	login := oauth.AuthCodeURL(state, options...)
	log("redirecting to login: %s", login)

	openTool := "open"
	if runtime.GOOS == "linux" {
		openTool = "xdg-open"
	}

	// TODO: Try multiple ways of opening browser
	cmd := exec.Command(openTool, login)
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

	log("got access token: valid to %s", token.Expiry)

	// Save tokens for reuse
	if err := cacheToken(cachefile, token); err != nil {
		log("couldn't cache token: %s", err)
	}

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

func cacheToken(file string, token *oauth2.Token) error {
	f, err := os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	defer f.Close()
	encoder := gob.NewEncoder(f)
	if err := encoder.Encode(token); err != nil {
		return err
	}
	return nil
}

func loadCachedToken(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := gob.NewDecoder(f)
	var token oauth2.Token
	if err := decoder.Decode(&token); err != nil {
		return nil, err
	}
	return &token, nil
}
