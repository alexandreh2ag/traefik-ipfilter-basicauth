package traefik_ipfilter_basicauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	goauth "github.com/abbot/go-http-auth"
)

type BasicAuth struct {
	Users        []string `json:"users,omitempty" toml:"users,omitempty" yaml:"users,omitempty" loggable:"false"`
	UsersFile    string   `json:"usersFile,omitempty" toml:"usersFile,omitempty" yaml:"usersFile,omitempty"`
	Realm        string   `json:"realm,omitempty" toml:"realm,omitempty" yaml:"realm,omitempty"`
	RemoveHeader bool     `json:"removeHeader,omitempty" toml:"removeHeader,omitempty" yaml:"removeHeader,omitempty" export:"true"`
	HeaderField  string   `json:"headerField,omitempty" toml:"headerField,omitempty" yaml:"headerField,omitempty" export:"true"`
}

type IPWhiteList struct {
	SourceRange []string `json:"sourceRange,omitempty" toml:"sourceRange,omitempty" yaml:"sourceRange,omitempty"`
}

// Config the plugin configuration.
type Config struct {
	BasicAuth   BasicAuth   `json:"basicAuth,omitempty" toml:"basicAuth,omitempty" yaml:"basicAuth,omitempty"`
	IPWhiteList IPWhiteList `json:"ipWhiteList,omitempty" toml:"ipWhiteList,omitempty" yaml:"ipWhiteList,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// Middleware a Middleware plugin.
type Middleware struct {
	auth         *goauth.BasicAuth
	next         http.Handler
	users        map[string]string
	headerField  string
	removeHeader bool
	whiteLister  *Checker
	name         string
}

// New created a new Middleware plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.IPWhiteList.SourceRange) == 0 {
		return nil, errors.New("sourceRange is empty, IPWhiteLister not created")
	}

	checker, err := NewChecker(config.IPWhiteList.SourceRange)
	if err != nil {
		return nil, fmt.Errorf("cannot parse CIDR whitelist %s: %w", config.IPWhiteList.SourceRange, err)
	}

	users, err := getUsers(config.BasicAuth.UsersFile, config.BasicAuth.Users, basicUserParser)
	if err != nil {
		return nil, err
	}
	m := &Middleware{
		users:        users,
		whiteLister:  checker,
		removeHeader: config.BasicAuth.RemoveHeader,
		headerField:  config.BasicAuth.HeaderField,
		next:         next,
		name:         name,
	}
	realm := defaultRealm
	if len(config.BasicAuth.Realm) > 0 {
		realm = config.BasicAuth.Realm
	}
	m.auth = &goauth.BasicAuth{Realm: realm, Secrets: m.secretBasic}

	return m, nil
}

func (m *Middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	user := ""
	if req.RemoteAddr == "" {
		fmt.Println("RemoteAddr is empty")
		return
	}

	err := m.whiteLister.IsAuthorized(req.RemoteAddr)
	if err != nil {
		fmt.Println("Try basic auth")
		ok := false
		if user = m.auth.CheckAuth(req); user == "" {
			ok = false
		} else {
			ok = true
		}

		if !ok {
			m.auth.RequireAuth(rw, req)
			fmt.Println("IP is not authorize and basic auth is not valid")
			return
		}
	}
	req.URL.User = url.User(user)
	if m.headerField != "" {
		req.Header[m.headerField] = []string{user}
	}

	if m.removeHeader {
		req.Header.Del(authorizationHeader)
	}

	fmt.Println("Request authorized")
	m.next.ServeHTTP(rw, req)
}

func (m *Middleware) secretBasic(user, realm string) string {
	if secret, ok := m.users[user]; ok {
		return secret
	}

	return ""
}

func basicUserParser(user string) (string, string, error) {
	split := strings.Split(user, ":")
	if len(split) != 2 {
		return "", "", fmt.Errorf("error parsing BasicUser: %v", user)
	}
	return split[0], split[1], nil
}
