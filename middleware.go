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
	Users        []string `json:"users,omitempty"`
	UsersFile    string   `json:"usersFile,omitempty"`
	Realm        string   `json:"realm,omitempty"`
	RemoveHeader bool     `json:"removeHeader,omitempty"`
	HeaderField  string   `json:"headerField,omitempty"`
}

type IPWhiteList struct {
	SourceRange []string `json:"sourceRange,omitempty"`
}

// Config the plugin configuration.
type Config struct {
	BasicAuth   BasicAuth   `json:"basicAuth,omitempty"`
	IPWhiteList IPWhiteList `json:"ipWhiteList,omitempty"`
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

	// workaround to bug in traefik/paerser who format []string{"A", "B"} to string("24║A║B") or string("║A║B")
	// see: https://github.com/traefik/traefik/issues/9638
	config.IPWhiteList.SourceRange = stringToSliceHook(config.IPWhiteList.SourceRange)
	config.BasicAuth.Users = stringToSliceHook(config.BasicAuth.Users)

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

		req.URL.User = url.User(user)
		if m.headerField != "" {
			req.Header[m.headerField] = []string{user}
		}

		if m.removeHeader {
			req.Header.Del(authorizationHeader)
		}
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

func stringToSliceHook(data []string) []string {
	if strings.Contains(data[0], "║") {
		values := strings.Split(data[0], "║")
		if len(values) >= 2 && values[0] == "" && values[1] == "24" {
			return values[2:]
		}
		return values
	}
	return data
}
