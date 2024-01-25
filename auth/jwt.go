package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	nerrors "errors"
	"log"
	"math"
	"net/http"
	"os"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

// MethodJWTAuth is used to identify JWTAuth auth.
const MethodJWTAuth settings.AuthMethod = "jwt-header"

// JWTAuth is a JWTAuth implementation of an auther.
type JWTAuth struct {
	CertsURL      string `json:"certsurl"`
	Aud           string `json:"aud"`
	Iss           string `json:"iss"`
	UsernameClaim string `json:"usernameClaim"`
	Header        string `json:"header"`
	remoteKeySet  *oidc.RemoteKeySet
	init          sync.Once
}

// Auth authenticates the user via a JWT token in an HTTP header.
func (a *JWTAuth) Auth(r *http.Request, usr users.Store, stg *settings.Settings, srv *settings.Server) (*users.User, error) {
	a.init.Do(func() {
		a.remoteKeySet = oidc.NewRemoteKeySet(context.Background(), a.CertsURL)
	})

	accessJWT := r.Header.Get(a.Header)
	if accessJWT == "" {
		return nil, os.ErrPermission
	}

	// The Application Audience (AUD) tag for your application
	config := &oidc.Config{
		ClientID: a.Aud,
	}

	verifier := oidc.NewVerifier(a.Iss, a.remoteKeySet, config)

	token, err := verifier.Verify(r.Context(), accessJWT)
	if err != nil {
		return nil, os.ErrPermission
	}

	payload := map[string]any{}
	err = token.Claims(&payload)
	if err != nil {
		return nil, os.ErrPermission
	}

	user, err := usr.Get(srv.Root, payload[a.UsernameClaim])
	if nerrors.Is(err, errors.ErrNotExist) {
		user, err := a.createNewUser(payload[a.UsernameClaim].(string), usr, stg, srv)
		if err != nil {
			return nil, err
		}
		return user, nil
	}

	return user, err
}

// LoginPage tells that proxy auth doesn't require a login page.
func (a *JWTAuth) LoginPage() bool {
	return false
}

func (a *JWTAuth) createNewUser(name string, usr users.Store, stg *settings.Settings, srv *settings.Server) (*users.User, error) {
	rnd, err := randomBase64String(16)
	if err != nil {
		return nil, err
	}
	pwd, err := users.HashPwd(rnd)
	if err != nil {
		return nil, err
	}

	user := &users.User{
		Username:     name,
		Password:     pwd,
		LockPassword: true,
	}
	stg.Defaults.Apply(user)

	home, err := stg.MakeUserDir(user.Username, user.Scope, srv.Root)
	if err != nil {
		return nil, err
	}
	user.Scope = home

	err = usr.Save(user)
	if nerrors.Is(err, errors.ErrExist) {
		user, err := usr.Get(srv.Root, user.Username)
		if err != nil {
			return nil, err
		}
		return user, nil
	} else if err != nil {
		return nil, err
	}

	log.Printf("new user: %s, home dir: [%s].", user.Username, user.Scope)

	return user, nil
}

// see: https://stackoverflow.com/a/55860599
func randomBase64String(l int) (string, error) {
	buff := make([]byte, int(math.Ceil(float64(l)*0.75)))
	_, err := rand.Read(buff)
	if err != nil {
		return "", err
	}
	str := base64.RawURLEncoding.EncodeToString(buff)
	return str[:l], nil
}
