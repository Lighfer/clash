package auth

import (
	"net"
	"strings"
	"sync"

	"github.com/Dreamacro/clash/log"
)

type Authenticator interface {
	Verify(user string, pass string) bool
	Users() []string
	IsSkip(addr string) bool
}

type AuthUser struct {
	User string
	Pass string
}

type inMemoryAuthenticator struct {
	storage   *sync.Map
	usernames []string
	skips     []*net.IPNet
}

func (au *inMemoryAuthenticator) Verify(user string, pass string) bool {
	realPass, ok := au.storage.Load(user)
	return ok && realPass == pass
}

func (au *inMemoryAuthenticator) Users() []string { return au.usernames }

func (au *inMemoryAuthenticator) IsSkip(addr string) bool {
	if addr != "" {
		addr = strings.Split(addr, ":")[0]
		ip := net.ParseIP(addr)
		if ip != nil {
			for _, ipNet := range au.skips {
				if ipNet.Contains(ip) {
					log.Infoln("%s skips the authentication by authentication-exclude %s", addr, ipNet.String())
					return true
				}
			}
		}
	}

	return false
}

func NewAuthenticator(users []AuthUser, skips []*net.IPNet) Authenticator {
	if len(users) == 0 {
		return nil
	}

	au := &inMemoryAuthenticator{storage: &sync.Map{}}
	for _, user := range users {
		au.storage.Store(user.User, user.Pass)
	}
	usernames := make([]string, 0, len(users))
	au.storage.Range(func(key, value any) bool {
		usernames = append(usernames, key.(string))
		return true
	})
	au.usernames = usernames

	au.skips = skips

	return au
}
