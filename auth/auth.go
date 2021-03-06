package auth

import (
	"github.com/dharmatin/sim-k-auth/auth/internal"
	"github.com/dharmatin/sim-k-utils/rest_error"
)

type AuthRequest struct {
	Username string
	Email    string
	Group    string
}

type AuthInterface interface {
	GenerateToken(AuthRequest) (string, rest_error.RestError)
	GetTokenInfo(string) (*internal.Claims, rest_error.RestError)
}
type auth struct {
	jwtToken internal.JWTTokenInterface
}

var (
	Auth AuthInterface
)

func init() {
	Auth = auth{
		jwtToken: internal.JwtToken,
	}
}

func (a auth) GenerateToken(request AuthRequest) (string, rest_error.RestError) {
	r := internal.Claims{
		Username: request.Username,
		Email:    request.Email,
		Group:    request.Group,
	}
	if err := a.jwtToken.NewWithClaims(r); err != nil {
		return "", rest_error.NewUnauthorizedError(err.Error())
	}
	signedToken, err := a.jwtToken.SignedString()
	if err != nil {
		return "", rest_error.NewUnauthorizedError(err.Error())
	}
	return signedToken, nil
}

func (a auth) GetTokenInfo(token string) (*internal.Claims, rest_error.RestError) {
	result, err := a.jwtToken.ParseWithClaims(token)
	if err != nil {
		return nil, rest_error.NewUnauthorizedError(err.Error())
	}
	return result, nil
}
