package token

import (
	"errors"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var APPLICATION_NAME = "SIM-K Authentication Service"
var LOGIN_EXPIRATION_DURATION = time.Duration(1) * time.Hour
var JWT_SIGNING_METHOD = jwt.SigningMethodHS256
var JWT_SIGNATURE_KEY = []byte(os.Getenv("JWT_SIGNATURE"))

type Claims struct {
	jwt.StandardClaims
	Username string
	Email    string
	Group    string
}

type JWTTokenInterface interface {
	NewWithClaims(Claims) error
	SignedString() (string, error)
	ParseWithClaims(string) (*Claims, error)
}

type jwtToken struct {
	*jwt.Token
}

var (
	JwtToken JWTTokenInterface = &jwtToken{}
)

func (t *jwtToken) NewWithClaims(claims Claims) error {
	if claims == (Claims{}) {
		return errors.New("Claim not empty")
	}
	t.Token = jwt.NewWithClaims(JWT_SIGNING_METHOD, claims)
	return nil
}

func (t *jwtToken) SignedString() (string, error) {
	return t.Token.SignedString(JWT_SIGNATURE_KEY)
}

func (t jwtToken) ParseWithClaims(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(JWT_SIGNATURE_KEY), nil
	})
	if err == nil {
		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
			return claims, nil
		}
	}

	return nil, err
}
