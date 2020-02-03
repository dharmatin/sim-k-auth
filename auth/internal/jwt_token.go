package internal

import (
	"errors"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	ApplicationName         = "SIM-K Authentication Service"
	LoginExpirationDuration = time.Duration(1) * time.Hour
	JwtSigningMethod        = jwt.SigningMethodHS256
	JwtSignatureKey         = []byte(os.Getenv(("JWT_SIGNATURE_KEY")))
)

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
		return errors.New("Claims not empty")
	}
	claims = Claims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    ApplicationName,
			ExpiresAt: time.Now().Add(LoginExpirationDuration).Unix(),
		},
		Username: claims.Username,
		Email:    claims.Email,
		Group:    claims.Group,
	}
	t.Token = jwt.NewWithClaims(JwtSigningMethod, claims)
	return nil
}

func (t *jwtToken) SignedString() (string, error) {
	return t.Token.SignedString(JwtSignatureKey)
}

func (t jwtToken) ParseWithClaims(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(JwtSignatureKey), nil
	})
	if err == nil {
		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
			return claims, nil
		}
	}

	return nil, err
}
