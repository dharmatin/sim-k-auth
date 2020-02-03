package internal

import (
	"errors"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

type jwtTokenMock struct{}

func TestNewWithClaims(t *testing.T) {

	claimsTests := []struct {
		claims   Claims
		expected *jwt.Token
		err      error
	}{
		{
			Claims{},
			nil,
			errors.New("Claims not empty"),
		},
		{
			Claims{
				Group: "test",
			},
			&jwt.Token{},
			nil,
		},
	}
	for _, tt := range claimsTests {
		err := JwtToken.NewWithClaims(tt.claims)
		assert.Equal(t, tt.err, err)
	}
}

func TestSignedString(t *testing.T) {
	signedToken, err := JwtToken.SignedString()
	assert.Nil(t, err)
	assert.NotNil(t, signedToken)
	assert.NotEmpty(t, signedToken)
}

func TestParseTokenWithClaim(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6IiIsIkVtYWlsIjoiIiwiR3JvdXAiOiJ0ZXN0In0.wQtxGVkqXg0ViEeSimJmXPOvqlynayamOCO9D5tHh_4"
	claims, err := JwtToken.ParseWithClaims(tokenString)
	assert.NotNil(t, claims)
	assert.Equal(t, "test", claims.Group)
	assert.Nil(t, err)
}

func TestParseInvalidTokenParsed(t *testing.T) {
	tokenString := "invalid token"
	claims, err := JwtToken.ParseWithClaims(tokenString)
	assert.Nil(t, claims)
	assert.NotNil(t, err)
}
