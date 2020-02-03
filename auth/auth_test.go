package auth

import (
	"errors"
	"testing"

	"github.com/dharmatin/sim-k-auth/auth/internal"
	"github.com/stretchr/testify/assert"
)

type jwtTokenMock struct{}

var (
	newWithClaimsError  func() error
	signedStringError   func() (string, error)
	parseWithClaimError func() (*internal.Claims, error)
)

func (j *jwtTokenMock) NewWithClaims(claims internal.Claims) error {
	return newWithClaimsError()
}

func (j *jwtTokenMock) SignedString() (string, error) {
	return signedStringError()
}

func (j jwtTokenMock) ParseWithClaims(token string) (*internal.Claims, error) {
	return parseWithClaimError()
}

func TestGenerateToken(t *testing.T) {
	token, restErr := Auth.GenerateToken(AuthRequest{
		Username: "test",
		Email:    "test@gmail.com",
		Group:    "admin",
	})
	assert.NotEmpty(t, token)
	assert.Nil(t, restErr)
}

func TestGenerateTokenWhenClaimsError(t *testing.T) {
	token, restErr := Auth.GenerateToken(AuthRequest{})
	assert.Empty(t, token)
	assert.NotNil(t, restErr)
	assert.Equal(t, "Claims not empty", restErr.Message())
}

func TestGenerateTokenWhenSignedStringHasAnError(t *testing.T) {
	Auth = auth{
		jwtToken: &jwtTokenMock{},
	}
	newWithClaimsError = func() error {
		return nil
	}
	signedStringError = func() (string, error) {
		return "", errors.New("Error When Getting Signed Token")
	}

	token, restErr := Auth.GenerateToken(AuthRequest{
		Username: "test",
		Email:    "test@gmail.com",
		Group:    "admin",
	})

	assert.Empty(t, token)
	assert.NotNil(t, restErr)
	assert.Equal(t, "Error When Getting Signed Token", restErr.Message())
}
