package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aleksa-hubgit/auth-service/data"
	"github.com/golang-jwt/jwt/v5"
)

var secretKey = []byte("secret-key")

type UserResponse struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
}

type TokenResponse struct {
	Token string `json:"token"`
	Refresh bool `json:"refresh"`
}

type Service interface {
	AuthUser(context.Context, AuthRequest) (*string, error)
	VerifyToken(context.Context, string) (*string, bool, error)
}

type AuthService struct {
	database *data.Queries
	httpClient http.Client
}

func NewAuthService(database *data.Queries, httpClient http.Client) Service {
	return &AuthService{database: database, httpClient: httpClient}
}

func (s *AuthService) AuthUser(ctx context.Context, ar AuthRequest) (*string, error) {
	resp, err := s.httpClient.Get(fmt.Sprintf("http://user-service:8080/%s", ar.Username))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("invalid credentials")
	}
	var userResp UserResponse
	err = json.NewDecoder(resp.Body).Decode(&userResp)
	if err != nil {
		return nil, err
	}
	if userResp.Password != ar.Password || userResp.Username != ar.Username {
		return nil, errors.New("invalid credentials")
	}


	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": ar.Username,
		"exp":      time.Now().Add(time.Minute * 30).Unix(),
	})
	tokenString, err := token.SignedString(secretKey)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": ar.Username,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})
	if err != nil {
		return nil, err
	}
	refreshTokenString, err := refreshToken.SignedString(secretKey)
	if err != nil {
		return nil, err
	}
	s.database.CreateToken(ctx, data.CreateTokenParams{ Tokenstring: refreshTokenString, Username: ar.Username})
	return &tokenString, nil
}

func (s *AuthService) refreshToken(username string) (*string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Minute * 30).Unix(),
	})
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return nil, err
	}
	return &tokenString, nil
}

func (s *AuthService) VerifyToken(ctx context.Context, tokenString string) (*string,bool, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return nil, false, err
	}
	claims := token.Claims.(jwt.MapClaims)
	username := claims["username"].(string)

	if !token.Valid {
		validRefresh, refreshID := s.hasValidRefresh(ctx, username)
		if validRefresh {
			newToken, err := s.refreshToken(username)
			if err != nil {
				return nil, false, err
			}
			return newToken, true, nil
		} else {
			err := s.deleteRefreshToken(ctx, refreshID)
			if err != nil {
				return nil, false, err
			}
			return nil, false, errors.New("invalid token")
		}
	}
	return &tokenString, false, nil
}

func (s *AuthService) hasValidRefresh(ctx context.Context, username string) (bool, int32) {
	token, err := s.database.GetTokenByUsername(ctx, username)
	if err != nil {
		return false,-1
	}
	refreshToken, err := jwt.Parse(token.Tokenstring, func(t *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return false,-1
	}
	return refreshToken.Valid, token.ID
}

func (s *AuthService) deleteRefreshToken(ctx context.Context, tokenID int32) error {
	return s.database.DeleteToken(ctx, tokenID)
}
