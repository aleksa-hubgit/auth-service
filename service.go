package main

import (
	"bytes"
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
	Login(context.Context, LoginRequest) (*string, error)
	Verify(context.Context, string) (*string, bool, error)
	Register(context.Context, RegisterRequest) error
}

type AuthService struct {
	database *data.Queries
	httpClient http.Client
}

func NewAuthService(database *data.Queries, httpClient http.Client) Service {
	return &AuthService{database: database, httpClient: httpClient}
}

func (s *AuthService) Login(ctx context.Context, lr LoginRequest) (*string, error) {
	resp, err := s.httpClient.Get(fmt.Sprintf("http://user-service:8080/%s", lr.Username))
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
	if userResp.Password != lr.Password || userResp.Username != lr.Username {
		return nil, errors.New("invalid credentials")
	}


	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": lr.Username,
		"exp":      time.Now().Add(time.Minute * 30).Unix(),
	})
	tokenString, err := token.SignedString(secretKey)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": lr.Username,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})
	if err != nil {
		return nil, err
	}
	refreshTokenString, err := refreshToken.SignedString(secretKey)
	if err != nil {
		return nil, err
	}
	s.database.CreateToken(ctx, data.CreateTokenParams{ Tokenstring: refreshTokenString, Username: lr.Username})
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

func (s *AuthService) Verify(ctx context.Context, tokenString string) (*string,bool, error) {
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
func (s *AuthService) Register(ctx context.Context, rr RegisterRequest) error {
	requestBody, err := json.Marshal(rr)
	if err != nil {
		return err
	}
	req , err := http.NewRequestWithContext(ctx, "POST", "http://user-service:8080/users", bytes.NewBuffer(requestBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("could not register user")
	}
	return nil
}
