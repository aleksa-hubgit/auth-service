package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)


type Handler interface {
	AuthUser(c *gin.Context)
	VerifyToken(c *gin.Context)
}

type AuthHandler struct {
	service Service
}

func NewAuthHandler(service Service) Handler {
	return &AuthHandler{service}
}


func (h *AuthHandler) VerifyToken(ctx *gin.Context) {
	bearerToken := ctx.Request.Header.Get("Authorization")
	if bearerToken == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"message": "unauthorized",
		})
		return
	}
	tokenString := strings.Split(bearerToken, " ")[1]
	token, refresh, err := h.service.VerifyToken(ctx, tokenString)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"message": "unauthorized",
		})
		return 
	}
	if refresh {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "refresh",
			"token": token,
		})
		return 
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "authorized",
	})
}

func (h *AuthHandler) AuthUser(ctx *gin.Context) {
	var authRequest AuthRequest

	if err := ctx.ShouldBindJSON(&authRequest); err != nil {
        ctx.JSON(http.StatusBadRequest, gin.H{
            "message": "invalid request",
            "error": err.Error(),
        })
        return
    }
	token, err := h.service.AuthUser(ctx, authRequest)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid credentials",
			"error": err.Error(),
		})
		return 
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message": "success",
		"token": token,
	})
}


