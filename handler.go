package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)


type Handler interface {
	Login(c *gin.Context)
	Verify(c *gin.Context)
	Register(c *gin.Context)
}

type AuthHandler struct {
	service Service
}

func NewAuthHandler(service Service) Handler {
	return &AuthHandler{service}
}


func (h *AuthHandler) Verify(ctx *gin.Context) {
	bearerToken := ctx.Request.Header.Get("Authorization")
	if bearerToken == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"message": "unauthorized",
		})
		return
	}
	tokenString := strings.Split(bearerToken, " ")[1]
	token, refresh, err := h.service.Verify(ctx, tokenString)
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

func (h *AuthHandler) Login(ctx *gin.Context) {
	var loginRequest LoginRequest

	if err := ctx.ShouldBindJSON(&loginRequest); err != nil {
        ctx.JSON(http.StatusBadRequest, gin.H{
            "message": "invalid request",
            "error": err.Error(),
        })
        return
    }
	token, err := h.service.Login(ctx, loginRequest)
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

func (h *AuthHandler) Register(ctx *gin.Context) {
	var registerRequest RegisterRequest

	if err := ctx.ShouldBindJSON(&registerRequest); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request",
			"error": err.Error(),
		})
		return
	}
	err := h.service.Register(ctx, registerRequest)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request",
			"error": err.Error(),
		})
		return 
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message": "success",
	})
}


