package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aleksa-hubgit/auth-service/data"
	"github.com/gin-gonic/gin"

	"github.com/jackc/pgx/v5"
)


func main() {
	username := os.Getenv("DATABASE_USERNAME")
	password := os.Getenv("DATABASE_PASSWORD")
	hostname := os.Getenv("DATABASE_HOSTNAME")
	port := os.Getenv("DATABASE_PORT")
	name := os.Getenv("DATABASE_NAME")
	connStr := fmt.Sprintf("postgresql://%s:%s@%s:%s/%s", username, password, hostname, port, name)
	// connStr := "postgresql://token:token@localhost:5432/token"
	fmt.Println(connStr)
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		log.Fatal(err)
	}
	database := data.New(conn)
	defer conn.Close(context.Background())

	httpClient := http.Client{Timeout: time.Duration(1) * time.Second}
	service := NewAuthService(database, httpClient)
	handler := NewAuthHandler(service)
	r := gin.Default()
	group := r.Group("/auth")
	{
		group.GET("/verify", handler.Verify)
		group.POST("/login", handler.Login)
		group.POST("/register", handler.Register)
	}
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("could not run server: %v", err)
	}
}