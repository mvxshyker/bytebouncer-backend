package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/mvxshyker/bytebouncer-backend/database"
	"github.com/mvxshyker/bytebouncer-backend/handlers"
	"github.com/mvxshyker/bytebouncer-backend/services"
)

func main() {
	appToken := os.Getenv("APP_TOKEN")

	db, err := database.Connect(os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}
	defer db.Close()

	if err := database.Migrate(db); err != nil {
		log.Fatalf("db migrate: %v", err)
	}

	dns := services.NewClient("https://api.nextdns.io", os.Getenv("NEXTDNS_API_KEY"))

	app := fiber.New()
	app.Use(recover.New())
	app.Use(compress.New())
	app.Use(logger.New(logger.Config{
		Format: "${time} ${status} ${method} ${path} ${latency}\n",
	}))
	app.Use(authMiddleware(appToken))

	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	api := app.Group("/api")
	api.Post("/onboard", handlers.Onboard(db, dns))
	api.Get("/analytics", handlers.Analytics(db, dns))
	api.Patch("/settings/services", handlers.SettingsServices(db, dns))
	api.Patch("/settings/natives", handlers.SettingsNatives(db, dns))
	api.Patch("/settings/blocklists", handlers.SettingsBlocklists(db, dns))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Println("shutting down...")
		_ = app.Shutdown()
	}()

	log.Printf("listening on :%s", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func authMiddleware(appToken string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if c.Path() == "/healthz" {
			return c.Next()
		}
		if appToken != "" && c.Get("X-App-Token") != appToken {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		return c.Next()
	}
}
