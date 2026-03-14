package main

import (
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/mvxshyker/bytebouncer-backend/database"
	"github.com/mvxshyker/bytebouncer-backend/handlers"
	"github.com/mvxshyker/bytebouncer-backend/services"
)

func main() {
	_ = godotenv.Load()

	appToken := os.Getenv("APP_TOKEN")
	jwtSecret := os.Getenv("JWT_SECRET")
	bundleID := os.Getenv("APPLE_BUNDLE_ID")

	authCfg := handlers.AuthConfig{
		JWTSecret: jwtSecret,
		BundleID:  bundleID,
	}
	rcCfg := handlers.RevenueCatConfig{
		APIKey:        os.Getenv("REVENUECAT_API_KEY"),
		WebhookSecret: os.Getenv("REVENUECAT_WEBHOOK_SECRET"),
	}

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

	// Health check — no auth
	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	api := app.Group("/api")

	// Public auth routes — no auth required
	api.Post("/auth/apple", handlers.AppleAuth(db, authCfg))
	api.Post("/auth/refresh", handlers.Refresh(db, authCfg))

	// RevenueCat webhook — authenticated by its own secret
	api.Post("/webhooks/revenuecat", handlers.RevenueCatWebhook(db, rcCfg))

	// Protected routes — dual auth (JWT or legacy X-App-Token)
	protected := api.Group("", dualAuthMiddleware(appToken, jwtSecret))

	// Auth-required routes
	protected.Post("/auth/logout", handlers.Logout(db))
	protected.Post("/auth/link-device", handlers.LinkDevice(db))
	protected.Get("/subscription/status", handlers.SubscriptionStatus(db))

	// Existing routes (now support both auth methods)
	protected.Post("/onboard", handlers.Onboard(db, dns))
	protected.Get("/analytics", handlers.Analytics(db, dns))
	protected.Patch("/settings/services", handlers.SettingsServices(db, dns))
	protected.Patch("/settings/natives", handlers.SettingsNatives(db, dns))
	protected.Patch("/settings/blocklists", handlers.SettingsBlocklists(db, dns))

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

// dualAuthMiddleware supports both JWT Bearer tokens (new) and X-App-Token (legacy).
// If a Bearer token is present, it validates it and sets user_id in locals.
// If X-App-Token is present, it validates against the static app token (legacy flow).
func dualAuthMiddleware(appToken, jwtSecret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Try JWT Bearer token first
		authHeader := c.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

			token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fiber.ErrUnauthorized
				}
				return []byte(jwtSecret), nil
			})

			if err != nil || !token.Valid {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid claims"})
			}

			// Don't accept refresh tokens as access tokens
			if tokenType, _ := claims["type"].(string); tokenType == "refresh" {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token type"})
			}

			userID, _ := claims["sub"].(string)
			if userID == "" {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
			}

			c.Locals("user_id", userID)
			return c.Next()
		}

		// Fallback: legacy X-App-Token
		if appToken != "" && c.Get("X-App-Token") == appToken {
			return c.Next()
		}

		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
}
