package handlers

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/mvxshyker/bytebouncer-backend/database"
)

type RevenueCatConfig struct {
	APIKey        string
	WebhookSecret string
}

// SubscriptionStatus returns the current subscription status for the authenticated user.
func SubscriptionStatus(db *database.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID, _ := c.Locals("user_id").(string)
		if userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		user, err := database.GetUserByID(c.Context(), db, userID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
		}
		return c.JSON(fiber.Map{
			"status":     user.SubStatus,
			"has_profile": user.ProfileID != "",
		})
	}
}

// RevenueCatWebhook handles subscription events from RevenueCat.
func RevenueCatWebhook(db *database.Pool, cfg RevenueCatConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Verify webhook secret
		authHeader := c.Get("Authorization")
		expected := "Bearer " + cfg.WebhookSecret
		if subtle.ConstantTimeCompare([]byte(authHeader), []byte(expected)) != 1 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}

		var event struct {
			Event struct {
				Type           string `json:"type"`
				AppUserID      string `json:"app_user_id"`
				ExpirationAtMs int64  `json:"expiration_at_ms"`
			} `json:"event"`
		}
		if err := c.BodyParser(&event); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
		}

		userID := event.Event.AppUserID
		if userID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing app_user_id"})
		}

		var status string
		var expiresAt *time.Time

		switch event.Event.Type {
		case "INITIAL_PURCHASE", "RENEWAL", "UNCANCELLATION":
			status = "active"
			if event.Event.ExpirationAtMs > 0 {
				t := time.UnixMilli(event.Event.ExpirationAtMs)
				expiresAt = &t
			}
		case "CANCELLATION", "EXPIRATION":
			status = "expired"
			if event.Event.ExpirationAtMs > 0 {
				t := time.UnixMilli(event.Event.ExpirationAtMs)
				expiresAt = &t
			}
		case "BILLING_ISSUE_DETECTED":
			status = "grace_period"
			if event.Event.ExpirationAtMs > 0 {
				t := time.UnixMilli(event.Event.ExpirationAtMs)
				expiresAt = &t
			}
		default:
			log.Printf("revenuecat: unhandled event type %s for user %s", event.Event.Type, userID)
			return c.JSON(fiber.Map{"ok": true})
		}

		if err := database.UpdateSubscription(c.Context(), db, userID, status, expiresAt); err != nil {
			log.Printf("revenuecat: failed to update subscription for %s: %v", userID, err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
		}

		log.Printf("revenuecat: %s → %s for user %s", event.Event.Type, status, userID)
		return c.JSON(fiber.Map{"ok": true})
	}
}

// CheckSubscriptionRC verifies subscription via RevenueCat REST API (on-demand).
func CheckSubscriptionRC(apiKey, userID string) (string, *time.Time, error) {
	req, err := http.NewRequest("GET",
		fmt.Sprintf("https://api.revenuecat.com/v1/subscribers/%s", userID), nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", nil, err
	}

	if resp.StatusCode != 200 {
		return "none", nil, nil
	}

	var result struct {
		Subscriber struct {
			Entitlements map[string]struct {
				ExpiresDate string `json:"expires_date"`
			} `json:"entitlements"`
		} `json:"subscriber"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", nil, err
	}

	// Check for "pro" entitlement
	ent, ok := result.Subscriber.Entitlements["pro"]
	if !ok {
		return "none", nil, nil
	}

	expTime, err := time.Parse(time.RFC3339, ent.ExpiresDate)
	if err != nil {
		return "active", nil, nil
	}

	if time.Now().After(expTime) {
		return "expired", &expTime, nil
	}
	return "active", &expTime, nil
}
