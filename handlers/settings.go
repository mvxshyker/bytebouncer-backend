package handlers

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/mvxshyker/bytebouncer-backend/database"
	"github.com/mvxshyker/bytebouncer-backend/services"
)

type settingsRequest struct {
	DeviceID string `json:"device_id"`
	Enabled  bool   `json:"enabled"`
}

// lookupProfile parses the request body and resolves the NextDNS profile ID.
func lookupProfile(c *fiber.Ctx, db *database.Pool) (profileID string, enabled bool, err error) {
	var req settingsRequest
	if parseErr := c.BodyParser(&req); parseErr != nil || req.DeviceID == "" {
		return "", false, c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_id required"})
	}
	user, dbErr := database.GetUserByDeviceID(c.Context(), db, req.DeviceID)
	if dbErr == pgx.ErrNoRows {
		return "", false, c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "device not found"})
	}
	if dbErr != nil {
		return "", false, c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
	}
	return user.ProfileID, req.Enabled, nil
}

// SettingsServices toggles social media blocking (instagram, tiktok, youtube, facebook).
func SettingsServices(db *database.Pool, dns *services.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		profileID, enabled, err := lookupProfile(c, db)
		if err != nil {
			return err
		}
		ids := []string{"instagram", "tiktok", "youtube", "facebook"}
		for _, id := range ids {
			if err := dns.Toggle(c.Context(), profileID, "parentalcontrol/services", id, enabled); err != nil {
				log.Printf("error: toggle services/%s: %v", id, err)
				return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "failed to update settings"})
			}
		}
		return c.JSON(fiber.Map{"ok": true})
	}
}

// SettingsNatives toggles analytics/crash reporting (apple).
func SettingsNatives(db *database.Pool, dns *services.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		profileID, enabled, err := lookupProfile(c, db)
		if err != nil {
			return err
		}
		if err := dns.Toggle(c.Context(), profileID, "privacy/natives", "apple", enabled); err != nil {
			log.Printf("error: toggle natives/apple: %v", err)
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "failed to update settings"})
		}
		return c.JSON(fiber.Map{"ok": true})
	}
}

// SettingsBlocklists toggles ad network blocking (adguard).
func SettingsBlocklists(db *database.Pool, dns *services.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		profileID, enabled, err := lookupProfile(c, db)
		if err != nil {
			return err
		}
		if err := dns.Toggle(c.Context(), profileID, "privacy/blocklists", "adguard-dns-filter", enabled); err != nil {
			log.Printf("error: toggle blocklists/adguard-dns-filter: %v", err)
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "failed to update settings"})
		}
		return c.JSON(fiber.Map{"ok": true})
	}
}
