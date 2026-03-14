package handlers

import (
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/mvxshyker/bytebouncer-backend/database"
	"github.com/mvxshyker/bytebouncer-backend/services"
)

const maxDeviceIDLen = 256

type onboardRequest struct {
	DeviceID string `json:"device_id"`
}

func Onboard(db *database.Pool, dns *services.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// JWT auth path: user_id comes from token
		if userID, ok := c.Locals("user_id").(string); ok && userID != "" {
			return onboardJWT(c, db, dns, userID)
		}
		// Legacy path: device_id from request body
		return onboardLegacy(c, db, dns)
	}
}

func onboardJWT(c *fiber.Ctx, db *database.Pool, dns *services.Client, userID string) error {
	// Check if user already has a profile
	user, err := database.GetUserByID(c.Context(), db, userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
	}
	if user.ProfileID != "" {
		return c.JSON(fiber.Map{"doh_url": dohURL(user.ProfileID)})
	}

	// Create new NextDNS profile
	profileID, err := dns.CreateProfile(c.Context())
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "failed to create nextdns profile"})
	}

	if err := dns.EnableBlocklist(c.Context(), profileID, "oisd"); err != nil {
		log.Printf("warn: enable oisd for %s: %v", profileID, err)
	}

	if err := database.SetProfileID(c.Context(), db, userID, profileID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"doh_url": dohURL(profileID)})
}

func onboardLegacy(c *fiber.Ctx, db *database.Pool, dns *services.Client) error {
	var req onboardRequest
	if err := c.BodyParser(&req); err != nil || req.DeviceID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_id required"})
	}
	if len(req.DeviceID) > maxDeviceIDLen {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_id too long"})
	}

	existing, err := database.GetUserByDeviceID(c.Context(), db, req.DeviceID)
	if err == nil {
		return c.JSON(fiber.Map{"doh_url": dohURL(existing.ProfileID)})
	}
	if err != pgx.ErrNoRows {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
	}

	profileID, err := dns.CreateProfile(c.Context())
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "failed to create nextdns profile"})
	}

	if err := dns.EnableBlocklist(c.Context(), profileID, "oisd"); err != nil {
		log.Printf("warn: enable oisd for %s: %v", profileID, err)
	}

	savedProfileID, err := database.UpsertUser(c.Context(), db, req.DeviceID, profileID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"doh_url": dohURL(savedProfileID)})
}

func dohURL(profileID string) string {
	return fmt.Sprintf("https://dns.nextdns.io/%s", profileID)
}
