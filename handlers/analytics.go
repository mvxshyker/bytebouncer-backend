package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/mvxshyker/bytebouncer-backend/database"
	"github.com/mvxshyker/bytebouncer-backend/services"
)

func Analytics(db *database.Pool, dns *services.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// JWT auth path
		if userID, ok := c.Locals("user_id").(string); ok && userID != "" {
			user, err := database.GetUserByID(c.Context(), db, userID)
			if err != nil {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
			}
			if user.ProfileID == "" {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "not onboarded"})
			}
			analytics, err := dns.GetAnalytics(c.Context(), user.ProfileID)
			if err != nil {
				return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "failed to fetch analytics"})
			}
			return c.JSON(analytics)
		}

		// Legacy path: device_id from query param
		deviceID := c.Query("device_id")
		if deviceID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_id required"})
		}
		if len(deviceID) > maxDeviceIDLen {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_id too long"})
		}

		user, err := database.GetUserByDeviceID(c.Context(), db, deviceID)
		if err == pgx.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "device not found"})
		}
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
		}

		analytics, err := dns.GetAnalytics(c.Context(), user.ProfileID)
		if err != nil {
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "failed to fetch analytics"})
		}

		return c.JSON(analytics)
	}
}
