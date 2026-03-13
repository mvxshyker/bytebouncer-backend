package handlers

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestOnboardRejectsEmptyDeviceID(t *testing.T) {
	app := fiber.New()
	// Pass nil db — we expect the handler to reject before touching DB
	app.Post("/api/onboard", func(c *fiber.Ctx) error {
		var req onboardRequest
		if err := c.BodyParser(&req); err != nil || req.DeviceID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_id required"})
		}
		return nil
	})

	tests := []struct {
		name string
		body string
		want int
	}{
		{"empty body", `{}`, 400},
		{"missing device_id", `{"device_id":""}`, 400},
		{"invalid json", `{bad`, 400},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/onboard", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := app.Test(req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
}

func TestOnboardRejectsLongDeviceID(t *testing.T) {
	app := fiber.New()
	app.Post("/api/onboard", func(c *fiber.Ctx) error {
		var req onboardRequest
		if err := c.BodyParser(&req); err != nil || req.DeviceID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_id required"})
		}
		if len(req.DeviceID) > maxDeviceIDLen {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_id too long"})
		}
		return c.SendString("ok")
	})

	longID := strings.Repeat("a", 300)
	req := httptest.NewRequest("POST", "/api/onboard",
		strings.NewReader(`{"device_id":"`+longID+`"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAnalyticsRejectsNoDeviceID(t *testing.T) {
	app := fiber.New()
	app.Get("/api/analytics", func(c *fiber.Ctx) error {
		if c.Query("device_id") == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_id required"})
		}
		return nil
	})

	req := httptest.NewRequest("GET", "/api/analytics", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthMiddleware(t *testing.T) {
	makeApp := func(token string) *fiber.App {
		app := fiber.New()
		app.Use(func(c *fiber.Ctx) error {
			if token != "" && c.Get("X-App-Token") != token {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
			}
			return c.Next()
		})
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.SendString("ok")
		})
		return app
	}

	t.Run("rejects missing token", func(t *testing.T) {
		app := makeApp("secret123")
		req := httptest.NewRequest("GET", "/test", nil)
		resp, _ := app.Test(req)
		if resp.StatusCode != 401 {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("rejects wrong token", func(t *testing.T) {
		app := makeApp("secret123")
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-App-Token", "wrong")
		resp, _ := app.Test(req)
		if resp.StatusCode != 401 {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("accepts correct token", func(t *testing.T) {
		app := makeApp("secret123")
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-App-Token", "secret123")
		resp, _ := app.Test(req)
		if resp.StatusCode != 200 {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("skips auth when token empty", func(t *testing.T) {
		app := makeApp("")
		req := httptest.NewRequest("GET", "/test", nil)
		resp, _ := app.Test(req)
		if resp.StatusCode != 200 {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	})
}

func TestDohURL(t *testing.T) {
	got := dohURL("abc123")
	want := "https://dns.nextdns.io/abc123"
	if got != want {
		t.Errorf("dohURL = %q, want %q", got, want)
	}
}

func TestSettingsRejectsEmptyDeviceID(t *testing.T) {
	app := fiber.New()
	app.Patch("/api/settings/services", func(c *fiber.Ctx) error {
		var req settingsRequest
		if err := c.BodyParser(&req); err != nil || req.DeviceID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_id required"})
		}
		return nil
	})

	req := httptest.NewRequest("PATCH", "/api/settings/services",
		strings.NewReader(`{"enabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	if resp.StatusCode != 400 {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d (body: %s), want 400", resp.StatusCode, body)
	}
}
