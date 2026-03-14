package handlers

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mvxshyker/bytebouncer-backend/database"
)

// AuthConfig holds auth-related configuration.
type AuthConfig struct {
	JWTSecret string
	BundleID  string
}

// --- Apple JWKS (cached) ---

type appleKey struct {
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

var (
	appleKeys   []appleKey
	appleKeysMu sync.RWMutex
)

func fetchAppleKeys() ([]appleKey, error) {
	appleKeysMu.RLock()
	if len(appleKeys) > 0 {
		defer appleKeysMu.RUnlock()
		return appleKeys, nil
	}
	appleKeysMu.RUnlock()

	resp, err := http.Get("https://appleid.apple.com/auth/keys")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var result struct {
		Keys []appleKey `json:"keys"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	appleKeysMu.Lock()
	appleKeys = result.Keys
	appleKeysMu.Unlock()
	return result.Keys, nil
}

func findAppleKey(kid string) (*rsa.PublicKey, error) {
	keys, err := fetchAppleKeys()
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if k.KID == kid {
			nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
			if err != nil {
				return nil, err
			}
			eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
			if err != nil {
				return nil, err
			}
			n := new(big.Int).SetBytes(nBytes)
			e := new(big.Int).SetBytes(eBytes)
			return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
		}
	}
	return nil, fmt.Errorf("apple key %s not found", kid)
}

// --- Token helpers ---

func IssueAccessToken(secret, userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func issueRefreshToken(secret, userID string) (string, time.Time, error) {
	exp := time.Now().Add(30 * 24 * time.Hour)
	claims := jwt.MapClaims{
		"sub":  userID,
		"iat":  time.Now().Unix(),
		"exp":  exp.Unix(),
		"type": "refresh",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	return signed, exp, err
}

// --- Handlers ---

type appleAuthRequest struct {
	IdentityToken string `json:"identity_token"`
}

// AppleAuth exchanges an Apple identity token for access + refresh tokens.
func AppleAuth(db *database.Pool, cfg AuthConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req appleAuthRequest
		if err := c.BodyParser(&req); err != nil || req.IdentityToken == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "identity_token required"})
		}

		// Parse the Apple JWT header to get the key ID
		parser := jwt.NewParser()
		appleToken, _, err := parser.ParseUnverified(req.IdentityToken, jwt.MapClaims{})
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid identity token"})
		}

		kid, ok := appleToken.Header["kid"].(string)
		if !ok {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing kid in token header"})
		}

		// Verify the token with Apple's public key
		pubKey, err := findAppleKey(kid)
		if err != nil {
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "failed to fetch Apple keys"})
		}

		verified, err := jwt.Parse(req.IdentityToken, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return pubKey, nil
		}, jwt.WithValidMethods([]string{"RS256"}))
		if err != nil || !verified.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid Apple token"})
		}

		claims, ok := verified.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid claims"})
		}

		// Validate issuer and audience
		iss, _ := claims["iss"].(string)
		aud, _ := claims["aud"].(string)
		if iss != "https://appleid.apple.com" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid issuer"})
		}
		if cfg.BundleID != "" && aud != cfg.BundleID {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid audience"})
		}

		appleUserID, _ := claims["sub"].(string)
		email, _ := claims["email"].(string)
		if appleUserID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing sub claim"})
		}

		// Upsert user
		userID, err := database.CreateAppleUser(c.Context(), db, appleUserID, email)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
		}

		// Issue tokens
		accessToken, err := IssueAccessToken(cfg.JWTSecret, userID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token error"})
		}
		refreshToken, refreshExp, err := issueRefreshToken(cfg.JWTSecret, userID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token error"})
		}

		// Store refresh token
		if err := database.SetRefreshToken(c.Context(), db, userID, refreshToken, refreshExp); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
		}

		// Check if user has a NextDNS profile already
		user, _ := database.GetUserByID(c.Context(), db, userID)
		hasProfile := user != nil && user.ProfileID != ""

		return c.JSON(fiber.Map{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"user_id":       userID,
			"has_profile":   hasProfile,
		})
	}
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Refresh exchanges a valid refresh token for a new access token.
func Refresh(db *database.Pool, cfg AuthConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req refreshRequest
		if err := c.BodyParser(&req); err != nil || req.RefreshToken == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "refresh_token required"})
		}

		// Parse and validate the refresh token
		token, err := jwt.Parse(req.RefreshToken, func(t *jwt.Token) (any, error) {
			return []byte(cfg.JWTSecret), nil
		})
		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid refresh token"})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid claims"})
		}
		userID, _ := claims["sub"].(string)
		tokenType, _ := claims["type"].(string)
		if userID == "" || tokenType != "refresh" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token type"})
		}

		// Verify it matches the stored refresh token
		storedToken, storedExp, err := database.GetRefreshToken(c.Context(), db, userID)
		if err != nil || storedToken != req.RefreshToken || time.Now().After(storedExp) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "refresh token expired or revoked"})
		}

		// Issue new access token
		accessToken, err := IssueAccessToken(cfg.JWTSecret, userID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token error"})
		}

		return c.JSON(fiber.Map{"access_token": accessToken})
	}
}

// Logout invalidates the user's refresh token.
func Logout(db *database.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID, _ := c.Locals("user_id").(string)
		if userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		if err := database.ClearRefreshToken(c.Context(), db, userID); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
		}
		return c.JSON(fiber.Map{"ok": true})
	}
}

// LinkDevice links an existing device_id to the authenticated Apple user.
func LinkDevice(db *database.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID, _ := c.Locals("user_id").(string)
		if userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		var req struct {
			DeviceID string `json:"device_id"`
		}
		if err := c.BodyParser(&req); err != nil || req.DeviceID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_id required"})
		}

		// Find existing user by device_id and transfer their profile
		existing, err := database.GetUserByDeviceID(c.Context(), db, req.DeviceID)
		if err == nil && existing.ProfileID != "" {
			// Transfer the NextDNS profile to the Apple-authed user
			if err := database.SetProfileID(c.Context(), db, userID, existing.ProfileID); err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
			}
		}

		if err := database.LinkDeviceToAppleUser(c.Context(), db, userID, req.DeviceID); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
		}

		return c.JSON(fiber.Map{"ok": true})
	}
}
