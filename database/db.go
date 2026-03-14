package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Pool = pgxpool.Pool

func Connect(dsn string) (*Pool, error) {
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_URL is not set")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 10
	cfg.MinConns = 2
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.MaxConnLifetime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(context.Background()); err != nil {
		return nil, err
	}
	return pool, nil
}

func Migrate(db *Pool) error {
	_, err := db.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS users (
			id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			device_id          VARCHAR(256) UNIQUE,
			nextdns_profile_id VARCHAR NOT NULL,
			created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			apple_user_id      VARCHAR(256) UNIQUE,
			email              VARCHAR(256),
			refresh_token      VARCHAR(512),
			refresh_token_exp  TIMESTAMPTZ,
			sub_status         VARCHAR(32) NOT NULL DEFAULT 'none',
			sub_expires_at     TIMESTAMPTZ,
			updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return err
	}

	// Add new columns to existing tables (idempotent)
	migrations := []string{
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS apple_user_id VARCHAR(256) UNIQUE`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(256)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS refresh_token VARCHAR(512)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS refresh_token_exp TIMESTAMPTZ`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS sub_status VARCHAR(32) NOT NULL DEFAULT 'none'`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS sub_expires_at TIMESTAMPTZ`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`,
		// device_id was NOT NULL before; make it nullable for new Apple-auth users
		`ALTER TABLE users ALTER COLUMN device_id DROP NOT NULL`,
	}
	for _, m := range migrations {
		if _, err := db.Exec(context.Background(), m); err != nil {
			return fmt.Errorf("migration %q: %w", m, err)
		}
	}
	return nil
}

type User struct {
	ID        string
	DeviceID  string
	ProfileID string
	SubStatus string
}

// GetUserByDeviceID looks up a user by their device_id (legacy flow).
func GetUserByDeviceID(ctx context.Context, db *Pool, deviceID string) (*User, error) {
	row := db.QueryRow(ctx,
		`SELECT id, device_id, nextdns_profile_id, sub_status FROM users WHERE device_id = $1`, deviceID)
	u := &User{}
	if err := row.Scan(&u.ID, &u.DeviceID, &u.ProfileID, &u.SubStatus); err != nil {
		return nil, err
	}
	return u, nil
}

// GetUserByAppleID looks up a user by their Apple user identifier.
func GetUserByAppleID(ctx context.Context, db *Pool, appleUserID string) (*User, error) {
	row := db.QueryRow(ctx,
		`SELECT id, COALESCE(device_id, ''), nextdns_profile_id, sub_status
		 FROM users WHERE apple_user_id = $1`, appleUserID)
	u := &User{}
	if err := row.Scan(&u.ID, &u.DeviceID, &u.ProfileID, &u.SubStatus); err != nil {
		return nil, err
	}
	return u, nil
}

// GetUserByID looks up a user by their internal UUID.
func GetUserByID(ctx context.Context, db *Pool, userID string) (*User, error) {
	row := db.QueryRow(ctx,
		`SELECT id, COALESCE(device_id, ''), nextdns_profile_id, sub_status
		 FROM users WHERE id = $1`, userID)
	u := &User{}
	if err := row.Scan(&u.ID, &u.DeviceID, &u.ProfileID, &u.SubStatus); err != nil {
		return nil, err
	}
	return u, nil
}

// UpsertUser inserts a user or returns the existing profile_id on conflict.
func UpsertUser(ctx context.Context, db *Pool, deviceID, profileID string) (string, error) {
	var returnedProfileID string
	err := db.QueryRow(ctx,
		`INSERT INTO users (device_id, nextdns_profile_id) VALUES ($1, $2)
		 ON CONFLICT (device_id) DO UPDATE SET device_id = EXCLUDED.device_id
		 RETURNING nextdns_profile_id`,
		deviceID, profileID).Scan(&returnedProfileID)
	return returnedProfileID, err
}

// CreateAppleUser creates a new user via Apple Sign-In (no NextDNS profile yet).
func CreateAppleUser(ctx context.Context, db *Pool, appleUserID, email string) (string, error) {
	var userID string
	err := db.QueryRow(ctx,
		`INSERT INTO users (apple_user_id, email, nextdns_profile_id)
		 VALUES ($1, $2, '')
		 ON CONFLICT (apple_user_id) DO UPDATE SET email = EXCLUDED.email
		 RETURNING id`,
		appleUserID, email).Scan(&userID)
	return userID, err
}

// SetRefreshToken stores a hashed refresh token for the user.
func SetRefreshToken(ctx context.Context, db *Pool, userID, token string, exp time.Time) error {
	_, err := db.Exec(ctx,
		`UPDATE users SET refresh_token = $1, refresh_token_exp = $2, updated_at = NOW()
		 WHERE id = $3`,
		token, exp, userID)
	return err
}

// GetRefreshToken retrieves the refresh token for validation.
func GetRefreshToken(ctx context.Context, db *Pool, userID string) (string, time.Time, error) {
	var token string
	var exp time.Time
	err := db.QueryRow(ctx,
		`SELECT COALESCE(refresh_token, ''), COALESCE(refresh_token_exp, '1970-01-01')
		 FROM users WHERE id = $1`, userID).Scan(&token, &exp)
	return token, exp, err
}

// ClearRefreshToken removes the refresh token (logout).
func ClearRefreshToken(ctx context.Context, db *Pool, userID string) error {
	_, err := db.Exec(ctx,
		`UPDATE users SET refresh_token = NULL, refresh_token_exp = NULL, updated_at = NOW()
		 WHERE id = $1`, userID)
	return err
}

// UpdateSubscription updates the user's subscription status.
func UpdateSubscription(ctx context.Context, db *Pool, userID, status string, expiresAt *time.Time) error {
	_, err := db.Exec(ctx,
		`UPDATE users SET sub_status = $1, sub_expires_at = $2, updated_at = NOW()
		 WHERE id = $3`,
		status, expiresAt, userID)
	return err
}

// LinkDeviceToAppleUser links an existing device_id user to an Apple account.
func LinkDeviceToAppleUser(ctx context.Context, db *Pool, userID, deviceID string) error {
	_, err := db.Exec(ctx,
		`UPDATE users SET device_id = $1, updated_at = NOW() WHERE id = $2`,
		deviceID, userID)
	return err
}

// SetProfileID sets the NextDNS profile ID for a user (after onboarding).
func SetProfileID(ctx context.Context, db *Pool, userID, profileID string) error {
	_, err := db.Exec(ctx,
		`UPDATE users SET nextdns_profile_id = $1, updated_at = NOW() WHERE id = $2`,
		profileID, userID)
	return err
}
