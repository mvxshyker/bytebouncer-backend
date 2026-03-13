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
			device_id          VARCHAR(256) UNIQUE NOT NULL,
			nextdns_profile_id VARCHAR NOT NULL,
			created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	return err
}

type User struct {
	DeviceID  string
	ProfileID string
}

func GetUserByDeviceID(ctx context.Context, db *Pool, deviceID string) (*User, error) {
	row := db.QueryRow(ctx,
		`SELECT device_id, nextdns_profile_id FROM users WHERE device_id = $1`, deviceID)
	u := &User{}
	if err := row.Scan(&u.DeviceID, &u.ProfileID); err != nil {
		return nil, err
	}
	return u, nil
}

// UpsertUser inserts a user or returns the existing profile_id on conflict.
// This prevents orphaned NextDNS profiles from TOCTOU races during onboarding.
func UpsertUser(ctx context.Context, db *Pool, deviceID, profileID string) (string, error) {
	var returnedProfileID string
	err := db.QueryRow(ctx,
		`INSERT INTO users (device_id, nextdns_profile_id) VALUES ($1, $2)
		 ON CONFLICT (device_id) DO UPDATE SET device_id = EXCLUDED.device_id
		 RETURNING nextdns_profile_id`,
		deviceID, profileID).Scan(&returnedProfileID)
	return returnedProfileID, err
}
