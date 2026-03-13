package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateProfile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/profiles" {
			t.Errorf("path = %s, want /profiles", r.URL.Path)
		}
		if got := r.Header.Get("X-Api-Key"); got != "test-key" {
			t.Errorf("X-Api-Key = %q, want %q", got, "test-key")
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"id": "profile-xyz"},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-key")
	id, err := c.CreateProfile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id != "profile-xyz" {
		t.Errorf("got %q, want %q", id, "profile-xyz")
	}
}

func TestEnableBlocklist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/profiles/p1/privacy/blocklists" {
			t.Errorf("path = %s, want /profiles/p1/privacy/blocklists", r.URL.Path)
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key")
	if err := c.EnableBlocklist(context.Background(), "p1", "oisd"); err != nil {
		t.Fatal(err)
	}
}

func TestGetAnalytics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/profiles/p1/analytics/status":
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"blocked": 42},
			})
		case r.URL.Path == "/profiles/p1/analytics/domains":
			json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{"name": "tracker.com", "queries": 10},
					{"name": "ad.net", "queries": 5},
				},
			})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key")
	a, err := c.GetAnalytics(context.Background(), "p1")
	if err != nil {
		t.Fatal(err)
	}
	if a.TotalBlocked != 42 {
		t.Errorf("blocked = %d, want 42", a.TotalBlocked)
	}
	if len(a.TopDomains) != 2 {
		t.Fatalf("domains count = %d, want 2", len(a.TopDomains))
	}
	if a.TopDomains[0].Name != "tracker.com" {
		t.Errorf("domain[0] = %q, want tracker.com", a.TopDomains[0].Name)
	}
}

func TestToggle(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		wantMet string
		wantURL string
	}{
		{"enable", true, "POST", "/profiles/p1/parentalcontrol/services"},
		{"disable", false, "DELETE", "/profiles/p1/parentalcontrol/services/instagram"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tt.wantMet {
					t.Errorf("method = %s, want %s", r.Method, tt.wantMet)
				}
				if r.URL.Path != tt.wantURL {
					t.Errorf("path = %s, want %s", r.URL.Path, tt.wantURL)
				}
				w.WriteHeader(200)
			}))
			defer srv.Close()

			c := NewClient(srv.URL, "key")
			if err := c.Toggle(context.Background(), "p1", "parentalcontrol/services", "instagram", tt.enabled); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCreateProfileBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key")
	_, err := c.CreateProfile(context.Background())
	if err == nil {
		t.Fatal("expected error for 500 status")
	}
}
