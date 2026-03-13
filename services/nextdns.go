package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client wraps the NextDNS API with an injectable base URL and API key.
type Client struct {
	BaseURL string
	APIKey  string
	http    *http.Client
}

func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		http:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, r)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Api-Key", c.APIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
	if err != nil {
		return nil, 0, fmt.Errorf("reading response body: %w", err)
	}
	return data, resp.StatusCode, nil
}

func (c *Client) CreateProfile(ctx context.Context) (string, error) {
	data, status, err := c.do(ctx, "POST", "/profiles", map[string]any{})
	if err != nil {
		return "", err
	}
	if status != 200 && status != 201 {
		return "", fmt.Errorf("nextdns create profile: status %d", status)
	}
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", err
	}
	return resp.Data.ID, nil
}

func (c *Client) EnableBlocklist(ctx context.Context, profileID, listID string) error {
	_, status, err := c.do(ctx, "POST", fmt.Sprintf("/profiles/%s/privacy/blocklists", profileID),
		map[string]string{"id": listID})
	if err != nil {
		return err
	}
	if status != 200 && status != 201 && status != 204 {
		return fmt.Errorf("nextdns enable blocklist: status %d", status)
	}
	return nil
}

// Analytics holds the response we return to iOS.
type Analytics struct {
	TotalBlocked int      `json:"total_blocked"`
	TopDomains   []Domain `json:"top_domains"`
}

type Domain struct {
	Name    string `json:"name"`
	Queries int    `json:"queries"`
}

func (c *Client) GetAnalytics(ctx context.Context, profileID string) (*Analytics, error) {
	type statusResult struct {
		blocked int
		err     error
	}
	type domainResult struct {
		domains []Domain
		err     error
	}

	statusCh := make(chan statusResult, 1)
	domainCh := make(chan domainResult, 1)

	go func() {
		data, code, err := c.do(ctx, "GET",
			fmt.Sprintf("/profiles/%s/analytics/status?from=-24h", profileID), nil)
		if err != nil {
			statusCh <- statusResult{err: err}
			return
		}
		if code != 200 {
			statusCh <- statusResult{err: fmt.Errorf("nextdns analytics status: %d", code)}
			return
		}
		var resp struct {
			Data struct {
				Blocked int `json:"blocked"`
			} `json:"data"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			statusCh <- statusResult{err: err}
			return
		}
		statusCh <- statusResult{blocked: resp.Data.Blocked}
	}()

	go func() {
		data, code, err := c.do(ctx, "GET",
			fmt.Sprintf("/profiles/%s/analytics/domains?from=-24h&status=blocked&limit=10", profileID), nil)
		if err != nil {
			domainCh <- domainResult{err: err}
			return
		}
		if code != 200 {
			domainCh <- domainResult{err: fmt.Errorf("nextdns analytics domains: %d", code)}
			return
		}
		var resp struct {
			Data []struct {
				Name    string `json:"name"`
				Queries int    `json:"queries"`
			} `json:"data"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			domainCh <- domainResult{err: err}
			return
		}
		domains := make([]Domain, len(resp.Data))
		for i, d := range resp.Data {
			domains[i] = Domain{Name: d.Name, Queries: d.Queries}
		}
		domainCh <- domainResult{domains: domains}
	}()

	sr := <-statusCh
	if sr.err != nil {
		return nil, sr.err
	}
	dr := <-domainCh
	if dr.err != nil {
		return nil, dr.err
	}

	return &Analytics{
		TotalBlocked: sr.blocked,
		TopDomains:   dr.domains,
	}, nil
}

func (c *Client) Toggle(ctx context.Context, profileID, subPath, id string, enabled bool) error {
	path := fmt.Sprintf("/profiles/%s/%s", profileID, subPath)
	var status int
	var err error
	if enabled {
		_, status, err = c.do(ctx, "POST", path, map[string]string{"id": id})
	} else {
		_, status, err = c.do(ctx, "DELETE", fmt.Sprintf("%s/%s", path, id), nil)
	}
	if err != nil {
		return err
	}
	if status != 200 && status != 201 && status != 204 {
		return fmt.Errorf("nextdns toggle %s/%s enabled=%v: status %d", subPath, id, enabled, status)
	}
	return nil
}
