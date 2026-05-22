package garmin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	garminMobileLoginURL = "https://sso.garmin.com/mobile/api/login"
	garminDITokenURL    = "https://diauth.garmin.com/di-oauth2-service/oauth/token"

	garminDIGrantServiceTicket = "https://connectapi.garmin.com/di-oauth2-service/oauth/grant/service_ticket"

	garminSSOClientID = "GCM_IOS_DARK"
	garminServiceURL  = "https://mobile.integration.garmin.com/gcm/ios"

	garminLoginUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"

	garminAPIUserAgent     = "GCM-Android-5.23"
	garminXGarminUserAgent = "com.garmin.android.apps.connectmobile/5.23; ; Google/sdk_gphone64_arm64/google; Android/33; Dalvik/2.1.0"
	garminPairedAppVersion = "10861"
	garminClientPlatform   = "Android"
	garminAppVersion       = "10861"
)

var garminDIClientIDs = []string{
	"GARMIN_CONNECT_MOBILE_ANDROID_DI_2025Q2",
	"GARMIN_CONNECT_MOBILE_ANDROID_DI_2024Q4",
	"GARMIN_CONNECT_MOBILE_ANDROID_DI",
	"GARMIN_CONNECT_MOBILE_IOS_DI",
}

func (c *Client) Login(username, password string) error {
	ticket, err := c.getServiceTicket(username, password)
	if err != nil {
		return err
	}

	return c.exchangeServiceTicket(ticket)
}

func (c *Client) getServiceTicket(username, password string) (string, error) {
	params := url.Values{}
	params.Set("clientId", garminSSOClientID)
	params.Set("locale", "en-US")
	params.Set("service", garminServiceURL)

	payload := map[string]any{
		"username":     username,
		"password":     password,
		"rememberMe":   true,
		"captchaToken": "",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		garminMobileLoginURL+"?"+params.Encode(),
		bytes.NewReader(body),
	)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", garminLoginUserAgent)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://sso.garmin.com")
	req.Header.Set("Referer", "https://sso.garmin.com/")

	res, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	if res.StatusCode == http.StatusTooManyRequests {
		return "", errors.New("garmin: rate limited by Garmin SSO")
	}

	var data struct {
		ResponseStatus struct {
			Type string `json:"type"`
		} `json:"responseStatus"`

		ServiceTicketID string `json:"serviceTicketId"`

		CustomerMfaInfo struct {
			MfaLastMethodUsed string `json:"mfaLastMethodUsed"`
		} `json:"customerMfaInfo"`

		Error struct {
			StatusCode string `json:"status-code"`
			Message    string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(raw, &data); err != nil {
		return "", fmt.Errorf("garmin: mobile login returned non-json response: HTTP %d: %s", res.StatusCode, string(raw))
	}

	switch data.ResponseStatus.Type {
	case "SUCCESSFUL":
		if data.ServiceTicketID == "" {
			return "", errors.New("garmin: login successful but serviceTicketId is empty")
		}
		return data.ServiceTicketID, nil

	case "MFA_REQUIRED":
		method := data.CustomerMfaInfo.MfaLastMethodUsed
		if method == "" {
			method = "unknown"
		}
		return "", fmt.Errorf("garmin: MFA required via %s; this SmartScaleConnect patch does not implement MFA code input yet", method)

	case "INVALID_USERNAME_PASSWORD":
		return "", errors.New("garmin: invalid username or password")
	}

	if data.Error.Message != "" {
		return "", fmt.Errorf("garmin: login failed: %s", data.Error.Message)
	}

	return "", fmt.Errorf("garmin: login failed: HTTP %d: %s", res.StatusCode, string(raw))
}

func (c *Client) exchangeServiceTicket(ticket string) error {
	var lastErr error

	for _, clientID := range garminDIClientIDs {
		values := url.Values{}
		values.Set("client_id", clientID)
		values.Set("service_ticket", ticket)
		values.Set("grant_type", garminDIGrantServiceTicket)
		values.Set("service_url", garminServiceURL)

		req, err := http.NewRequest(
			http.MethodPost,
			garminDITokenURL,
			strings.NewReader(values.Encode()),
		)
		if err != nil {
			return err
		}

		req.Header.Set("Authorization", basicAuth(clientID))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Cache-Control", "no-cache")
		setGarminNativeHeaders(req.Header)

		res, err := c.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		raw, readErr := io.ReadAll(res.Body)
		res.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}

		if res.StatusCode == http.StatusTooManyRequests {
			return errors.New("garmin: DI token exchange rate limited")
		}

		if res.StatusCode < 200 || res.StatusCode >= 300 {
			lastErr = fmt.Errorf("garmin: DI token exchange failed for %s: HTTP %d: %s", clientID, res.StatusCode, string(raw))
			continue
		}

		var tokenData struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}

		if err := json.Unmarshal(raw, &tokenData); err != nil {
			lastErr = fmt.Errorf("garmin: DI token parse failed for %s: %w: %s", clientID, err, string(raw))
			continue
		}

		if tokenData.AccessToken == "" {
			lastErr = fmt.Errorf("garmin: DI token exchange returned empty access_token for %s", clientID)
			continue
		}

		c.diAccessToken = tokenData.AccessToken
		c.diRefreshToken = tokenData.RefreshToken
		c.diClientID = clientID

		if jwtClientID := extractClientIDFromJWT(tokenData.AccessToken); jwtClientID != "" {
			c.diClientID = jwtClientID
		}

		return nil
	}

	if lastErr != nil {
		return lastErr
	}

	return errors.New("garmin: DI token exchange failed")
}

func (c *Client) refreshDIToken() error {
	if c.diRefreshToken == "" {
		return errors.New("garmin: no DI refresh token available")
	}

	clientID := c.diClientID
	if clientID == "" {
		clientID = "GARMIN_CONNECT_MOBILE_ANDROID_DI_2025Q2"
	}

	values := url.Values{}
	values.Set("grant_type", "refresh_token")
	values.Set("client_id", clientID)
	values.Set("refresh_token", c.diRefreshToken)

	req, err := http.NewRequest(
		http.MethodPost,
		garminDITokenURL,
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", basicAuth(clientID))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cache-Control", "no-cache")
	setGarminNativeHeaders(req.Header)

	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if res.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("garmin: DI token refresh rate limited: %s", string(raw))
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("garmin: DI token refresh failed: HTTP %d: %s", res.StatusCode, string(raw))
	}

	var tokenData struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.Unmarshal(raw, &tokenData); err != nil {
		return err
	}

	if tokenData.AccessToken == "" {
		return errors.New("garmin: DI token refresh returned empty access_token")
	}

	c.diAccessToken = tokenData.AccessToken

	if tokenData.RefreshToken != "" {
		c.diRefreshToken = tokenData.RefreshToken
	}

	if jwtClientID := extractClientIDFromJWT(tokenData.AccessToken); jwtClientID != "" {
		c.diClientID = jwtClientID
	}

	return nil
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	if c.diAccessToken == "" {
		if err := c.refreshDIToken(); err != nil {
			return nil, err
		}
	}

	if tokenExpiresSoon(c.diAccessToken) && c.diRefreshToken != "" {
		_ = c.refreshDIToken()
	}

	req.Header.Set("Authorization", "Bearer "+c.diAccessToken)
	setGarminNativeHeaders(req.Header)

	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode == http.StatusUnauthorized && c.diRefreshToken != "" {
		res.Body.Close()

		if err := c.refreshDIToken(); err != nil {
			return nil, err
		}

		req2 := cloneRequest(req)
		req2.Header.Set("Authorization", "Bearer "+c.diAccessToken)
		setGarminNativeHeaders(req2.Header)

		return c.client.Do(req2)
	}

	return res, nil
}

func (c *Client) LoginWithToken(token string) error {
	parts := strings.SplitN(token, "|", 4)

	if len(parts) != 4 || parts[0] != "di" {
		return errors.New("garmin: old token format is not supported, please login again")
	}

	c.diClientID = parts[1]
	c.diAccessToken = parts[2]
	c.diRefreshToken = parts[3]

	res, err := c.Get("userprofile-service/userprofile/userProfileBase")
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusUnauthorized {
		if err := c.refreshDIToken(); err != nil {
			return err
		}

		res, err = c.Get("userprofile-service/userprofile/userProfileBase")
		if err != nil {
			return err
		}
		defer res.Body.Close()
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("garmin: can't login with stored DI token: %s", res.Status)
	}

	return nil
}

func (c *Client) Token() string {
	return "di|" + c.diClientID + "|" + c.diAccessToken + "|" + c.diRefreshToken
}

func basicAuth(clientID string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"))
}

func setGarminNativeHeaders(header http.Header) {
	if header.Get("User-Agent") == "" {
		header.Set("User-Agent", garminAPIUserAgent)
	}

	header.Set("X-Garmin-User-Agent", garminXGarminUserAgent)
	header.Set("X-Garmin-Paired-App-Version", garminPairedAppVersion)
	header.Set("X-Garmin-Client-Platform", garminClientPlatform)
	header.Set("X-App-Ver", garminAppVersion)
	header.Set("X-Lang", "en")
	header.Set("Accept-Language", "en-US,en;q=0.9")
}

func cloneRequest(req *http.Request) *http.Request {
	req2 := req.Clone(req.Context())
	req2.Header = req.Header.Clone()
	return req2
}

func extractClientIDFromJWT(token string) string {
	claims := jwtClaims(token)
	if claims == nil {
		return ""
	}

	if v, ok := claims["client_id"].(string); ok {
		return v
	}

	if v, ok := claims["clientId"].(string); ok {
		return v
	}

	return ""
}

func tokenExpiresSoon(token string) bool {
	claims := jwtClaims(token)
	if claims == nil {
		return false
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return false
	}

	expTime := time.Unix(int64(exp), 0)

	return time.Now().After(expTime.Add(-15 * time.Minute))
}

func jwtClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}

	payload := parts[1]
	payload += strings.Repeat("=", (4-len(payload)%4)%4)

	raw, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil
	}

	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil
	}

	return claims
}
