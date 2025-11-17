package garmin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/AlexxIT/SmartScaleConnect/pkg/core"
	"github.com/gomodule/oauth1/oauth"
)

// Client инкапсулирует HTTP-клиент и OAuth-состояние.
type Client struct {
	client       *http.Client
	oauthClient  *oauth.Client
	oauthToken   string
	oauthSecret  string
	accessToken  string
	expiresTime  time.Time
	apiBase      string
	modernBase   string
	ssoBase      string
	userAgent    string
	requestToken string
}

// NewClient создаёт клиента с cookie-jar и таймаутом.
func NewClient(apiBase, modernBase, ssoBase string) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &Client{
		client: &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
		},
		apiBase:    strings.TrimRight(apiBase, "/") + "/",
		modernBase: strings.TrimRight(modernBase, "/") + "/",
		ssoBase:    strings.TrimRight(ssoBase, "/"),
		userAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome Safari",
	}, nil
}

// Login — основной метод авторизации
func (c *Client) Login(username, password string) error {
	ticket, err := c.getTicket(username, password)
	if err != nil {
		return fmt.Errorf("garmin login: %w", err)
	}

	if err := c.getCredentials(ticket); err != nil {
		return fmt.Errorf("garmin login: %w", err)
	}

	// Проверочный запрос
	res, err := c.Get("userprofile-service/userprofile/userProfileBase")
	if err != nil {
		return fmt.Errorf("garmin login: test request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf(
			"garmin login: test request bad status=%d body=%q",
			res.StatusCode, truncate(string(b), 400),
		)
	}
	return nil
}

// getTicket — обмен логина/пароля на OAuth ticket
func (c *Client) getTicket(username, password string) (string, error) {

	// 1. GET embed (часто ставит нужные куки)
	url1 := c.ssoBase + "/sso/embed?" +
		"id=gauth-widget&embedWidget=true&gauthHost=" + url.QueryEscape(c.ssoBase+"/sso")

	res, err := c.client.Get(url1)
	if err != nil {
		return "", fmt.Errorf("getTicket: GET embed: %w", err)
	}
	_, _ = io.ReadAll(res.Body)
	res.Body.Close()

	// 2. GET signin
	url2 := c.ssoBase + "/sso/signin?" +
		"id=gauth-widget&embedWidget=true&" +
		"clientId=GarminConnect&" +
		"gauthHost=" + url.QueryEscape(c.ssoBase+"/sso") + "&" +
		"service=" + url.QueryEscape(c.modernBase) + "&" +
		"source=" + url.QueryEscape(c.modernBase)

	res, err = c.client.Get(url2)
	if err != nil {
		return "", fmt.Errorf("getTicket: GET signin: %w", err)
	}
	pageBytes, _ := io.ReadAll(res.Body)
	res.Body.Close()
	page := string(pageBytes)

	csrf := core.Between(page, `name="_csrf" value="`, `"`)
	if csrf == "" {
		return "", fmt.Errorf(
			"garmin: can't find csrf (status=%d url=%s body=%q)",
			res.StatusCode, res.Request.URL.String(), truncate(page, 500),
		)
	}

	// 3. POST signin
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	form.Set("embed", "true")
	form.Set("_csrf", csrf)

	req, err := http.NewRequest("POST", url2, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("getTicket: POST signin new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", url2)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Origin", c.ssoBase)

	res, err = c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("getTicket: POST signin: %w", err)
	}
	defer res.Body.Close()

	// 1) Ticket в финальном URL
	if t := res.Request.URL.Query().Get("ticket"); t != "" {
		return t, nil
	}

	// 2) Ticket в Location
	if loc := res.Header.Get("Location"); loc != "" {
		u, _ := url.Parse(loc)
		if u != nil {
			if t := u.Query().Get("ticket"); t != "" {
				return t, nil
			}
		}
	}

	// 3) Ищем в теле
	bodyBytes, _ := io.ReadAll(res.Body)
	body := string(bodyBytes)

	if t := core.Between(body, `embed?ticket=`, `"`); t != "" {
		return t, nil
	}
	if t := core.Between(body, `ticket=`, `"`); t != "" {
		return t, nil
	}
	if t := core.Between(body, `"ticket":"`, `"`); t != "" {
		return t, nil
	}

	return "", fmt.Errorf(
		"garmin: can't find ticket (status=%d url=%s body=%q)",
		res.StatusCode, res.Request.URL.String(), truncate(body, 800),
	)
}

func (c *Client) initOAuth() error {
	if c.oauthClient != nil {
		return nil
	}

	res, err := http.Get("https://thegarth.s3.amazonaws.com/oauth_consumer.json")
	if err != nil {
		return fmt.Errorf("initOAuth: download json: %w", err)
	}
	defer res.Body.Close()

	var consumer struct {
		Key    string `json:"consumer_key"`
		Secret string `json:"consumer_secret"`
	}
	if err = json.NewDecoder(res.Body).Decode(&consumer); err != nil {
		return fmt.Errorf("initOAuth: decode json: %w", err)
	}

	c.oauthClient = &oauth.Client{
		Credentials: oauth.Credentials{
			Token:  consumer.Key,
			Secret: consumer.Secret,
		},
	}
	return nil
}

// getCredentials — ticket -> oauth_token
func (c *Client) getCredentials(ticket string) error {
	if err := c.initOAuth(); err != nil {
		return err
	}

	url1 := c.apiBase + "oauth-service/oauth/preauthorized?" +
		"ticket=" + url.QueryEscape(ticket) + "&" +
		"login-url=" + url.QueryEscape(c.ssoBase+"/sso/embed") + "&" +
		"accepts-mfa-tokens=true"

	req, err := http.NewRequest("GET", url1, nil)
	if err != nil {
		return fmt.Errorf("getCredentials: new request: %w", err)
	}
	if err = c.oauthClient.SetAuthorizationHeader(req.Header, nil, req.Method, req.URL, nil); err != nil {
		return fmt.Errorf("getCredentials: SetAuthHeader: %w", err)
	}

	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("getCredentials: do: %w", err)
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()

	values, err := url.ParseQuery(string(raw))
	if err != nil {
		return fmt.Errorf("getCredentials: parse response %q: %w", truncate(string(raw), 500), err)
	}

	c.oauthToken = values.Get("oauth_token")
	c.oauthSecret = values.Get("oauth_token_secret")

	if c.oauthToken == "" || c.oauthSecret == "" {
		return fmt.Errorf(
			"garmin: preauthorized missing tokens raw=%q",
			truncate(string(raw), 500),
		)
	}

	return nil
}

// refreshAccessToken — oauth_token -> access_token
func (c *Client) refreshAccessToken() error {
	if err := c.initOAuth(); err != nil {
		return err
	}

	url1 := c.apiBase + "oauth-service/oauth/exchange/user/2.0"

	req, err := http.NewRequest("POST", url1, nil)
	if err != nil {
		return fmt.Errorf("refreshAccessToken: new request: %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	cred := &oauth.Credentials{Token: c.oauthToken, Secret: c.oauthSecret}

	if err = c.oauthClient.SetAuthorizationHeader(req.Header, cred, req.Method, req.URL, nil); err != nil {
		return fmt.Errorf("refreshAccessToken: SetAuthHeader: %w", err)
	}

	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("refreshAccessToken: do: %w", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()

	var data struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err = json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("refreshAccessToken: bad json %q: %w", truncate(string(body), 500), err)
	}

	if data.AccessToken == "" {
		return fmt.Errorf("garmin: exchange returned no access_token body=%q", truncate(string(body), 500))
	}

	c.accessToken = data.AccessToken
	c.expiresTime = time.Now().Add(time.Duration(data.ExpiresIn) * time.Second)
	return nil
}

// do — общий отправитель
func (c *Client) do(req *http.Request) (*http.Response, error) {
	if c.accessToken == "" || time.Now().After(c.expiresTime) {
		if err := c.refreshAccessToken(); err != nil {
			return nil, err
		}
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("User-Agent", c.userAgent)

	return c.client.Do(req)
}

func (c *Client) Get(path string) (*http.Response, error) {
	u := c.apiBase + strings.TrimLeft(path, "/")
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

func (c *Client) LoginWithToken(token string) error {
	c.oauthToken, c.oauthSecret, _ = strings.Cut(token, ":")

	res, err := c.Get("userprofile-service/userprofile/userProfileBase")
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("garmin: can't login with saved token status=%d body=%q",
			res.StatusCode, truncate(string(b), 400))
	}
	return nil
}

func (c *Client) Token() string {
	return c.oauthToken + ":" + c.oauthSecret
}

// truncate — вспомогательная функция для вывода тела запроса
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}
