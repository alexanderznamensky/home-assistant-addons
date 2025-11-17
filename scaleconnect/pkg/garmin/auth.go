package garmin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	apiBase      string // например, https://connectapi.garmin.com/
	modernBase   string // например, https://connect.garmin.com/modern/
	ssoBase      string // например, https://sso.garmin.com
	userAgent    string
	requestToken string
}

// NewClient создаёт клиента с cookie-jar и таймаутом.
// apiBase:   "https://connectapi.garmin.com/"
// modernBase:"https://connect.garmin.com/modern/"
// ssoBase:   "https://sso.garmin.com"
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

func (c *Client) Login(username, password string) error {
	log.Printf("[garmin] Login: start for user %q", username)

	ticket, err := c.getTicket(username, password)
	if err != nil {
		log.Printf("[garmin] Login: getTicket error: %v", err)
		return fmt.Errorf("garmin login: getTicket: %w", err)
	}
	log.Printf("[garmin] Login: got ticket %q", ticket)

	if err := c.getCredentials(ticket); err != nil {
		log.Printf("[garmin] Login: getCredentials error: %v", err)
		return fmt.Errorf("garmin login: getCredentials: %w", err)
	}
	log.Printf("[garmin] Login: got oauthToken=%q, oauthSecret len=%d", c.oauthToken, len(c.oauthSecret))

	// Пробный запрос, чтобы убедиться, что всё ок
	res, err := c.Get("userprofile-service/userprofile/userProfileBase")
	if err != nil {
		log.Printf("[garmin] Login: test request error: %v", err)
		return fmt.Errorf("garmin login: test request: %w", err)
	}
	defer res.Body.Close()

	log.Printf("[garmin] Login: test request status %d", res.StatusCode)
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		log.Printf("[garmin] Login: test request non-200, body: %s", truncate(string(body), 500))
		return fmt.Errorf("garmin login: test request status %d", res.StatusCode)
	}

	log.Printf("[garmin] Login: success")
	return nil
}

// getTicket — обмен логина/пароля на OAuth ticket.
// Делает устойчивым поиск тикета: финальный URL, Location, тело (HTML/JSON).
func (c *Client) getTicket(username, password string) (string, error) {
	log.Printf("[garmin] getTicket: start")

	// 1. Пробуждаем виджет (часто ставит нужные куки)
	url1 := c.ssoBase + "/sso/embed?" +
		"id=gauth-widget&embedWidget=true&gauthHost=" + url.QueryEscape(c.ssoBase+"/sso")

	log.Printf("[garmin] getTicket: GET %s", url1)
	res, err := c.client.Get(url1)
	if err != nil {
		return "", fmt.Errorf("getTicket: GET embed: %w", err)
	}
	defer res.Body.Close()
	_, _ = io.ReadAll(res.Body) // прогреваем, но содержимое не критично
	log.Printf("[garmin] getTicket: GET %s -> %d", url1, res.StatusCode)

	// 2. Получаем CSRF
	url2 := c.ssoBase + "/sso/signin?" +
		"id=gauth-widget&embedWidget=true&" +
		"clientId=GarminConnect&" +
		"gauthHost=" + url.QueryEscape(c.ssoBase+"/sso") + "&" +
		"service=" + url.QueryEscape(c.modernBase) + "&" +
		"source=" + url.QueryEscape(c.modernBase)

	log.Printf("[garmin] getTicket: GET %s", url2)
	res, err = c.client.Get(url2)
	if err != nil {
		return "", fmt.Errorf("getTicket: GET signin: %w", err)
	}
	defer res.Body.Close()

	page, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("getTicket: read signin page: %w", err)
	}
	log.Printf("[garmin] getTicket: signin status=%d body[0:200]=%s", res.StatusCode, truncate(string(page), 200))

	csrf := core.Between(string(page), `name="_csrf" value="`, `"`)
	if csrf == "" {
		log.Printf("[garmin] getTicket: can't find csrf in page")
		return "", errors.New("garmin: can't find csrf")
	}
	log.Printf("[garmin] getTicket: found csrf len=%d", len(csrf))

	// 3. Signin
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	form.Set("embed", "true")
	form.Set("_csrf", csrf)

	req, err := http.NewRequest("POST", url2, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("getTicket: new POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", url2)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Origin", c.ssoBase)
	req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")

	log.Printf("[garmin] getTicket: POST %s (signin)", url2)
	res, err = c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("getTicket: POST signin: %w", err)
	}
	defer res.Body.Close()

	log.Printf("[garmin] getTicket: POST signin status=%d finalURL=%s", res.StatusCode, res.Request.URL.String())

	// 1) Частый кейс — тикет в финальном URL после редиректов
	if t := res.Request.URL.Query().Get("ticket"); t != "" {
		log.Printf("[garmin] getTicket: ticket found in final URL: %s", t)
		return t, nil
	}

	// 2) Иногда тикет только в Location (если 3xx поймали вручную или промежуточно)
	if loc := res.Header.Get("Location"); loc != "" {
		log.Printf("[garmin] getTicket: Location header: %s", loc)
		if u, _ := url.Parse(loc); u != nil {
			if t := u.Query().Get("ticket"); t != "" {
				log.Printf("[garmin] getTicket: ticket found in Location: %s", t)
				return t, nil
			}
		}
	}

	// 3) Фоллбек: ищем в теле разные варианты встраивания
	body, _ := io.ReadAll(res.Body) // если уже читали — будет пусто, это ок
	s := string(body)
	log.Printf("[garmin] getTicket: response body[0:500]=%s", truncate(s, 500))

	if t := core.Between(s, `embed?ticket=`, `"`); t != "" {
		log.Printf("[garmin] getTicket: ticket found via embed?ticket=: %s", t)
		return t, nil
	}
	if t := core.Between(s, `ticket=`, `"`); t != "" {
		log.Printf("[garmin] getTicket: ticket found via ticket=: %s", t)
		return t, nil
	}
	if t := core.Between(s, `"ticket":"`, `"`); t != "" {
		log.Printf("[garmin] getTicket: ticket found via \"ticket\": %s", t)
		return t, nil
	}

	log.Printf("[garmin] getTicket: can't find ticket anywhere")
	return "", errors.New("garmin: can't find ticket")
}

func (c *Client) initOAuth() error {
	if c.oauthClient != nil {
		return nil
	}

	log.Printf("[garmin] initOAuth: downloading consumer key/secret")
	res, err := http.Get("https://thegarth.s3.amazonaws.com/oauth_consumer.json")
	if err != nil {
		return fmt.Errorf("initOAuth: download consumer json: %w", err)
	}
	defer res.Body.Close()

	var consumer struct {
		Key    string `json:"consumer_key"`
		Secret string `json:"consumer_secret"`
	}
	if err = json.NewDecoder(res.Body).Decode(&consumer); err != nil {
		return fmt.Errorf("initOAuth: decode consumer json: %w", err) // фикс + лог
	}

	log.Printf("[garmin] initOAuth: consumer key len=%d, secret len=%d", len(consumer.Key), len(consumer.Secret))

	c.oauthClient = &oauth.Client{
		Credentials: oauth.Credentials{
			Token:  consumer.Key,
			Secret: consumer.Secret,
		},
	}
	return nil
}

// getCredentials — обмен ticket -> oauth_token / oauth_token_secret
func (c *Client) getCredentials(ticket string) error {
	log.Printf("[garmin] getCredentials: start with ticket=%q", ticket)

	if err := c.initOAuth(); err != nil {
		log.Printf("[garmin] getCredentials: initOAuth error: %v", err)
		return err
	}

	url1 := c.apiBase + "oauth-service/oauth/preauthorized?" +
		"ticket=" + url.QueryEscape(ticket) + "&" +
		"login-url=" + url.QueryEscape(c.ssoBase+"/sso/embed") + "&" +
		"accepts-mfa-tokens=true"

	log.Printf("[garmin] getCredentials: GET %s", url1)
	req, err := http.NewRequest("GET", url1, nil)
	if err != nil {
		return fmt.Errorf("getCredentials: new request: %w", err)
	}
	if err = c.oauthClient.SetAuthorizationHeader(req.Header, nil, req.Method, req.URL, nil); err != nil {
		return fmt.Errorf("getCredentials: SetAuthorizationHeader: %w", err)
	}

	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("getCredentials: do request: %w", err)
	}
	defer res.Body.Close()

	log.Printf("[garmin] getCredentials: status=%d", res.StatusCode)

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("getCredentials: read body: %w", err)
	}
	log.Printf("[garmin] getCredentials: raw response=%s", truncate(string(raw), 500))

	values, err := url.ParseQuery(string(raw))
	if err != nil {
		return fmt.Errorf("getCredentials: parse query: %w", err)
	}
	c.oauthToken = values.Get("oauth_token")
	c.oauthSecret = values.Get("oauth_token_secret")
	log.Printf("[garmin] getCredentials: oauth_token=%q, oauth_secret len=%d", c.oauthToken, len(c.oauthSecret))

	if c.oauthToken == "" || c.oauthSecret == "" {
		return errors.New("garmin: preauthorized response missing tokens")
	}
	return nil
}

// refreshAccessToken — обмен oauth_token/secret на access_token (Bearer)
func (c *Client) refreshAccessToken() error {
	log.Printf("[garmin] refreshAccessToken: start")

	if err := c.initOAuth(); err != nil {
		log.Printf("[garmin] refreshAccessToken: initOAuth error: %v", err)
		return err
	}
	const path = "oauth-service/oauth/exchange/user/2.0"
	url1 := c.apiBase + path

	log.Printf("[garmin] refreshAccessToken: POST %s", url1)
	req, err := http.NewRequest("POST", url1, nil)
	if err != nil {
		return fmt.Errorf("refreshAccessToken: new request: %w", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	credentials := &oauth.Credentials{Token: c.oauthToken, Secret: c.oauthSecret}
	if err = c.oauthClient.SetAuthorizationHeader(req.Header, credentials, req.Method, req.URL, nil); err != nil {
		return fmt.Errorf("refreshAccessToken: SetAuthorizationHeader: %w", err)
	}

	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("refreshAccessToken: do request: %w", err)
	}
	defer res.Body.Close()

	log.Printf("[garmin] refreshAccessToken: status=%d", res.StatusCode)
	body, _ := io.ReadAll(res.Body)
	log.Printf("[garmin] refreshAccessToken: raw body=%s", truncate(string(body), 500))

	var data struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err = json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("refreshAccessToken: decode json: %w", err)
	}
	if data.AccessToken == "" || data.ExpiresIn <= 0 {
		return fmt.Errorf("garmin: invalid exchange response: token=%q expiresIn=%d", data.AccessToken, data.ExpiresIn)
	}

	c.accessToken = data.AccessToken
	c.expiresTime = time.Now().Add(time.Duration(data.ExpiresIn) * time.Second)
	log.Printf("[garmin] refreshAccessToken: got access_token len=%d, expires in %ds", len(c.accessToken), data.ExpiresIn)
	return nil
}

// do — общий отправитель с авто-рефрешем access token
func (c *Client) do(req *http.Request) (*http.Response, error) {
	log.Printf("[garmin] do: %s %s", req.Method, req.URL.String())

	if c.accessToken == "" || time.Now().After(c.expiresTime) {
		log.Printf("[garmin] do: access token empty or expired, refreshing...")
		if err := c.refreshAccessToken(); err != nil {
			log.Printf("[garmin] do: refreshAccessToken error: %v", err)
			return nil, err
		}
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("User-Agent", c.userAgent)

	res, err := c.client.Do(req)
	if err != nil {
		log.Printf("[garmin] do: request error: %v", err)
		return nil, err
	}
	log.Printf("[garmin] do: response status=%d", res.StatusCode)
	return res, nil
}

// Get — удобный хелпер для GET по относительному пути к API.
func (c *Client) Get(path string) (*http.Response, error) {
	u := c.apiBase + strings.TrimLeft(path, "/")
	log.Printf("[garmin] Get: %s", u)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

// LoginWithToken — логин по ранее сохранённой паре oauth_token:oauth_secret
func (c *Client) LoginWithToken(token string) error {
	log.Printf("[garmin] LoginWithToken: start with token string len=%d", len(token))

	c.oauthToken, c.oauthSecret, _ = strings.Cut(token, ":")
	log.Printf("[garmin] LoginWithToken: parsed oauthToken=%q, oauthSecret len=%d", c.oauthToken, len(c.oauthSecret))

	res, err := c.Get("userprofile-service/userprofile/userProfileBase")
	if err != nil {
		log.Printf("[garmin] LoginWithToken: test request error: %v", err)
		return err
	}
	defer res.Body.Close()

	log.Printf("[garmin] LoginWithToken: status=%d", res.StatusCode)
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		log.Printf("[garmin] LoginWithToken: non-200 body=%s", truncate(string(body), 500))
		return errors.New("garmin: can't login")
	}
	log.Printf("[garmin] LoginWithToken: success")
	return nil
}

// Token — вернуть oauth_token:oauth_secret для сохранения.
func (c *Client) Token() string {
	return c.oauthToken + ":" + c.oauthSecret
}

// truncate — вспомогательная функция для логов, чтобы не заливать гигантские тела.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}
