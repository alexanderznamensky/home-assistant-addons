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
	ticket, err := c.getTicket(username, password)
	if err != nil {
		return err
	}
	return c.getCredentials(ticket)
}

// getTicket — обмен логина/пароля на OAuth ticket.
// Делает устойчивым поиск тикета: финальный URL, Location, тело (HTML/JSON).
func (c *Client) getTicket(username, password string) (string, error) {
	// 1. Пробуждаем виджет (часто ставит нужные куки)
	url1 := c.ssoBase + "/sso/embed?" +
		"id=gauth-widget&embedWidget=true&gauthHost=" + url.QueryEscape(c.ssoBase+"/sso")

	res, err := c.client.Get(url1)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	_, _ = io.ReadAll(res.Body) // прогреваем, но содержимое не критично

	// 2. Получаем CSRF
	url2 := c.ssoBase + "/sso/signin?" +
		"id=gauth-widget&embedWidget=true&" +
		"clientId=GarminConnect&" +
		"gauthHost=" + url.QueryEscape(c.ssoBase+"/sso") + "&" +
		"service=" + url.QueryEscape(c.modernBase) + "&" +
		"source=" + url.QueryEscape(c.modernBase)

	res, err = c.client.Get(url2)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	page, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	csrf := core.Between(string(page), `name="_csrf" value="`, `"`)
	if csrf == "" {
		return "", errors.New("garmin: can't find csrf")
	}

	// 3. Signin
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	form.Set("embed", "true")
	form.Set("_csrf", csrf)

	req, err := http.NewRequest("POST", url2, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", url2)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Origin", c.ssoBase)
	req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")

	res, err = c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	// 1) Частый кейс — тикет в финальном URL после редиректов
	if t := res.Request.URL.Query().Get("ticket"); t != "" {
		return t, nil
	}

	// 2) Иногда тикет только в Location (если 3xx поймали вручную или промежуточно)
	if loc := res.Header.Get("Location"); loc != "" {
		if u, _ := url.Parse(loc); u != nil {
			if t := u.Query().Get("ticket"); t != "" {
				return t, nil
			}
		}
	}

	// 3) Фоллбек: ищем в теле разные варианты встраивания
	body, _ := io.ReadAll(res.Body) // если уже читали — будет пусто, это ок
	s := string(body)
	if t := core.Between(s, `embed?ticket=`, `"`); t != "" {
		return t, nil
	}
	if t := core.Between(s, `ticket=`, `"`); t != "" {
		return t, nil
	}
	if t := core.Between(s, `"ticket":"`, `"`); t != "" {
		return t, nil
	}

	return "", errors.New("garmin: can't find ticket")
}

func (c *Client) initOAuth() error {
	if c.oauthClient != nil {
		return nil
	}

	res, err := http.Get("https://thegarth.s3.amazonaws.com/oauth_consumer.json")
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var consumer struct {
		Key    string `json:"consumer_key"`
		Secret string `json:"consumer_secret"`
	}
	if err = json.NewDecoder(res.Body).Decode(&consumer); err != nil {
		return err // фикс: раньше возвращалось nil
	}

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
	if err := c.initOAuth(); err != nil {
		return err
	}

	url1 := c.apiBase + "oauth-service/oauth/preauthorized?" +
		"ticket=" + url.QueryEscape(ticket) + "&" +
		"login-url=" + url.QueryEscape(c.ssoBase+"/sso/embed") + "&" +
		"accepts-mfa-tokens=true"

	req, err := http.NewRequest("GET", url1, nil)
	if err != nil {
		return err
	}
	if err = c.oauthClient.SetAuthorizationHeader(req.Header, nil, req.Method, req.URL, nil); err != nil {
		return err
	}

	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	values, err := url.ParseQuery(string(raw))
	if err != nil {
		return err
	}
	c.oauthToken = values.Get("oauth_token")
	c.oauthSecret = values.Get("oauth_token_secret")
	if c.oauthToken == "" || c.oauthSecret == "" {
		return errors.New("garmin: preauthorized response missing tokens")
	}
	return nil
}

// refreshAccessToken — обмен oauth_token/secret на access_token (Bearer)
func (c *Client) refreshAccessToken() error {
	if err := c.initOAuth(); err != nil {
		return err
	}
	const path = "oauth-service/oauth/exchange/user/2.0"
	url1 := c.apiBase + path

	req, err := http.NewRequest("POST", url1, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	credentials := &oauth.Credentials{Token: c.oauthToken, Secret: c.oauthSecret}
	if err = c.oauthClient.SetAuthorizationHeader(req.Header, credentials, req.Method, req.URL, nil); err != nil {
		return err
	}

	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var data struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err = json.NewDecoder(res.Body).Decode(&data); err != nil {
		return err
	}
	if data.AccessToken == "" || data.ExpiresIn <= 0 {
		return errors.New("garmin: invalid exchange response")
	}

	c.accessToken = data.AccessToken
	c.expiresTime = time.Now().Add(time.Duration(data.ExpiresIn) * time.Second)
	return nil
}

// do — общий отправитель с авто-рефрешем access token
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

// Get — удобный хелпер для GET по относительному пути к API.
func (c *Client) Get(path string) (*http.Response, error) {
	u := c.apiBase + strings.TrimLeft(path, "/")
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

// LoginWithToken — логин по ранее сохранённой паре oauth_token:oauth_secret
func (c *Client) LoginWithToken(token string) error {
	c.oauthToken, c.oauthSecret, _ = strings.Cut(token, ":")

	res, err := c.Get("userprofile-service/userprofile/userProfileBase")
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return errors.New("garmin: can't login")
	}
	return nil
}

// Token — вернуть oauth_token:oauth_secret для сохранения.
func (c *Client) Token() string {
	return c.oauthToken + ":" + c.oauthSecret
}
