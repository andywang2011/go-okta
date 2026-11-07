package okta

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testClient(t *testing.T, handler http.Handler) API {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	api, err := NewClient(Config{
		ClientID:     "cid",
		ClientSecret: "csecret",
		Issuer:       srv.URL,
		Callback:     "http://localhost/callback",
		Timeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient err = %v", err)
	}
	return api
}

func TestGetAuthUrl(t *testing.T) {
	api, err := NewClient(Config{
		ClientID:     "cid",
		ClientSecret: "sec",
		Issuer:       "https://issuer.example",
		Callback:     "http://localhost/cb",
		Timeout:      time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	url := api.GetAuthUrl("nonce123", "state456")
	if !strings.Contains(url, "client_id=cid") || !strings.Contains(url, "nonce=nonce123") {
		t.Errorf("url = %q", url)
	}
}

func TestGenerateNonce(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	n1, err := api.GenerateNonce()
	if err != nil || n1 == "" {
		t.Fatalf("GenerateNonce() = %q, %v", n1, err)
	}
	n2, _ := api.GenerateNonce()
	if n1 == n2 {
		t.Error("expected unique nonces")
	}
}

func TestCodeExchangeToken(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/v1/token" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(Exchange{AccessToken: "at", IdToken: "id"})
	}))
	ex, err := api.CodeExchangeToken(context.Background(), "code1", "st")
	if err != nil {
		t.Fatalf("CodeExchangeToken err = %v", err)
	}
	if ex.AccessToken != "at" {
		t.Errorf("AccessToken = %q", ex.AccessToken)
	}
}

func TestCodeExchangeToken_Error(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(Exchange{Error: "invalid_grant"})
	}))
	_, err := api.CodeExchangeToken(context.Background(), "bad", "st")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetUserInfo(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/v1/userinfo" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(UserInfo{Email: "a@b.com", Sub: "sub1"})
	}))
	info, err := api.GetUserInfo(context.Background(), "token")
	if err != nil {
		t.Fatalf("GetUserInfo err = %v", err)
	}
	if info.Email != "a@b.com" {
		t.Errorf("Email = %q", info.Email)
	}
}

func TestLogout_OK(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err := api.Logout(context.Background(), "tok"); err != nil {
		t.Fatalf("Logout err = %v", err)
	}
}

func TestLogout_Fail(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	if err := api.Logout(context.Background(), "tok"); err == nil {
		t.Fatal("expected error")
	}
}

func TestGetUserInfo_ErrorStatus(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(UserInfo{})
	}))
	_, err := api.GetUserInfo(context.Background(), "token")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCodeExchangeToken_UnmarshalError(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	_, err := api.CodeExchangeToken(context.Background(), "code1", "st")
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
}

func TestLogout_CanceledContext(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := api.Logout(ctx, "tok"); err == nil {
		t.Fatal("expected error on canceled context")
	}
}

func TestGetUserInfo_InvalidJSON(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{invalid"))
	}))
	_, err := api.GetUserInfo(context.Background(), "token")
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
}

func TestVerifyToken_Invalid(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	_, err := api.VerifyToken("not-a-jwt", "nonce")
	if err == nil {
		t.Fatal("expected verify error")
	}
}

func TestCodeExchangeToken_FormBody(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if r.URL.RawQuery != "" {
			t.Errorf("unexpected query: %q", r.URL.RawQuery)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", ct)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{
			"grant_type":   "authorization_code",
			"code":         "code1",
			"state":        "st",
			"redirect_uri": "http://localhost/callback",
		}
		for k, v := range want {
			if got := r.PostForm.Get(k); got != v {
				t.Errorf("form %s = %q, want %q", k, got, v)
			}
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "cid" || p != "csecret" {
			t.Errorf("basic auth = %q %q %v", u, p, ok)
		}
		_ = json.NewEncoder(w).Encode(Exchange{AccessToken: "at"})
	}))
	if _, err := api.CodeExchangeToken(context.Background(), "code1", "st"); err != nil {
		t.Fatal(err)
	}
}

func TestCodeExchangeToken_EmptyState(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server must not be called")
	}))
	_, err := api.CodeExchangeToken(context.Background(), "code", "")
	if !errors.Is(err, ErrEmptyState) {
		t.Fatalf("err = %v, want ErrEmptyState", err)
	}
}

func TestCodeExchangeToken_ErrorStatusNoJSON(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>"))
	}))
	_, err := api.CodeExchangeToken(context.Background(), "c", "s")
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("err = %v", err)
	}
	var syn *json.SyntaxError
	if !errors.As(err, &syn) {
		t.Errorf("expected wrapped json error, got %v", err)
	}
}

func TestCodeExchangeToken_HTTPStatusNoErrorField(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("{}"))
	}))
	_, err := api.CodeExchangeToken(context.Background(), "c", "s")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
}

func TestCodeExchangeToken_TransportErrorWrapped(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := api.CodeExchangeToken(ctx, "c", "s")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestGetUserInfo_TransportErrorWrapped(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := api.GetUserInfo(ctx, "tok")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestLogout_CanceledWrapped(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := api.Logout(ctx, "tok"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestGetAuthUrl_EmptyParams(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if u := api.GetAuthUrl("", "st"); u != "" {
		t.Errorf("empty nonce url = %q", u)
	}
	if u := api.GetAuthUrl("n", ""); u != "" {
		t.Errorf("empty state url = %q", u)
	}
}

func TestValidateAuthParams(t *testing.T) {
	if err := ValidateAuthParams("", "s"); !errors.Is(err, ErrEmptyNonce) {
		t.Errorf("err = %v", err)
	}
	if err := ValidateAuthParams("n", ""); !errors.Is(err, ErrEmptyState) {
		t.Errorf("err = %v", err)
	}
	if err := ValidateAuthParams("n", "s"); err != nil {
		t.Errorf("err = %v", err)
	}
}

func TestVerifyToken_EmptyNonce(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if _, err := api.VerifyToken("tok", ""); !errors.Is(err, ErrEmptyNonce) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyToken_ErrorWrapped(t *testing.T) {
	api := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	_, err := api.VerifyToken("not-a-jwt", "nonce")
	if err == nil || errors.Unwrap(err) == nil {
		t.Fatalf("expected wrapped error, got %v", err)
	}
}
