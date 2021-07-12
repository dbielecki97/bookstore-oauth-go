package oauth

import (
	"errors"
	"github.com/dbielecki97/bookstore-utils-go/errs"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"os"
	"testing"
)

func setup() {
	httpmock.ActivateNonDefault(oauthRestClient.GetClient())
}

func shutdown() {
	httpmock.DeactivateAndReset()
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	shutdown()
	os.Exit(code)
}

func TestOauthConstants(t *testing.T) {
	assert.EqualValues(t, "X-Caller-Id", headerXCallerId)
	assert.EqualValues(t, "X-Client-Id", headerXClientId)
	assert.EqualValues(t, "X-Public", headerXPublic)
	assert.EqualValues(t, "token", paramToken)
}

func TestIsPublic(t *testing.T) {
	type args struct {
		req *http.Request
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "with an nil request",
			args: args{req: nil},
			want: true,
		},
		{
			name: "with an request with no public header",
			args: args{req: &http.Request{}},
			want: false,
		},
		{
			name: "with an request with public header",
			args: args{req: &http.Request{Header: map[string][]string{headerXPublic: {"true"}}}},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPublic(tt.args.req); got != tt.want {
				t.Errorf("IsPublic() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetCallerId(t *testing.T) {
	type args struct {
		req *http.Request
	}
	tests := []struct {
		name string
		args args
		want int64
	}{
		{
			name: "request equals nil",
			args: args{req: nil},
			want: 0,
		},
		{
			name: "no caller id header",
			args: args{req: &http.Request{}},
			want: 0,
		},
		{
			name: "request with an caller id not being an int64",
			args: args{req: &http.Request{Header: map[string][]string{headerXCallerId: {"asdaf1124"}}}},
			want: 0,
		},
		{
			name: "request with an caller int64 caller id",
			args: args{req: &http.Request{Header: map[string][]string{headerXCallerId: {"15"}}}},
			want: 15,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetCallerId(tt.args.req); got != tt.want {
				t.Errorf("GetCallerId() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetClientId(t *testing.T) {
	type args struct {
		req *http.Request
	}
	tests := []struct {
		name string
		args args
		want int64
	}{
		{
			name: "request equals nil",
			args: args{req: nil},
			want: 0,
		},
		{
			name: "no caller id header",
			args: args{req: &http.Request{}},
			want: 0,
		},
		{
			name: "request with an client id not being an int64",
			args: args{req: &http.Request{Header: map[string][]string{headerXClientId: {"asdaf1124"}}}},
			want: 0,
		},
		{
			name: "request with an client int64 client id",
			args: args{req: &http.Request{Header: map[string][]string{headerXClientId: {"15"}}}},
			want: 15,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetClientId(tt.args.req); got != tt.want {
				t.Errorf("GetClientId() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAccessTokenErrorFromOauthServer(t *testing.T) {
	httpmock.Reset()

	errorResponder := httpmock.NewErrorResponder(errs.NewError("timeout error"))
	httpmock.RegisterResponder(http.MethodGet, "/oauth/token/1234", errorResponder)

	_, restErr := oauthServer.getAccessToken("1234")
	assert.NotNil(t, restErr)
	assert.EqualValues(t, "could not contact oauth remote server", restErr.Message())
}

func TestGetAccessTokenStatusCodeBiggerThan299InvalidInterface(t *testing.T) {
	httpmock.Reset()

	responder, err := httpmock.NewJsonResponder(http.StatusInternalServerError, map[string]interface{}{"error": 123})
	if err != nil {
		t.Error("could not create responder")
	}
	httpmock.RegisterResponder(http.MethodGet, "/oauth/token/1234", responder)

	_, restErr := oauthServer.getAccessToken("1234")
	assert.NotNil(t, restErr)
	assert.EqualValues(t, "invalid error interface when trying to get token", restErr.Message())
}

func TestGetAccessTokenStatusCodeBiggerThan299Unmarshalled(t *testing.T) {
	httpmock.Reset()

	responder, err := httpmock.NewJsonResponder(http.StatusInternalServerError, errs.NewRestErr("error", http.StatusInternalServerError, "error", []string{"database error"}))
	if err != nil {
		t.Error("could not create responder")
	}
	httpmock.RegisterResponder(http.MethodGet, "/oauth/token/1234", responder)

	_, restErr := oauthServer.getAccessToken("1234")
	assert.NotNil(t, restErr)
	assert.EqualValues(t, []string{"database error"}, restErr.Causes())
}

func TestGetAccessTokenTokenUnmarshallError(t *testing.T) {
	httpmock.Reset()

	responder, err := httpmock.NewJsonResponder(http.StatusOK, map[string]interface{}{"id": 1234})
	if err != nil {
		t.Error("could not create responder")
	}
	httpmock.RegisterResponder(http.MethodGet, "/oauth/token/1234", responder)

	_, restErr := oauthServer.getAccessToken("1234")
	assert.NotNil(t, restErr)
	assert.EqualValues(t, "error when trying to unmarshal token response", restErr.Message())
}

func TestGetAccessTokenShouldReturnToken(t *testing.T) {
	httpmock.Reset()

	responder, err := httpmock.NewJsonResponder(http.StatusOK, &token{
		ID:       "asff123",
		UserId:   123,
		ClientId: 12,
	})
	if err != nil {
		t.Error("could not create responder")
	}
	httpmock.RegisterResponder(http.MethodGet, "/oauth/token/1234", responder)

	token, restErr := oauthServer.getAccessToken("1234")
	assert.Nil(t, restErr)
	assert.NotNil(t, token)
	assert.EqualValues(t, "asff123", token.ID)
	assert.EqualValues(t, 123, token.UserId)
	assert.EqualValues(t, 12, token.ClientId)
}

func TestCleanRequestShouldCleanHeaders(t *testing.T) {
	r := &http.Request{Header: map[string][]string{
		headerXClientId: {"123"},
		headerXCallerId: {"12"},
	}}

	cleanRequest(r)

	assert.EqualValues(t, "", r.Header.Get(headerXClientId))
	assert.EqualValues(t, "", r.Header.Get(headerXCallerId))
}

func TestCleanRequestRequestIsNil(t *testing.T) {
	cleanRequest(nil)
}

func TestAuthenticateRequestShouldSetHeaders(t *testing.T) {
	httpmock.Reset()
	u, err := url.Parse("http://localhost/test?token=1234")
	if err != nil {
		t.Error("could not create url")
	}
	responder, err := httpmock.NewJsonResponder(http.StatusOK, &token{
		ID:       "1234",
		UserId:   123,
		ClientId: 12,
	})
	if err != nil {
		t.Error("could not create responder")
	}
	httpmock.RegisterResponder(http.MethodGet, "/oauth/token/1234", responder)

	r := http.Request{URL: u, Header: make(http.Header)}

	restErr := AuthenticateRequest(&r)
	assert.Nil(t, restErr)

	assert.EqualValues(t, "12", r.Header.Get(headerXClientId))
	assert.EqualValues(t, "123", r.Header.Get(headerXCallerId))
}

func TestAuthenticateRequestNilRequest(t *testing.T) {
	restErr := AuthenticateRequest(nil)
	assert.Nil(t, restErr)
}

type mockOAuthServer struct {
	fn func(string) (*token, errs.RestErr)
}

func (m mockOAuthServer) getAccessToken(s string) (*token, errs.RestErr) {
	return m.fn(s)
}

func TestAuthenticateRequestNoTokenQueryParam(t *testing.T) {
	u, err := url.Parse("http://localhost/test")
	if err != nil {
		t.Error("could not create url")
	}

	r := http.Request{URL: u, Header: make(http.Header)}

	restErr := AuthenticateRequest(&r)
	assert.Nil(t, restErr)
}

func TestAuthenticateRequestTokenNotFound(t *testing.T) {
	u, err := url.Parse("http://localhost/test?token=1234")
	if err != nil {
		t.Error("could not create url")
	}
	tmp := oauthServer
	oauthServer = mockOAuthServer{fn: func(s string) (*token, errs.RestErr) {
		return nil, errs.NewNotFoundErr("token not found")
	}}

	r := http.Request{URL: u, Header: make(http.Header)}

	restErr := AuthenticateRequest(&r)
	assert.Nil(t, restErr)
	oauthServer = tmp
}

func TestAuthenticateRequestOAuthServerError(t *testing.T) {
	u, err := url.Parse("http://localhost/test?token=1234")
	if err != nil {
		t.Error("could not create url")
	}
	tmp := oauthServer
	oauthServer = mockOAuthServer{fn: func(s string) (*token, errs.RestErr) {
		return nil, errs.NewInternalServerErr("token not found", errors.New("database error"))
	}}

	r := http.Request{URL: u, Header: make(http.Header)}

	restErr := AuthenticateRequest(&r)
	assert.NotNil(t, restErr)
	oauthServer = tmp
}
