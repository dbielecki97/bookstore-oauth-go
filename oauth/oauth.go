package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/dbielecki97/bookstore-oauth-go/oauth/errors"
	"gopkg.in/resty.v1"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramToken = "token"
)

var (
	oauthRestClient = resty.NewWithClient(&http.Client{
		Timeout: 200 * time.Millisecond,
	}).SetHostURL("http://localhost:8081")
)

type token struct {
	ID       string `json:"id,omitempty"`
	UserId   int64  `json:"user_id,omitempty"`
	ClientId int64  `json:"client_id,omitempty"`
}

func GetCallerId(req *http.Request) int64 {
	if req == nil {
		return 0
	}

	callerId, err := strconv.ParseInt(req.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(req *http.Request) int64 {
	if req == nil {
		return 0
	}

	clientId, err := strconv.ParseInt(req.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func IsPublic(req *http.Request) bool {
	if req == nil {
		return true
	}

	return req.Header.Get(headerXPublic) == "true"
}

func AuthenticateRequest(req *http.Request) *errors.RestErr {
	if req == nil {
		return nil
	}

	cleanRequest(req)

	tokenId := strings.TrimSpace(req.URL.Query().Get(paramToken))
	if tokenId == "" {
		return nil
	}

	token, err := getAccessToken(tokenId)
	if err != nil {
		if err.StatusCode == http.StatusNotFound {
			return nil
		}
		return err
	}

	req.Header.Add(headerXCallerId, fmt.Sprintf("%v", token.UserId))
	req.Header.Add(headerXClientId, fmt.Sprintf("%v", token.UserId))

	return nil
}

func cleanRequest(req *http.Request) {
	if req == nil {
		return
	}

	req.Header.Del(headerXClientId)
	req.Header.Del(headerXCallerId)
}

func getAccessToken(tokenId string) (*token, *errors.RestErr) {
	res, err := oauthRestClient.R().Get(fmt.Sprintf("/oauth/token/%s", tokenId))
	if err != nil {
		fmt.Println(err)
		return nil, errors.NewInternalServerError("restclient error")
	}

	if res.StatusCode() > 299 {
		var restErr errors.RestErr
		if err := json.Unmarshal(res.Body(), &restErr); err != nil {
			return nil, errors.NewInternalServerError("invalid error interface when trying to get token")
		}

		return nil, &restErr
	}

	var t token
	err = json.Unmarshal(res.Body(), &t)
	if err != nil {
		return nil, errors.NewInternalServerError("error when trying to unmarshal token response")
	}

	return &t, nil
}
