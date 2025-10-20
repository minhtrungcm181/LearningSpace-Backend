package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

type SignupRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

type signupRes struct {
	UserConfirmed bool   `json:"userConfirmed"`
	UserSub       string `json:"userSub"`
	Message       string `json:"message,omitempty"`
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type loginRes struct {
	message      string `json:"message"`
	IDtoken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type ConfirmRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type UserData struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	UserID   string `json:"userId"`
}

var (
	cognito   cip.Client
	appClient = os.Getenv("APP_CLIENT_ID")
	appSecret = os.Getenv("APP_CLIENT_SECRET")
)

func init() {
	cfg, err := config.LoadDefaultConfig(context.Background())

	if err != nil {
		panic(err)
	}

	cognito = *cip.NewFromConfig(cfg)
	if appClient == "" {
		panic("APP_CLIENT_ID env var is not set")
	}

}
func CognitoSecretHash(username, clientID, clientSecret string) string {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(username + clientID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func handleLogin(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var body loginReq
	err := json.Unmarshal([]byte(req.Body), &body)
	if err != nil {
		return jsonResp(http.StatusBadRequest, map[string]string{"error": "invalid request body"}), nil
	}
	if body.Username == "" || body.Password == "" {
		return jsonResp(http.StatusBadRequest, map[string]string{"error": "username and password is required"}), nil
	}
	input := &cip.InitiateAuthInput{
		AuthFlow: "USER_PASSWORD_AUTH",
		ClientId: aws.String(appClient),
		AuthParameters: map[string]string{
			"USERNAME":    body.Username,
			"PASSWORD":    body.Password,
			"SECRET_HASH": CognitoSecretHash(body.Username, appClient, appSecret),
		},
	}
	out, err := cognito.InitiateAuth(ctx, input)
	if err != nil {
		return jsonResp(http.StatusBadRequest, map[string]string{"error": err.Error()}), nil
	}

	return jsonResp(http.StatusOK, loginRes{
		message:      "Login success",
		IDtoken:      aws.ToString(out.AuthenticationResult.IdToken),
		AccessToken:  aws.ToString(out.AuthenticationResult.AccessToken),
		RefreshToken: aws.ToString(out.AuthenticationResult.RefreshToken),
	}), nil
}

func handleConfirm(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var body ConfirmRequest
	err := json.Unmarshal([]byte(request.Body), &body)
	if err != nil {
		return jsonResp(http.StatusBadRequest, map[string]string{"error": "invalid request body"}), nil
	}
	if body.Email == "" || body.Code == "" {
		return jsonResp(http.StatusBadRequest, map[string]string{"error": "email, code are required"}), nil
	}
	input := &cip.ConfirmSignUpInput{
		ClientId:         aws.String(appClient),
		Username:         aws.String(body.Email),
		ConfirmationCode: aws.String(body.Code),
		SecretHash:       aws.String(CognitoSecretHash(body.Email, appClient, appSecret)),
	}
	_, err = cognito.ConfirmSignUp(ctx, input)
	if err != nil {
		return jsonResp(http.StatusBadRequest, map[string]string{"error": err.Error()}), nil
	}
	return jsonResp(http.StatusOK, map[string]string{"status": "verified"}), nil
}

func handleSignup(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var body SignupRequest
	err := json.Unmarshal([]byte(req.Body), &body)
	if err != nil {
		return jsonResp(http.StatusBadRequest, map[string]string{"error": "invalid request body"}), nil
	}
	if body.Email == "" || body.Password == "" || body.DisplayName == "" {
		return jsonResp(http.StatusBadRequest, map[string]string{"error": "email, password and display_name are required"}), nil
	}
	input := &cip.SignUpInput{
		ClientId:   aws.String(appClient),
		Username:   aws.String(body.Email),
		Password:   aws.String(body.Password),
		SecretHash: aws.String(CognitoSecretHash(body.Email, appClient, appSecret)),
		UserAttributes: []types.AttributeType{
			{Name: aws.String("email"), Value: aws.String(body.Email)},
			{Name: aws.String("name"), Value: aws.String(body.DisplayName)},
		},
	}
	out, err := cognito.SignUp(ctx, input)
	if err != nil {
		return jsonResp(http.StatusInternalServerError, map[string]string{"error": err.Error()}), nil
	}
	return jsonResp(http.StatusCreated, signupRes{
		UserConfirmed: out.UserConfirmed,
		UserSub:       aws.ToString(out.UserSub),
		Message:       "Check your email for the verification code.",
	}), nil

}

func handleGetMe(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	if req.RequestContext.Authorizer == nil || req.RequestContext.Authorizer.JWT == nil {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusUnauthorized,
			Body:       `{"error":"missing JWT authorizer"}`,
		}, nil
	}

	claims := req.RequestContext.Authorizer.JWT.Claims
	email := claims["email"]
	username := claims["name"]
	userSub := claims["sub"]

	user := UserData{
		Username: username,
		Email:    email,
		UserID:   userSub,
	}
	b, _ := json.Marshal(user)

	return jsonResp(http.StatusOK, string(b)), nil
}
