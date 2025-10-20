package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

func jsonResp(status int, v any) events.APIGatewayV2HTTPResponse {
	b, _ := json.Marshal(v)
	return events.APIGatewayV2HTTPResponse{
		StatusCode: status,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(b),
	}
}

func notFound() events.APIGatewayV2HTTPResponse {
	return jsonResp(http.StatusNotFound, map[string]string{"error": "not found"})
}

func router(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	switch req.RequestContext.HTTP.Method + " " + req.RawPath {
	case "POST /auth/signup":
		return handleSignup(ctx, req)
	case "POST /auth/confirm":
		return handleConfirm(ctx, req)
	case "POST /auth/signin":
		return handleLogin(ctx, req)
	case "GET /me":
		return handleGetMe(ctx, req)
	default:
		return notFound(), nil
	}
}

func main() {
	lambda.Start(router)
}
