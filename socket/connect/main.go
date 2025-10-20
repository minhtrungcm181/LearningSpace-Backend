package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	ddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/golang-jwt/jwt/v5"
)

var (
	tableName   = mustEnv("TABLE_NAME")
	roomID      = getEnv("ROOM_ID", "global")
	region      = getEnv("AWS_REGION", "ap-northeast-1")
	userPoolID  = mustEnv("COGNITO_USER_POOL_ID")
	appClientID = mustEnv("COGNITO_APP_CLIENT_ID")
	issuer      = fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolID)
	jwksURL     = issuer + "/.well-known/jwks.json"

	ddbClient *ddb.Client
	jwks      jwksCache
)

type jwksCache struct {
	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey // kid -> key
	exp  time.Time
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing env %s", k)
	}
	return v
}

func init() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	ddbClient = ddb.NewFromConfig(cfg)
	jwks = jwksCache{keys: map[string]*rsa.PublicKey{}, exp: time.Time{}}
}

// entry
func handler(ctx context.Context, req events.APIGatewayWebsocketProxyRequest) (events.APIGatewayProxyResponse, error) {
	if req.RequestContext.RouteKey != "$connect" {
		return events.APIGatewayProxyResponse{StatusCode: 200}, nil
	}

	// 1) Lấy token từ query (?token=)
	tokenStr := extractToken(req)
	if tokenStr == "" {
		return resp(401, "missing token in query (?token=<JWT>)"), nil
	}

	// 2) Verify JWT (chữ ký + iss + aud + exp)
	claims := jwt.MapClaims{}
	keyFunc := func(t *jwt.Token) (any, error) {
		// chỉ nhận RSA
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected alg: %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		pub, err := getPublicKey(kid)
		if err != nil {
			return nil, err
		}
		return pub, nil
	}

	parsed, err := jwt.ParseWithClaims(
		tokenStr,
		claims,
		keyFunc,
		jwt.WithIssuer(issuer),
		jwt.WithAudience(appClientID),
	)
	if err != nil || !parsed.Valid {
		log.Printf("JWT invalid: %v", err)
		return resp(401, "invalid token"), nil
	}

	// 3) Kiểm tra token_use + lấy identity
	tu, _ := claims["token_use"].(string) // "id" hoặc "access" tuỳ bạn chấp nhận
	if tu != "id" && tu != "access" {
		return resp(401, "invalid token_use"), nil
	}
	sub := str(claims["sub"])
	username := str(claims["cognito:username"])
	email := str(claims["email"])

	// 4) Ghi vào DynamoDB
	connID := req.RequestContext.ConnectionID
	_, err = ddbClient.PutItem(ctx, &ddb.PutItemInput{
		TableName: aws.String(tableName),
		Item: map[string]types.AttributeValue{
			"roomId":       &types.AttributeValueMemberS{Value: roomID},
			"connectionId": &types.AttributeValueMemberS{Value: connID},
			"userId":       &types.AttributeValueMemberS{Value: sub},
			"username":     &types.AttributeValueMemberS{Value: username},
			"email":        &types.AttributeValueMemberS{Value: email},
			"connectedAt":  &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Unix(), 10)},
		},
		ConditionExpression: aws.String("attribute_not_exists(connectionId)"),
	})
	if err != nil {
		log.Printf("PutItem error: %v", err)
		return resp(500, "db error"), nil
	}

	return resp(200, "ok"), nil
}

// ---------------- helpers ----------------

func extractToken(req events.APIGatewayWebsocketProxyRequest) string {
	// Chỉ lấy từ query ?token=
	return req.QueryStringParameters["token"]
}

func getPublicKey(kid string) (*rsa.PublicKey, error) {
	now := time.Now()
	jwks.mu.RLock()
	if now.Before(jwks.exp) {
		if k := jwks.keys[kid]; k != nil {
			jwks.mu.RUnlock()
			return k, nil
		}
	}
	jwks.mu.RUnlock()

	keys, err := fetchJWKS()
	if err != nil {
		return nil, err
	}

	jwks.mu.Lock()
	jwks.keys = keys
	jwks.exp = time.Now().Add(6 * time.Hour)
	jwks.mu.Unlock()

	if k := keys[kid]; k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("kid not found in JWKS: %s", kid)
}

func fetchJWKS() (map[string]*rsa.PublicKey, error) {
	req, _ := http.NewRequest("GET", jwksURL, nil)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("jwks http %d: %s", res.StatusCode, string(b))
	}
	var body struct {
		Keys []struct {
			Kty string `json:"kty"`
			E   string `json:"e"`
			N   string `json:"n"`
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return nil, err
	}

	out := make(map[string]*rsa.PublicKey, len(body.Keys))
	for _, k := range body.Keys {
		if k.Kty != "RSA" {
			continue
		}
		// v5 không còn jwt.DecodeSegment → dùng base64.RawURLEncoding
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		e := 0
		for _, b := range eb {
			e = e<<8 + int(b)
		}
		out[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
	}
	return out, nil
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func resp(code int, body string) events.APIGatewayProxyResponse {
	return events.APIGatewayProxyResponse{
		StatusCode: code,
		Body:       body,
	}
}

func main() { lambda.Start(handler) }
