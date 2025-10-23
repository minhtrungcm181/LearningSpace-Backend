package main

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	ddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"log"
	"os"
)

var (
	tableName = mustEnv("TABLE_NAME")
	roomID    = getEnv("ROOM_ID", "global")

	ddbClient *ddb.Client
)

func init() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	ddbClient = ddb.NewFromConfig(cfg)
}

func handler(ctx context.Context, request events.APIGatewayWebsocketProxyRequest) (events.APIGatewayProxyResponse, error) {
	if request.RequestContext.RouteKey != "$disconnect" {
		return events.APIGatewayProxyResponse{StatusCode: 200}, nil
	}
	connID := request.RequestContext.ConnectionID
	_, err := ddbClient.DeleteItem(ctx, &ddb.DeleteItemInput{
		TableName: aws.String(tableName),
		Key: map[string]types.AttributeValue{
			"roomId":       &types.AttributeValueMemberS{Value: roomID},
			"connectionId": &types.AttributeValueMemberS{Value: connID},
		},
	})
	if err != nil {
		log.Printf("DeleteItem error: %v", err)
		return resp(500, "disconnect error"), nil
	}
	return resp(200, "ok"), nil
}

func resp(code int, body string) events.APIGatewayProxyResponse {
	return events.APIGatewayProxyResponse{
		StatusCode: code,
		Body:       body,
	}
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

func main() { lambda.Start(handler) }
