package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/apigatewaymanagementapi"
	apiTypes "github.com/aws/aws-sdk-go-v2/service/apigatewaymanagementapi/types"
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

type RequestBody struct {
	Action  string `json:"action"`
	Message string `json:"message"`
}

func getAwsConfig() (cfg aws.Config) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	return cfg
}

func init() {
	ddbClient = ddb.NewFromConfig(getAwsConfig())
}

func handler(ctx context.Context, request events.APIGatewayWebsocketProxyRequest) (events.APIGatewayProxyResponse, error) {
	if request.RequestContext.RouteKey != "sendMessage" {
		return events.APIGatewayProxyResponse{StatusCode: 201}, nil
	}
	var body RequestBody
	err := json.Unmarshal([]byte(request.Body), &body)

	if body.Message == "" || err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 201}, nil
	}
	out, err := ddbClient.Query(ctx, &ddb.QueryInput{
		TableName:              aws.String(tableName),
		KeyConditionExpression: aws.String("roomId = :r"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":r": &types.AttributeValueMemberS{Value: roomID},
		},
		ProjectionExpression: aws.String("connectionId, username"),
	})
	if err != nil {
		log.Printf("Error querying ddb: %v", err)
		return events.APIGatewayProxyResponse{StatusCode: 500}, err
	}

	api := apigatewaymanagementapi.NewFromConfig(getAwsConfig(), func(o *apigatewaymanagementapi.Options) {
		// IMPORTANT: include the stage at the end
		o.BaseEndpoint = aws.String(fmt.Sprintf("https://%s/%s",
			request.RequestContext.DomainName,
			request.RequestContext.Stage,
		))
	})
	for _, item := range out.Items {
		connAttr := item["connectionId"].(*types.AttributeValueMemberS)
		usernameAttr := item["username"].(*types.AttributeValueMemberS)
		payload := map[string]string{
			"username": usernameAttr.Value,
			"message":  body.Message,
		}
		b, _ := json.Marshal(payload)
		_, err = api.PostToConnection(ctx, &apigatewaymanagementapi.PostToConnectionInput{
			ConnectionId: aws.String(connAttr.Value),
			Data:         b,
		})
		if err != nil {
			var gone *apiTypes.GoneException
			if errors.As(err, &gone) {
				// delete stale connection
				_, _ = ddbClient.DeleteItem(ctx, &ddb.DeleteItemInput{
					TableName: aws.String(tableName),
					Key: map[string]types.AttributeValue{
						"roomId":       &types.AttributeValueMemberS{Value: roomID},
						"connectionId": &types.AttributeValueMemberS{Value: connAttr.Value},
					},
				})
			}
		}
	}
	return events.APIGatewayProxyResponse{StatusCode: 200}, nil
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
