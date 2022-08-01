package main

import (
	"context"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/nic-gibson/lambda-auth/auth"
)

var authConfig *auth.Config

func main() {

	if cfg, err := auth.NewFromSecret(context.Background(), os.Getenv("AWS_REGION"), os.Getenv("LAMBDA_AHTH_CONFIG")); err != nil {
		log.Fatalf("unable to load configuration: %v", err)
	} else {
		authConfig = cfg
	}

	lambda.Start(Handler)
}

func Handler(ctx context.Context, event events.APIGatewayV2CustomAuthorizerV2Request) (events.APIGatewayCustomAuthorizerResponse, error) {
	return auth.Authenticate(event, authConfig)
}
