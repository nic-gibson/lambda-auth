package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

// Fetch the values for userid and key from headers and return them
// An error is returned if either header is missing. c.UserHeader can be blank when only an key is
// required.
func GetUserIdAndKeyFromHeaders(event events.APIGatewayV2CustomAuthorizerV2Request, c *Config) (string, string, error) {

	var userId, key string
	var ok bool

	if Logging() {
		log.Printf("fetching headers for key auth, headers are '%s' and '%s'", c.UserHeader, c.KeyHeader)
	}

	if c.UserHeader != "" {
		if userId, ok = event.Headers[c.UserHeader]; !ok {
			return "", "", fmt.Errorf("cannot get user id from header - %s", c.UserHeader)
		}
	}

	if c.KeyHeader == "" {
		return "", "", fmt.Errorf("cannot get key when key header is not defined")
	}

	if key, ok = event.Headers[c.KeyHeader]; !ok {
		return "", "", fmt.Errorf("cannot get key from header - %s", c.KeyHeader)
	}

	if Logging() {
		log.Printf("got user id '%s' and key '%s'", userId, key)
	}

	return userId, key, nil
}

// Fetch the values for userid and key (password) from Basic Autho
// Empty strings are returned if not found.
func GetUserIdAndKeyFromAuth(event events.APIGatewayV2CustomAuthorizerV2Request) (string, string, error) {

	if Logging() {
		log.Printf("fetching Authorization header for Basic Auth")
	}
	if authHeaderValue := event.Headers["Authorization"]; authHeaderValue == "" {
		return "", "", fmt.Errorf("no Authorization Header")
	} else {
		// REGEXP - case insensitively - (?i) -  match optional whitespace + Basic + whitespace + token
		re, _ := regexp.Compile(`(?i)\s*Basic\s+(.+)$`)
		results := re.FindStringSubmatch(authHeaderValue)
		if len(results) == 2 {
			token := results[1]
			if decoded, err := base64.StdEncoding.DecodeString(token); err != nil {
				return "", "", fmt.Errorf("unable to decode %s from base64 - %w", token, err)
			} else if !strings.Contains(string(decoded), ":") {
				return "", "", fmt.Errorf("unable to decode %s as auth token", token)
			} else {
				parts := strings.Split(string(decoded), ":")
				if Logging() {
					log.Printf("got user id '%s' and password '%s'", parts[0], parts[1])
				}
				return parts[0], parts[1], nil
			}
		} else {
			return "", "", fmt.Errorf("failed to parsed authorization header: %s", authHeaderValue)
		}

	}

}

// ValidateAuth returns true if the user id and key can be matched and false if not
func GetIdentity(event events.APIGatewayV2CustomAuthorizerV2Request, config *Config) (string, string, error) {

	var userId, key string
	var err error

	if config.BasicAuth {
		if userId, key, err = GetUserIdAndKeyFromAuth(event); err != nil {
			return "", "", err
		}
	} else {
		if userId, key, err = GetUserIdAndKeyFromHeaders(event, config); err != nil {
			return "", "", err
		}
	}

	return userId, key, nil

}

// ValidateIP returns true if the user's IP address in the whitelist or if the whitelist is empty
func AuthenticateIP(event events.APIGatewayV2CustomAuthorizerV2Request, config *Config) bool {

	if Logging() {
		log.Printf("testing whitelist for source IP '%s'", event.RequestContext.HTTP.SourceIP)
	}

	return config.ValidAddress(event.RequestContext.HTTP.SourceIP)
}

func Authenticate(event events.APIGatewayV2CustomAuthorizerV2Request, config *Config) (events.APIGatewayCustomAuthorizerResponse, error) {
	if userId, key, err := GetIdentity(event, config); err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, err
	} else {
		if Logging() {
			log.Printf("validating user id '%s' and key '%s'", userId, key)
		}

		if !config.ValidUser(userId, key) {
			return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unathorized")
		}

		if Logging() {
			log.Printf("validating source IP '%s'", event.RequestContext.HTTP.SourceIP)
		}

		if config.ValidAddress(event.RequestContext.HTTP.SourceIP) {
			return generateResponse(config, userId, event, "Allow"), nil
		} else {
			return generateResponse(config, userId, event, "Deny"), nil
		}
	}

}

func generateResponse(config *Config, userId string, event events.APIGatewayV2CustomAuthorizerV2Request, effect string) events.APIGatewayCustomAuthorizerResponse {

	arn, _ := arn.Parse(event.RouteArn)

	pathPaths := strings.Split(arn.Resource, "/")
	arnRoot := strings.Join(pathPaths[0:len(pathPaths)-2], "/")

	resources := make([]string, len(config.Paths))

	if len(config.Paths) == 0 {
		arn.Resource = arnRoot + "/*"
		resources = append(resources, arn.String())

		if Logging() {
			log.Printf("setting '%s' effect for user '%s' on *default* ARN  '%s'", effect, userId, arn.String())
		}
	} else {
		for n, path := range config.Paths {
			arn.Resource = arnRoot + path
			resources[n] = arn.String()

			if Logging() {
				log.Printf("setting '%s' effect for user '%s' on ARN  '%s'", effect, userId, arn.String())
			}
		}
	}
	return events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: userId,
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: resources,
				},
			},
		},
	}
}
