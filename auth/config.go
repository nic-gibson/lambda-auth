package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const CONFIG_ENV = "LAMBDA_AUTH_CONFIG"
const CONFIG_LOGGING = "LAMBDA_AUTH_LOGGING"

// User represents a user id and key/password pair. UserId may be empty if we are only checking against keys
type User struct {
	UserId string `json:"userId"`
	Key    string `json:"key"`
}

// Config represents the contents of the configuration secret and provides functions to check user validity.
type Config struct {
	Whitelist   []string `json:"whiteList"`
	ipWhiteList []*net.IPNet
	BasicAuth   bool     `json:"basicAuth"`
	Users       []User   `json:"users"`
	Paths       []string `json:"paths"`
	UserHeader  string   `json:"userHeader"`
	KeyHeader   string   `json:"keyHeader"`
}

// GetSecretName returns the name of the AWS secret.
func GetSecretName() string {
	return os.Getenv(CONFIG_ENV)
}

// GetLogging returns true if the CONFIG_LOGGING environment is set to something
// we consider to be true ("yes" or "true")
func Logging() bool {
	logVar := strings.ToLower(os.Getenv(CONFIG_LOGGING))
	return logVar == "yes" || logVar == "true"
}

// Load the configuration from an AWS Secret.
func NewFromSecret(ctx context.Context, region, secretName string) (*Config, error) {

	if region == "" {
		return nil, fmt.Errorf("can't initialise the secrets manager without an AWS region")
	}

	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("can't initialise an AWS config - %+v", err)
	}

	secrets := secretsmanager.NewFromConfig(awsConfig)

	if secretName == "" {
		return nil, fmt.Errorf("unable to find the secret name in the environment")
	}

	// And the value
	secretValue, err := secrets.GetSecretValue(ctx,
		&secretsmanager.GetSecretValueInput{
			SecretId: &secretName,
		},
	)

	if err != nil {
		return nil, fmt.Errorf("unable to load secret from AWS: %+v", err)
	}

	// Unmarshall the JSON to a struct
	cfg := Config{}
	err = json.Unmarshal([]byte(*secretValue.SecretString), &cfg)

	if err != nil {
		return nil, fmt.Errorf("unable to decode secret to config data - %+v", err)
	}

	return &cfg, cfg.initWhitelist()
}

// Compare a user id and password/key against the config, returning true if they match
func (c *Config) ValidUser(userId, key string) bool {

	for _, user := range c.Users {

		if c.UserHeader == "" && user.Key == key {
			return true
		} else if user.UserId == userId && user.Key == key {
			return true
		}
	}

	return false
}

// Compare an IP address against the whitelist, returning true if in the whitelist or
// if the whitelist is empty.
func (c *Config) ValidAddress(ipAddr string) bool {

	// If we are not checking then return true
	if len(c.Whitelist) == 0 {
		return true
	}

	// Convert the address.
	if ip := net.ParseIP(ipAddr); ip == nil {
		return false
	} else {
		for _, network := range c.ipWhiteList {
			if network.Contains(ip) {
				return true
			}
		}
		return false
	}
}

// Take the whitelist defined as strings and convert to IP networks
func (c *Config) initWhitelist() error {

	for _, addr := range c.Whitelist {

		// First try as a network.
		if _, cidr, err := net.ParseCIDR(addr); err != nil {
			// Put a /32 on the end and try again
			if _, cidr, err := net.ParseCIDR(addr + "/32"); err != nil {
				return err
			} else {
				c.ipWhiteList = append(c.ipWhiteList, cidr)
			}
		} else {
			c.ipWhiteList = append(c.ipWhiteList, cidr)
		}
	}

	return nil
}
