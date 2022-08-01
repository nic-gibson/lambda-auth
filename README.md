# LAMBDA-AUTH 

This package implements a basic auth for Lambda functions along with a simple API key model. It also implements IP whitelisting. This is a very simple authenticator, taking all configuration from a JSON config file.

Configuration is done via a JSON document stored in an AWS secret. The lambda handler in main.go finds this by looking up the name of the  secret in an environment variable: LAMBDA_AUTH_CONFIG

## Configuration

### Basic auth

If basic auth is enabled then the configuration file contains the following keys

* `whitelist`: an array of CIDR networks and/or IP addresses that should be allowed access to the resources. If empty or omitted, all addresses are allowed
* `paths`: an array of paths (with optional wildcards). Each path consists of HTTP verb followed by a resource path (see [AWS docs](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-control-access-using-iam-policies-to-invoke-api.html#api-gateway-calling-api-permissions)). The resources authenticated by this function are defined by these. For each path an ARN is gnerated using the RouteArn for the lambda call, replacing the resource portion of the ARN with the invidual path values. If ommitted a single path "*" will be used.
* `basicAuth`: true when using basic authentication
* `users`: an array of objects, each with `userid` and `key` keys. Logins are validated against this set of users

```
{
    whitelist: ["10.11.12.0/24", "192.168.1.3"]
    paths: [
        "/GET/api/acount/*",
        "*/api/user/*"
    ],
    basicAuth: true,
    users: [
        {
            "userid": "user1",
            "key": "password1"
        },
        {
            "userid": "user2",
            "key": "password2"
        }
    ]
}
```

### API Keys

If basic auth is not in  use then the configuration file contains the following keys:

* `whitelist`: as above
* `paths`: as above
* `basicAuth`: false or omitted
* `userHeader`: the name of the HTTP header from where a user id is taken. If omitted, user ids are not checked and only the `key` field below is checked (by iterating the array) 
* `keyHeader`: the name of the HTTP header from where an API key is taken. This is mandatory. 
* `users`: an array of objects, each with `userid` and `key` keys. Logins are validated against this set of users

```
{
    whitelist: ["10.11.12.0/24", "192.168.1.3"]
    paths: [
        "/GET/api/acount/*",
        "*/api/user/*"
    ],
    basicAuth: false,
    userHeader: "x-api-user",
    keyHeader: "x-api-key",
    users: [
        {
            "userid": "user1",
            "key": "key1"
        },
        {
            "userid": "user2",
            "key": "key2"
        }
    ]
}
```

The only difference between the two approaches is _where_ the userid and key are fetched from.

### Debugging & testing

Setting the environment variable `LAMBDA_AUTH_LOGGING` will enable some additional testing output. 

## Usage

The lambda function finds the configuration file using an environment variable. The name of a AWS Secret must be stored in the environment variable `LAMBDA_AUTH_CONFIG`. That secret must contain the config file. The config file is read when `main()` is called and cached for the duration of the lambda


