module github.com/zoobz-io/rocco/auth0

go 1.24.0

toolchain go1.25.5

require (
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/zoobz-io/capitan v1.0.2
	github.com/zoobz-io/clockz v1.0.2
	github.com/zoobz-io/rocco v0.1.13
)

require (
	github.com/zoobz-io/check v0.0.5 // indirect
	github.com/zoobz-io/openapi v1.0.2 // indirect
	github.com/zoobz-io/sentinel v1.0.4 // indirect
	golang.org/x/exp v0.0.0-20260112195511-716be5621a96 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/zoobz-io/rocco => ../
