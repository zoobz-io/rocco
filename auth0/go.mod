module github.com/zoobzio/rocco/auth0

go 1.24

toolchain go1.25.5

require (
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/zoobzio/capitan v1.0.0
	github.com/zoobzio/clockz v1.0.0
	github.com/zoobzio/rocco v1.0.0
)

require (
	github.com/zoobzio/openapi v1.0.0 // indirect
	github.com/zoobzio/sentinel v1.0.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/zoobzio/rocco => ../
