// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package api holds the generated model types of the frozen wire contract
// (docs/api/openapi.yaml). internal/rest marshals these types, so response
// shapes are compile-checked against the spec. Do not edit api.gen.go —
// regenerate with `go generate ./internal/api` and commit the result; CI
// fails on drift.
package api

//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.1 -config ../../docs/api/oapi-codegen.yaml -o api.gen.go ../../docs/api/openapi.yaml
