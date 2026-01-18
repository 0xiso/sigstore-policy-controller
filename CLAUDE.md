# CLAUDE.md

This file provides guidance for AI assistants working on the sigstore policy-controller codebase.

## Project Overview

Policy Controller is a Kubernetes admission controller (webhook) that enforces container image signature and attestation verification policies. It validates that images running in a cluster are signed by approved authorities using the Sigstore ecosystem.

## Build Commands

```bash
make policy-controller      # Build main webhook binary
make policy-tester          # Build policy tester CLI
make local-dev              # Build local development tool
make test                   # Run unit tests
make lint                   # Run golangci-lint
make fmt                    # Format Go code (goimports)
make ko-apply               # Build and deploy to current k8s cluster
make docs/generate-api      # Regenerate API documentation
```

## Testing

```bash
# Unit tests
make test

# E2E tests (require Kind cluster)
./test/e2e_test_cluster_image_policy.sh

# Manual policy testing
./bin/policy-tester --policy <yaml-file> --image <image-ref>

# Local development cluster
./bin/local-dev setup --cluster-name=policy-test
./bin/local-dev clean --cluster-name=policy-test
```

## Repository Structure

- `cmd/webhook/` - Main policy-controller webhook entry point
- `cmd/tester/` - policy-tester CLI for validating policies locally
- `pkg/apis/policy/v1beta1/` - ClusterImagePolicy and TrustRoot CRD types
- `pkg/webhook/` - Admission webhook validation logic
- `pkg/policy/` - Policy compilation and image verification
- `pkg/reconciler/` - Kubernetes reconciler controllers
- `config/` - Kubernetes manifests for deployment
- `test/` - E2E test scripts and test data
- `examples/policies/` - Example ClusterImagePolicy YAML files

## Key Files

| File | Purpose |
|------|---------|
| `pkg/apis/policy/v1beta1/clusterimagepolicy_types.go` | Main CRD type definitions |
| `pkg/apis/policy/v1beta1/clusterimagepolicy_validation.go` | CRD validation logic |
| `pkg/webhook/validator.go` | Core admission webhook validation |
| `pkg/policy/validate.go` | Policy parsing and verification |
| `pkg/reconciler/clusterimagepolicy/clusterimagepolicy.go` | Policy reconciliation |

## Architecture

1. **ClusterImagePolicy CRD** - Users create these to define verification policies
2. **Reconciler** - Watches CRDs, inlines keys/policies, updates ConfigMaps
3. **Webhook** - Intercepts pod creation, validates images against compiled policies
4. **Policy Package** - Standalone verification logic usable by external tools

## Development Patterns

### API Changes
When modifying CRD types:
1. Edit types in `pkg/apis/policy/v1beta1/clusterimagepolicy_types.go`
2. Update validation in `clusterimagepolicy_validation.go`
3. Update defaults in `clusterimagepolicy_defaults.go` if needed
4. Run code generation
5. Update API docs: `make docs/generate-api`

### Status Conditions
Reconcilers use these conditions on ClusterImagePolicy:
- `ClusterImagePolicyConditionReady` - Overall readiness
- `ClusterImagePolicyConditionKeysInlined` - Public keys resolved
- `ClusterImagePolicyConditionPoliciesInlined` - External policies fetched
- `ClusterImagePolicyConditionCMUpdated` - ConfigMap updated

### Policy Modes
- `enforce` - Reject pods if verification fails (default)
- `warn` - Allow pods but emit warning if verification fails

## Code Style

- Uses Knative framework patterns for webhooks and controllers
- Go 1.25 with modules
- Linter: golangci-lint (see `.golangci.yml`)
- Format with goimports

## Common Mistakes to Avoid

- Not running code generation after API type changes
- Forgetting to update both validation and defaults for new fields
- Missing status condition updates in reconcilers
- Not testing with actual container registries in e2e tests
- Adding security vulnerabilities (this is security-critical code)

## Key Dependencies

- `github.com/sigstore/cosign/v2` - Container signature verification
- `github.com/sigstore/sigstore` - Cryptographic utilities
- `knative.dev/pkg` - Kubernetes patterns (webhooks, reconcilers)
- `github.com/google/go-containerregistry` - OCI image handling
