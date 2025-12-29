# Provenance Verification

SecureAI provides a provenance verification module that allows you to verify SLSA (Supply-chain Levels for Software Artifacts) provenance for container images, particularly those referenced in docker-compose files.

## Table of Contents

- [What is SLSA?](#what-is-slsa)
- [What is Provenance?](#what-is-provenance)
- [How It Works](#how-it-works)
- [Usage](#usage)
  - [Basic Usage](#basic-usage)
  - [Using the Convenience Function](#using-the-convenience-function)
  - [Advanced Policies](#advanced-policies)
  - [Ignoring Services](#ignoring-services)
  - [Verifying a Single Image](#verifying-a-single-image)
- [Policy Configuration](#policy-configuration)
- [Error Handling](#error-handling)
- [Debugging](#debugging)
- [Integration with RATLS](#integration-with-ratls)
- [Requirements](#requirements)

## What is SLSA?

**SLSA** (pronounced "salsa") stands for **Supply-chain Levels for Software Artifacts**. It's a security framework that helps protect against supply chain attacks by ensuring that software artifacts (like container images) can be traced back to their source code and build process.

SLSA defines four levels of increasing security guarantees:

- **Level 1**: Documentation of the build process
- **Level 2**: Tamper resistance of the build service
- **Level 3**: Extra resistance to specific threats (used by this module)
- **Level 4**: Highest levels of confidence and trust (Two-party review + hermetic builds)

You can read more [here](https://slsa.dev/spec/v0.1/levels).

When a container image has SLSA Level 3 provenance, it means:

1. The build process is fully defined and automated
2. The build service is hardened against tampering
3. There's cryptographic proof linking the image to its source code

## What is Provenance?

**Provenance** is metadata about how an artifact was built. It answers questions like:

- What source code was used?
- Who/what built it?
- What build system was used?
- What were the build inputs and outputs?

In the context of container images, provenance attestations are cryptographically signed statements that prove:

- The image was built from a specific Git repository
- The build happened at a specific commit
- The build was performed by a specific CI/CD workflow (e.g., GitHub Actions)

## How It Works

SecureAI's provenance verification uses [SLSA3 Container Generator](https://slsa.dev/blog/2023/02/slsa-github-workflows-container-ga) and [Sigstore](https://www.sigstore.dev/) for signing and verifying software artifacts. The SLSA3 Generator is responsible for publishing the attestation (it uses Sigstore's cosign under the hood). The client will then verify a given container image using the published attestation. The verification process is as follow:

1. **Parses your docker-compose file** to extract container image references
2. **Fetches attestations** from the container registry (stored alongside images)
3. **Verifies signatures and validates policies** describing the expected repo, commit, etc.

## Usage

### Basic Usage

```python
from secureai.provenance import (
    DockerComposeProvenanceVerifier,
    ProvenanceVerificationError,
    build_default_policy,
)

# Read your docker-compose file
with open("docker-compose.yml", "r") as f:
    docker_compose_content = f.read()

# Define policies for each service using the helper function
service_policies = {
    "nginx-cert-manager": build_default_policy(
        expected_repo="my-org/my-repo",
        expected_commit="abc123def456",  # Optional: pin to specific commit
    ),
    "auth-service": build_default_policy(
        expected_repo="my-org/my-repo",
    ),
    "attestation-service": build_default_policy(
        expected_repo="my-org/my-repo",
    ),
}

# Create verifier and verify
verifier = DockerComposeProvenanceVerifier(
    docker_compose=docker_compose_content,
    service_policies=service_policies,
)

try:
    result = verifier.verify()
    print("All services verified successfully!")
    for service_name, service_result in result.service_results.items():
        print(f"  {service_name}: {service_result.result.image}")
except ProvenanceVerificationError as e:
    print(f"Verification failed: {e}")
```

### Using the Convenience Function

For simpler use cases:

```python
from secureai.provenance import (
    verify_docker_compose_provenance,
    build_default_policy,
)

result = verify_docker_compose_provenance(
    docker_compose=docker_compose_content,
    service_policies={
        "web": build_default_policy("org/web-app"),
    },
)
```

### Advanced Policies

For more control, use Sigstore's policy classes directly:

```python
from secureai.provenance import DockerComposeProvenanceVerifier
from sigstore.verify.policy import (
    AllOf,
    AnyOf,
    Identity,
    OIDCIssuer,
    GitHubWorkflowRepository,
    GitHubWorkflowSHA,
    GitHubWorkflowRef,
)

GITHUB_OIDC = "https://token.actions.githubusercontent.com"

service_policies = {
    # Strict policy: specific commit and main branch only
    "production-api": AllOf([
        OIDCIssuer(GITHUB_OIDC),
        GitHubWorkflowRepository("my-org/api-server"),
        GitHubWorkflowSHA("abc123def456"),
        GitHubWorkflowRef("refs/heads/main"),
    ]),

    # Flexible policy: allow multiple signers
    "shared-library": AnyOf([
        AllOf([
            OIDCIssuer(GITHUB_OIDC),
            GitHubWorkflowRepository("my-org/shared-lib"),
        ]),
        AllOf([
            OIDCIssuer(GITHUB_OIDC),
            GitHubWorkflowRepository("trusted-org/shared-lib"),
        ]),
    ]),
}

verifier = DockerComposeProvenanceVerifier(
    docker_compose=docker_compose_content,
    service_policies=service_policies,
)
```

### Ignoring Services

Some services (like databases) may not have SLSA provenance. Use the `ignore` parameter to skip them:

```python
verifier = DockerComposeProvenanceVerifier(
    docker_compose=docker_compose_content,
    service_policies={
        "web": build_default_policy("org/web-app"),
        "api": build_default_policy("org/api-server"),
    },
    ignore=["redis", "postgres", "nginx"],  # Skip these services
)
```

### Verifying a Single Image

You can also verify individual container images:

```python
from secureai.provenance import ContainerSLSAVerifier, build_default_policy

verifier = ContainerSLSAVerifier()
policy = build_default_policy(
    expected_repo="my-org/my-repo",
    expected_commit="abc123def456",
)

result = verifier.verify(
    image_ref="ghcr.io/my-org/my-service@sha256:abc123...",
    policy=policy,
)

if result.verified:
    print(f"Verified! Provenance: {result.provenance}")
else:
    print(f"Failed: {result.error}")
```

## Policy Configuration

### build_default_policy Helper

The `build_default_policy` function creates a policy for the standard SLSA GitHub generator workflow:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `expected_repo` | str | Yes | GitHub repository (e.g., "org/repo") |
| `expected_commit` | str | No | Exact commit SHA to verify |
| `expected_workflow_name` | str | No | GitHub Actions workflow name |

### Available Sigstore Policy Classes

For advanced use cases, see available Sigstore policy classes [here](https://sigstore.github.io/sigstore-python/api/verify/policy/).

### Image Requirements

Images must:

1. **Include a digest** (e.g., `@sha256:...`), not just a tag
2. **Have SLSA provenance attestations** published to the same registry
3. **Be built using the SLSA GitHub generator** workflow (or compatible)

## Error Handling

The module raises `ProvenanceVerificationError` with detailed information:

```python
from secureai.provenance import (
    DockerComposeProvenanceVerifier,
    ProvenanceVerificationError,
)

try:
    result = verifier.verify()
except ProvenanceVerificationError as e:
    print(f"Error: {e}")
    print(f"Service: {e.service}")   # Which service failed
    print(f"Image: {e.image}")       # Which image failed
    print(f"Reason: {e.reason}")     # Detailed reason
```

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| "No policies provided for services" | Service in docker-compose lacks a policy | Add policy or add to `ignore` list |
| "No SLSA attestation found" | Image doesn't have provenance attestation | Ensure image was built with SLSA generator |
| "Signature verification failed" | Policy doesn't match attestation | Check expected repo, commit, etc. |
| "Image reference must include a digest" | Image uses tag instead of digest | Use `@sha256:...` format |

## Debugging

Enable debug logging to see detailed verification steps:

```bash
export DEBUG_PROVENANCE=true
```

This will log:

- Docker-compose parsing progress
- Each service found and its image
- Policy matching
- Verification steps for each image
- Success/failure for each service

Example output:

```
2024-01-15 10:30:00 - provenance - DEBUG - DockerComposeProvenanceVerifier initialized
2024-01-15 10:30:00 - provenance - DEBUG -   Policies provided for services: ['web', 'api']
2024-01-15 10:30:00 - provenance - DEBUG -   Services to ignore: ['redis']
2024-01-15 10:30:00 - provenance - DEBUG - Starting provenance verification...
2024-01-15 10:30:00 - provenance - DEBUG - Parsing docker-compose file...
2024-01-15 10:30:00 - provenance - DEBUG -   Found service 'web': ghcr.io/org/web@sha256:abc...
2024-01-15 10:30:00 - provenance - DEBUG -   Found service 'api': ghcr.io/org/api@sha256:def...
2024-01-15 10:30:00 - provenance - DEBUG - Verifying service 'web'...
2024-01-15 10:30:01 - provenance - DEBUG -   Service 'web' verification: PASSED
```

## Integration with RATLS

Provenance verification complements RATLS verification for complete supply chain security:

1. **Provenance Verification**: Verify images came from trusted sources (software supply chain)
2. **RATLS Verification**: Verify the runtime environment is a TEE running expected components (hardware attestation)

```python
from secureai.provenance import DockerComposeProvenanceVerifier, build_default_policy
from secureai.verifiers import DstackTDXVerifier

# Read docker-compose
with open("docker-compose.yml", "r") as f:
    docker_compose_content = f.read()

# Step 1: Verify provenance of images
provenance_verifier = DockerComposeProvenanceVerifier(
    docker_compose=docker_compose_content,
    service_policies={
        "vllm": build_default_policy("my-org/vllm-service", expected_commit="hash1"),
        "auth": build_default_policy("my-org/auth-service", expected_commit="hash1"),
    },
    ignore=["redis"],
)
provenance_verifier.verify()  # Raises on failure
print("Provenance verification passed!")

# Step 2: Use the same docker-compose for RATLS verification
ratls_verifier = DstackTDXVerifier(
    app_compose_docker_compose_file=docker_compose_content,
    expected_bootchain={...},
    os_image_hash="...",
)

# Step 3: Use RATLS verifier with your HTTP client
from secureai import OpenAI

client = OpenAI(
    base_url="https://secure-api.example.com/v1",
    ratls_verifier_per_hostname={
        "secure-api.example.com": ratls_verifier,
    },
)
```
