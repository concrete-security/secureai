# SecureAI

**SecureAI** is a Python library that adds RATLS (Remote Attestation TLS) support to popular HTTP clients, including OpenAI SDK and httpx. It enables applications to cryptographically verify that AI inference and API services are running inside Trusted Execution Environments (TEEs) like Intel TDX before sending sensitive data.

The library transparently extends existing clients - simply specify which hostnames require TEE attestation, and SecureAI handles the verification automatically during the TLS handshake.

## Installation

SecureAI uses [uv](https://docs.astral.sh/uv/getting-started/installation/) for dependency management and building.

You can install SecureAI from PyPI or build it from source.

```bash
# From PyPI
uv pip install secureai

# From source
git clone https://github.com/concrete-security/secureai.git
cd secureai
uv build # to build the wheel
uv pip install dist/secureai-*.whl
```

## What is RATLS?

Remote Attestation TLS (RATLS) extends standard TLS with hardware-based attestation to verify that a server is running inside a Trusted Execution Environment (TEE) like Intel TDX. This ensures your data is processed in a secure, isolated environment.

RATLS provides cryptographic proof that the client is communicating with the correct server identity (as defined in the TLS certificate) and that the server is running inside a TEE.

### Context

The TEE server maintains an **event log** that records all significant operations, including TLS certificate renewals. When the server generates a new certificate (using keys created inside the TEE that never leave it), it appends an event to this log containing the certificate hash.

The TEE hardware uses these event logs to compute **Runtime Measurements (RTMRs)** - cryptographic hashes that reflect the entire state and history of the TEE. These RTMRs are included in the attestation quote and can be verified by clients to ensure the TEE is running expected software with the expected certificate.

### How it works

- **Pre-RATLS Setup** (happens before client connects): Server adds a certificate event to its event log whenever it renews its TLS certificate. This updates the RTMR3 register using the new certificate hash.
- **TLS Connection**: Client establishes a standard TLS connection with the server and retrieves the TLS certificate.
- **Quote Request**: Client sends random challenge data (64 bytes) and requests a cryptographic quote from the TEE.
- **Quote Response**: Server generates and returns a quote signed by the TEE hardware, along with metadata:
   - Quote contains: random challenge data, runtime measurements (RTMRs)
   - Metadata contains: event log with TLS certificate hash
- **Verification**: Client verifies:
   - Quote signature using the DCAP library
   - TLS certificate (current session) matches the one in the event log
   - Event log correctly produces the RTMRs by replaying all events
   - TEE measurements match expected values
   - TCB status is UpToDate

```
Client                                    Server (TEE)
  |----- Pre-RATLS ---------------------------|
  |                                           |
  |                                           |
  |                                     0. Append new event to the
  |                                        event log with cert hash
  |                                        when doing cert renewal
  |                                           |
  |                                           |
  |----- RATLS -------------------------------|
  |                                           |
  | 1. TLS Handshake                          |
  |<=========================================>|
  |   (Get TLS certificate)                   |
  |                                           |
  | 2. POST /tdx_quote                        |
  |    { report_data: <random_64_bytes> }     |
  |------------------------------------------>|
  |                                           |
  |                                     3. Generate Quote + Metadata
  |                                      - Quote include report_data, RTMRs, ...
  |                                      - Metadata include event_log containing cert hash
  |                                      - Sign with TEE hardware key
  |                                      - Other measurements
  | 4. Quote Response                         |
  |<------------------------------------------|
  |                                           |
  | 5. Client Verification                    |
  |  - Verify quote signature (DCAP)          |
  |  - Check report_data matches challenge    |
  |  - Check cert hash in event_log matches   |
  |  - Verify event_log by replaying RTMRs    |
  |  - Verify TCB status is UpToDate          |
  |  - Verify runtime measurements            |
  |                                           |
  | 6. Regular HTTPS requests                 |
  |    (if verification passed)               |
  |<=========================================>|
```

## Server Requirements

For a server to support RATLS verification with SecureAI, it must:

1. **Run inside a TEE**: Currently only Intel TDX is supported
2. **Maintain an event log**: Record all significant operations including TLS certificate renewals with certificate hashes
3. **Provide a quote endpoint**: Expose an HTTP POST endpoint (default: `/tdx_quote`) that:
   - Accepts JSON with `report_data_hex` field (64 bytes hex-encoded)
   - Returns a JSON response containing:
     - `quote`: TDX quote (hex-encoded) signed by TEE hardware
     - `event_log`: JSON array of events used to compute RTMRs
4. **Generate TLS certificates inside the TEE**: Private keys must never leave the TEE
5. **Update RTMRs on certificate renewal**: Append certificate hash events to the log, updating RTMR3

See the [server implementation reference](https://github.com/concrete-security/umbra/tree/main/cvm) for a complete example.

## Examples

You can set `DEBUG_RATLS=true` to see debug logs.

### DstackTDXVerifier

`DstackTDXVerifier` is used to verify that a server is running inside a TDX TEE managed by [Dstack](https://github.com/Dstack-TEE/dstack). It verifies the TDX quote and optionally checks that the TEE is running a specific docker-compose configuration.

```python
from secureai import httpx
from secureai.verifiers import DstackTDXVerifier

# Option 1: Verify TEE with runtime verification disabled (NOT RECOMMENDED)
# Only verifies that the server is running in a TEE, but not what application it runs
verifier = DstackTDXVerifier(disable_runtime_verification=True)

# Option 2: Verify TEE is running a specific docker-compose (RECOMMENDED)
# This ensures the TEE is running exactly the application you expect
with open("docker-compose.yml", "r") as f:
    docker_compose_content = f.read()

verifier = DstackTDXVerifier(docker_compose_file=docker_compose_content)

# Option 3: Provide a full app_compose configuration
app_compose = {
    "docker_compose_file": docker_compose_content,
    "manifest_version": 2,
    # ... other configuration options
}
verifier = DstackTDXVerifier(app_compose=app_compose)

# Use with httpx client
with httpx.Client(
    ratls_verifier_per_hostname={
        "your-tee-server.com": verifier
    }
) as client:
    response = client.get("https://your-tee-server.com/api")
```


### OpenAI Client with RATLS

```python
from secureai import OpenAI
from secureai.verifiers import DstackTDXVerifier

with open("you-docker-compose.yml", "r") as f:
    docker_compose_content = f.read()

verifier = DstackTDXVerifier(docker_compose_file=docker_compose_content)

client = OpenAI(ratls_verifier_per_hostname={"vllm.concrete-security.com": verifier})
```


### HTTP Client with RATLS

```python
from secureai import httpx
from secureai.verifiers import DstackTDXVerifier

with open("you-docker-compose.yml", "r") as f:
    docker_compose_content = f.read()

verifier = DstackTDXVerifier(docker_compose_file=docker_compose_content)

with httpx.Client(ratls_verifier_per_hostname={"vllm.concrete-security.com": verifier}) as client:
    # No RATLS as not in the list
    response = client.get("https://httpbin.org/get")
    print(f"Response status: {response.status_code}")
    
    # Uses RATLS
    response = client.get("https://vllm.concrete-security.com/health")
    print(f"Response status: {response.status_code}")
    
    # This shouldn't trigger another verification as the connection is still open
    response = client.get("https://vllm.concrete-security.com/v1/models")
    print(f"Response status: {response.status_code}")
```

## Development

SecureAI uses [uv](https://docs.astral.sh/uv/getting-started/installation/) for dependency management and building. There is also a Makefile with basic recipes.

### Running Tests

```bash
# Run all tests
uv run pytest
```

or

```bash
make test # or test-coverage
```

### Code Quality

```bash
# Format code
uv run ruff format

# Lint code
uv run ruff check

# For import order specifically
uv run ruff check --select I
```

or

```bash
make qa-all # or qa-all-fix
```

### Build

```bash
# Build a wheel from source
uv build
```

## Hardware Support

Only TDX is supported at the moment.