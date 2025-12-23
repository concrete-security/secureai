import os

os.environ["DEBUG_RATLS"] = "true"

from secureai import httpx
from secureai.verifiers import DstackTDXVerifier

if __name__ == "__main__":
    with open("example_docker_compose.yml", "r") as f:
        docker_compose_file = f.read()

    # Bootchain measurements depend on hardware configuration (CPU count, memory size, etc.)
    # These values must be computed for your specific deployment
    # See docs/dstack-bootchain-verification.md for instructions
    expected_bootchain = {
        "mrtd": "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217",
        "rtmr0": "24c15e08c07aa01c531cbd7e8ba28f8cb62e78f6171bf6a8e0800714a65dd5efd3a06bf0cf5433c02bbfac839434b418",
        "rtmr1": "6e1afb7464ed0b941e8f5bf5b725cf1df9425e8105e3348dca52502f27c453f3018a28b90749cf05199d5a17820101a7",
        "rtmr2": "89e73cedf48f976ffebe8ac1129790ff59a0f52d54d969cb73455b1a79793f1dc16edc3b1fccc0fd65ea5905774bbd57",
    }
    os_image_hash = "86b181377635db21c415f9ece8cc8505f7d4936ad3be7043969005a8c4690c1a"

    with httpx.Client(
        ratls_verifier_per_hostname={
            "vllm.concrete-security.com": DstackTDXVerifier(
                # Makes sure the TEE is running this docker-compose
                docker_compose_file=docker_compose_file,
                # Verify full bootchain (MRTD, RTMR0-2) and OS image hash
                expected_bootchain=expected_bootchain,
                os_image_hash=os_image_hash,
            )
        }
    ) as client:
        # Don't use RATLS as not configured
        response = client.get("https://httpbin.org/get")
        print(f"Response status: {response.status_code}")

        response = client.get("https://vllm.concrete-security.com/health")
        print(f"Response status: {response.status_code}")

        response = client.get("https://vllm.concrete-security.com/v1/models")
        print(f"Response status: {response.status_code}")
