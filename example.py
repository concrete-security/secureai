import os

os.environ["DEBUG_RATLS"] = "true"

from secureai import httpx
from secureai.verifiers import DstackTDXVerifier

if __name__ == "__main__":
    with open("example_docker_compose.yml", "r") as f:
        docker_compose_file = f.read()

    with httpx.Client(
        ratls_verifier_per_hostname={
            "vllm.concrete-security.com": DstackTDXVerifier(
                # Makes sure the TEE is running this docker-compose
                docker_compose_file=docker_compose_file
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
