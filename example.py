import os

os.environ["DEBUG_RATLS"] = "true"

from secureai import httpx

if __name__ == "__main__":
    with httpx.Client(ratls_server_hostnames=["vllm.concrete-security.com"]) as client:
        response = client.get("https://httpbin.org/get")
        print(f"Response status: {response.status_code}")

        response = client.get("https://vllm.concrete-security.com/health")
        print(f"Response status: {response.status_code}")

        response = client.get("https://vllm.concrete-security.com/v1/models")
        print(f"Response status: {response.status_code}")
