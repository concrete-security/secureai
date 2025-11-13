import os

os.environ["DEBUG_RATLS"] = "true"

from secureai import httpx


if __name__ == "__main__":
    with httpx.Client(ratls_server_hostnames=["httpbin.org", "google.com"]) as client:
        response = client.get("https://httpbin.org/get")
        print(f"Response status: {response.status_code}")

        response = client.get("https://google.com/get")
        print(f"Response status: {response.status_code}")

    with httpx.Client(ratls_server_hostnames=["httpbin.org", "google.com"]) as client:
        response = client.get("https://httpbin.org/get")
        print(f"Response status: {response.status_code}")

        response = client.get("https://google.com/get")
        print(f"Response status: {response.status_code}")
