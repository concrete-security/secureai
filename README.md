# SecureAI

## Examples

You can set `DEBUG_RATLS=true` to see debug logs.

### OpenAI Client with RATLS

```python
from secureai import OpenAI


client = OpenAI(ratls_server_hostnames=["api.openai.com"])
```


### HTTP Client with RATLS

```python
from secureai import httpx


with httpx.Client(ratls_server_hostnames=["vllm.concrete-security.com"]) as client:
    response = client.get("https://httpbin.org/get")
    print(f"Response status: {response.status_code}")

    response = client.get("https://vllm.concrete-security.com/health")
    print(f"Response status: {response.status_code}")
```