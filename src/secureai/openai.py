"""
OpenAI API client with RATLS verification.

You can use this client just like the standard `openai.OpenAI` client.
"""

from typing import List

import openai

from .httpx import Client


class OpenAI(openai.OpenAI):
    """OpenAI client with RATLS verification. See `openai.OpenAI` for more details.

    You can use this client just like the standard `openai.OpenAI` client.

    You should never set the `http_client` keyword argument as we use a custom client.
    """

    def __init__(self, *args, ratls_server_hostnames: List[str] = [], **kwargs):
        if kwargs.get("http_client") is not None:
            raise ValueError(
                "setting http_client argument isn't possible as we use a custom client with RATLS"
            )
        kwargs["http_client"] = Client(ratls_server_hostnames=ratls_server_hostnames)
        super().__init__(*args, **kwargs)
