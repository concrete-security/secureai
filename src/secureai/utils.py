import json
import logging
import ssl
from http.client import HTTPResponse, HTTPSConnection


def _get_default_logger() -> logging.Logger:
    return logging.getLogger("ratls")


def post_json_from_tls_conn(
    ssl_sock: ssl.SSLSocket,
    host: str,
    json_data: dict,
    endpoint: str,
) -> HTTPResponse:
    """Post JSON data over an established TLS connection.

    Args:
        ssl_sock: An established SSL socket connected to the server.
        host: The server hostname.
        endpoint: The HTTP endpoint to post the request to.
        json_data: The JSON data to send to the server.

    Returns:
        HTTPResponse: The server's HTTP response.
    """
    # Create a connection object and attach our socket to it
    conn = HTTPSConnection(host)
    conn.sock = ssl_sock
    # Make the POST request
    conn.request(
        "POST",
        endpoint,
        body=json.dumps(json_data),
        headers={"Content-Type": "application/json"},
    )
    # Never close the socket, as it's externally managed
    # the socket should still be usable after this function returns
    return conn.getresponse()
