#!/var/ossec/framework/python/bin/python3
"""Forward a Wazuh JSON alert to the n8n SOAR webhook."""

import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main():
    if len(sys.argv) < 4:
        raise SystemExit("Expected alert file, API key, and webhook URL")

    with open(sys.argv[1], encoding="utf-8") as file:
        payload = {"_source": json.load(file)}

    webhook_url = os.getenv("N8N_WEBHOOK_URL", sys.argv[3])
    request = Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        # This workflow waits for ATT&CK mapping and Gemini analysis before it
        # responds. Keep the timeout configurable and long enough for that path.
        timeout = float(os.getenv("N8N_WEBHOOK_TIMEOUT", "120"))
        with urlopen(request, timeout=timeout) as response:
            if not 200 <= response.status < 300:
                raise SystemExit(f"n8n returned HTTP {response.status}")
            response_body = response.read()
            if os.getenv("N8N_WEBHOOK_DEBUG") == "1":
                print(response_body.decode("utf-8", errors="replace"))
    except (HTTPError, URLError, OSError) as error:
        raise SystemExit(f"Could not deliver alert to n8n: {error}") from error


if __name__ == "__main__":
    main()
