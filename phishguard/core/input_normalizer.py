import re


def normalize_url(value):
    """
    Normalize raw input into a clean URL.

    Supports:
    - Plain URLs
    - Markdown links
    - Leading/trailing whitespace
    """

    if not isinstance(value, str):
        raise TypeError("URL must be a string")

    value = value.strip()

    # Extract URL from Markdown:
    # [https://example.com](https://example.com)
    markdown_match = re.search(
        r"\]\((https?://[^)]+)\)",
        value
    )

    if markdown_match:
        return markdown_match.group(1)

    # If plain URL, return unchanged
    return value
