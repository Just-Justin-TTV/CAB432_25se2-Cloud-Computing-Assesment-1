from django.core.cache import cache 
from django.conf import settings
import requests


def get_api_tags():
    """
    Fetch available API tags from Ollama.
    Uses Django cache to avoid repeated requests.
    """
    tags = cache.get("api_tags")
    if tags:
        return tags

    url = f"{settings.OLLAMA_HOST}/api/tags"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        tags = response.json()
        cache.set("api_tags", tags, timeout=300)  # cache for 5 mins
        return tags
    except requests.RequestException:
        return []


def test_api_tags():
    """
    Return the currently available API tags.
    """
    tags = get_api_tags()
    return tags
