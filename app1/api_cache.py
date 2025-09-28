from django.core.cache import cache 
from django.conf import settings
import requests


def get_api_tags():
    """
    Fetch available Ollama API tags, using Memcached (AWS ElastiCache) for caching.
    """
    cache_key = "api_tags"
    now = datetime.datetime.now().isoformat()

    # Try fetching from cache first
    tags = cache.get(cache_key)
    if tags:
        logger.debug(f"[{now}] [CACHE HIT] Returning cached tags: {tags}")
        return tags

    # Cache miss: fetch from Ollama API
    logger.debug(f"[{now}] [CACHE MISS] Fetching from Ollama...")
    try:
        response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=10)
        response.raise_for_status()
        tags = response.json()

        # Store in cache for 5 minutes
        cache.set(cache_key, tags, timeout=300)
        logger.debug(f"[{now}] [CACHE SET] Cached tags for 5 min")
        return tags

    except requests.RequestException as e:
        logger.error(f"[{now}] [ERROR] Failed to fetch tags from Ollama: {e}")
        return {"models": []}


def test_api_tags():
    """
    Return the currently available API tags.
    """
    tags = get_api_tags()
    return tags
