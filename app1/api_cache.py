from django.core.cache import cache
from django.conf import settings
import requests
import logging

logger = logging.getLogger(__name__)

def get_api_tags():
    tags = cache.get("api_tags")  # Django handles serialization
    if tags:
        return tags

    url = f"{settings.OLLAMA_HOST}/api/tags"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        tags = response.json()
        cache.set("api_tags", tags, timeout=300)  # cache for 5 mins
        return tags
    except requests.RequestException as e:
        logger.error(f"[ERROR] Failed to fetch API tags: {e}")
        return []

def test_api_tags():
    tags = get_api_tags()
    logger.info(f"[INFO] Ollama API tags: {tags}")
    return tags
