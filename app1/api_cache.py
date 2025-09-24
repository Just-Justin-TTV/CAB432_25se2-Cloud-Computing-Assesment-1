from django.conf import settings
import requests
from pymemcache.client import base

# Connect to Memcached
cache = base.Client((settings.MEMCACHED_HOST, settings.MEMCACHED_PORT))

def get_api_tags():
    cached = cache.get(b'api_tags')  # always use bytes key
    if cached:
        tags = eval(cached.decode('utf-8'))  # decode from bytes to str, then eval
    else:
        url = f"{settings.OLLAMA_HOST}/api/tags"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            tags = response.json()
            cache.set(b'api_tags', str(tags).encode('utf-8'), expire=300)  # cache 5 mins
        except requests.RequestException as e:
            print(f"[ERROR] Failed to fetch API tags: {e}")
            tags = []
    return tags

# Don't call at module load; call from a view or management command instead
def test_api_tags():
    tags = get_api_tags()
    print("[INFO] Ollama API tags:", tags)
    return tags
