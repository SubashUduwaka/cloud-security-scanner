"""
Simple in-memory caching for Aegis Scanner
"""
import time
from functools import wraps
from typing import Any, Optional

class SimpleCache:
    def __init__(self, default_timeout=300):
        self.cache = {}
        self.default_timeout = default_timeout
    
    def get(self, key: str) -> Optional[Any]:
        if key in self.cache:
            data, expires_at = self.cache[key]
            if time.time() < expires_at:
                return data
            else:
                del self.cache[key]
        return None
    
    def set(self, key: str, value: Any, timeout: Optional[int] = None) -> None:
        timeout = timeout or self.default_timeout
        expires_at = time.time() + timeout
        self.cache[key] = (value, expires_at)
    
    def delete(self, key: str) -> None:
        self.cache.pop(key, None)
    
    def clear(self) -> None:
        self.cache.clear()


cache = SimpleCache()

def cached(timeout=300, key_func=None):
    """Decorator to cache function results"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{f.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"
            
            
            result = cache.get(cache_key)
            if result is not None:
                return result
            
            
            result = f(*args, **kwargs)
            cache.set(cache_key, result, timeout)
            return result
        
        return wrapper
    return decorator
