from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.cache import cache
from .models import Post

@receiver(post_save, sender=Post)
def invalidate_post_cache(sender, instance, created, **kwargs):
    """Invalidate cache when a post is created or updated"""
    # Clear all homepage caches when posts change
    keys = [k for k in cache._cache.keys() if k.startswith('homepage_')]
    for key in keys:
        cache.delete(key)