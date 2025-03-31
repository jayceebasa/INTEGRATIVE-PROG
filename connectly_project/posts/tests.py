import time
from django.test import TestCase, Client
from django.urls import reverse
from django.core.cache import cache
from .models import User, Post, Role

class CacheTestCase(TestCase):
    def setUp(self):
        # Clear cache before each test
        cache.clear()
        
        # Create necessary roles first
        # Create both admin and regular user roles to ensure all needed roles exist
        self.admin_role = Role.objects.create(id=1, name='Admin', descrpiton='Administrator role')
        self.user_role = Role.objects.create(id=2, name='User', descrpiton='Regular user role')
        
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword'
        )
        
        # Manually assign the role
        self.user.roles.add(self.user_role)
        
        # Create test posts
        for i in range(10):
            Post.objects.create(
                title=f'Test Post {i}',
                content=f'Content for test post {i}',
                post_type='text',
                author=self.user,
                is_private=False
            )
        
        self.client = Client()
        self.client.login(username='testuser', password='testpassword')
    
    def test_homepage_cache(self):
        # First request should be a cache miss
        response1 = self.client.get(reverse('homepage'))
        self.assertEqual(response1.status_code, 200)
        
        # Second request should be a cache hit
        response2 = self.client.get(reverse('homepage'))
        self.assertEqual(response2.status_code, 200)
        
        # Create a new post to invalidate cache
        Post.objects.create(
            title='New Post',
            content='New content',
            post_type='text',
            author=self.user,
            is_private=False
        )
        
        # Cache should be invalidated
        response3 = self.client.get(reverse('homepage'))
        self.assertEqual(response3.status_code, 200)
      
    def test_cache_performance(self):
      # Clear any existing cache
      cache.clear()
      
      # Run multiple requests to get a more reliable average
      num_requests = 5
      
      # Measure uncached requests
      uncached_times = []
      for i in range(num_requests):
          start = time.time()
          response = self.client.get(reverse('homepage'))
          end = time.time()
          # Only count the first one as uncached, the rest might use cache
          if i == 0:
              uncached_times.append(end - start)
          # Clear cache between requests for accurate uncached timing
          cache.clear()
      
      # Measure cached requests
      # First request populates cache
      self.client.get(reverse('homepage'))
      
      # Now measure cached performance
      cached_times = []
      for _ in range(num_requests):
          start = time.time()
          response = self.client.get(reverse('homepage'))
          end = time.time()
          cached_times.append(end - start)
      
      # Calculate averages
      avg_uncached = uncached_times[0]  # Just use the first uncached request
      avg_cached = sum(cached_times) / len(cached_times)
      
      # Calculate performance improvement percentage
      improvement = ((avg_uncached - avg_cached) / avg_uncached) * 100
      
      # Print performance information
      print(f"\nCache Performance Results:")
      print(f"Uncached request time: {avg_uncached:.6f} seconds")
      print(f"Average cached request time: {avg_cached:.6f} seconds")
      print(f"Performance improvement: {improvement:.2f}%")
      
      # Assert that cached is significantly faster (at least 20% faster)
      self.assertGreater(improvement, 20, 
                        f"Caching should improve performance by at least 20%, but only improved by {improvement:.2f}%")
    def test_cache_invalidation_performance(self):
      """Test performance after cache invalidation"""
      # First request - uncached
      self.client.get(reverse('homepage'))
      
      # Create a new post to invalidate cache
      Post.objects.create(title='New Post', content='Content', post_type='text', 
                          author=self.user, is_private=False)
      
      # Measure time for a request after cache invalidation
      start = time.time()
      self.client.get(reverse('homepage'))
      invalidation_time = time.time() - start
      
      # This time should be similar to an uncached request
      # You could compare it to a baseline measurement
      print(f"Time after cache invalidation: {invalidation_time:.6f} seconds")