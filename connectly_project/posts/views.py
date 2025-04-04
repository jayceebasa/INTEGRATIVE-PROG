from django.forms import ValidationError
from django.http import JsonResponse
from django.test import TestCase, Client
from django.urls import reverse
from django.shortcuts import redirect, render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate, get_user_model, logout as auth_logout, login as auth_login
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.views.decorators.cache import cache_page
from django.core.cache import cache
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from .permissions import IsPostAuthor
from .models import User, Post, Comment, Likes
from .serializers import UserSerializer, PostSerializer, CommentSerializer
from .singletons.config_manager import ConfigManager
from .singletons.logger_singleton import LoggerSingleton
from .factories.post_factory import PostFactory
from .pagination import CommentPagination

# Initialize configuration and logger
config = ConfigManager()
config.set_setting("DEFAULT_PAGE_SIZE", 50)

logger = LoggerSingleton().get_logger()
logger.info("API initialized successfully.")

@ensure_csrf_cookie
def check_auth(request):
    """Check if the user is authenticated and return appropriate response"""
    if request.user.is_authenticated:
        return JsonResponse({
            'isAuthenticated': True,
            'username': request.user.username
        })
    return JsonResponse({'isAuthenticated': False})

def login_page(request):
    """Render the login page"""
    return render(request, 'login.html')

@login_required
def homepage(request):
    """Render the homepage with paginated posts"""
    user_id = request.user.id
    page = request.GET.get('page', 1)
    cache_key = f'homepage_{user_id}_{page}'
    
    # Try to get data from cache
    cached_response = cache.get(cache_key)
    if cached_response:
        return cached_response
    
    # If not in cache, generate the response
    if request.user.is_admin_user():
        posts_list = Post.objects.all().order_by('-created_at')
    else:
        posts_list = Post.objects.filter(author=request.user) | Post.objects.filter(is_private=False)
        posts_list = posts_list.distinct().order_by('-created_at')

    for post in posts_list:
        post.is_liked_by_user = Likes.objects.filter(post=post, user=request.user).exists()

    # Pagination
    paginator = Paginator(posts_list, 5)  # Show 5 posts per page

    try:
        posts = paginator.page(page)
    except PageNotAnInteger:
        posts = paginator.page(1)
    except EmptyPage:
        posts = paginator.page(paginator.num_pages)

    response = render(request, 'homepage.html', {'posts': posts})
    
    # Cache the response for 10 minutes (600 seconds)
    cache.set(cache_key, response, 600)
    
    return response

def signup(request):
    """Render the signup page"""
    return render(request, 'signup.html')

def logout_view(request):
    """Log out the user and redirect to the home page"""
    auth_logout(request)
    return redirect('/')

@csrf_exempt
@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
def create_superuser(request):
    """Create a new superuser"""
    data = request.data
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return Response({"error": "Username, email, and password are required."}, status=status.HTTP_400_BAD_REQUEST)

    User = get_user_model()
    try:
        user = User.objects.create_superuser(username=username, email=email, password=password)
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    except Exception as e:
        logger.error(f"Error creating superuser: {e}")
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
def create_user(request):
    """Create a new user"""
    data = request.data
    serializer = UserSerializer(data=data)
    if serializer.is_valid():
        password = data.get('password')
        try:
            validate_password(password)
            user = serializer.save()
            user.set_password(password)
            user.save()
            
            user.roles.add(2)
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response({'password': e.messages}, status=status.HTTP_400_BAD_REQUEST)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
def login(request):
    """Authenticate and log in the user"""
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)
    
    if user is not None:
        auth_login(request, user)  # Create the session
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user': {
                'username': user.username,
                'email': user.email
            }
        }, status=status.HTTP_200_OK)
    else:
        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

@csrf_exempt
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def logout(request):
    """Log out the user and delete the token"""
    try:
        request.user.auth_token.delete()
    except (AttributeError, Token.DoesNotExist):
        pass
    auth_logout(request)
    response = Response({"message": "Logged out successfully. Please remove the token from local storage."}, status=status.HTTP_200_OK)
    response.delete_cookie('sessionid')
    response.delete_cookie('csrftoken')
    response['Clear-Site-Data'] = '"storage"'
    return response

class ProtectedView(APIView):
    """A protected view that requires authentication"""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "Authenticated!"})

class UserListCreate(APIView):
    """View to list and create users"""
    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)
      
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        try:
            user = User.objects.get(id=request.data['id'])
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request):
        try:
            user = User.objects.get(id=request.data['id'])
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class CreatePostView(APIView):
    """View to create, retrieve, update, and delete posts"""
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
      data = request.data
      if not data.get('content') or not data.get('title'):
          return Response({'error': 'Title and content are required fields.'}, status=status.HTTP_400_BAD_REQUEST)
      try:
          post = PostFactory.create_post(
              post_type=data['post_type'],
              title=data['title'],
              content=data.get('content', ''),
              metadata=data.get('metadata', {}),
              author=request.user,
              is_private=data.get('is_private', False)
          )
          # Replace delete_pattern with our custom function
          delete_cache_by_pattern("homepage_*")
          return Response({'message': 'Post created successfully!', 'post_id': post.id}, status=status.HTTP_201_CREATED)
      except ValueError as e:
          logger.error(f"Error creating post: {e}")
          return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
          
    def get(self, request):
      # Get the queryset once based on user permissions
      if request.user.is_admin_user():
          # Admin can see all posts
          posts = Post.objects.all().select_related('author')
      else:
          # Regular users can only see their own posts and public posts
          posts = (Post.objects.filter(author=request.user) | 
                  Post.objects.filter(is_private=False)).select_related('author')
      
      # Ensure no duplicate posts are returned
      posts = posts.distinct()
      
      # Now we can reuse this queryset without additional DB hits
      post_data = []
      for post in posts:
          serializer = PostSerializer(post)
          # These queries are separate from the posts queryset
          comments_count = Comment.objects.filter(post=post).count()
          likes_count = Likes.objects.filter(post=post).count()
          comments = Comment.objects.filter(post=post)

          paginator = CommentPagination()
          paginated_comments = paginator.paginate_queryset(comments, request)
          comments_serializer = CommentSerializer(paginated_comments, many=True)

          post_info = serializer.data
          post_info['comments_count'] = comments_count
          post_info['likes_count'] = likes_count
          post_info['comments'] = paginator.get_paginated_response(comments_serializer.data).data
          post_data.append(post_info)

      return Response(post_data)
      
    def put(self, request, id):
        try:
            post = Post.objects.get(id=id)
        except Post.DoesNotExist:
            return Response({'error': 'Post not found.'}, status=status.HTTP_404_NOT_FOUND)

        if request.user != post.author and not request.user.is_admin_user():
            return Response({'error': 'You do not have permission to edit this post.'}, status=status.HTTP_403_FORBIDDEN)

        is_private = request.data.get('is_private', None)
        if is_private is not None:
            post.is_private = is_private
            post.save()

        return Response({'message': 'Post updated successfully.'}, status=status.HTTP_200_OK)
      
    def delete(self, request, id):
        try:
            post = Post.objects.get(id=id)
        except Post.DoesNotExist:
            return Response({"error": "Post not found."}, status=status.HTTP_404_NOT_FOUND)
        
        if request.user != post.author and not request.user.is_admin_user():
            return Response({"error": "You do not have permission to delete this post."}, status=status.HTTP_403_FORBIDDEN)

        post.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class CreateCommentView(APIView):
    """View to create, retrieve, update, and delete comments"""
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        data = request.data.copy()
        data['post'] = id
        serializer = CommentSerializer(data=data, context={'request': request})
        if serializer.is_valid():
            comment = serializer.save()
            # Enhance response with additional data needed by frontend
            response_data = serializer.data
            response_data['comment_id'] = comment.id  # Explicitly include the comment ID
            response_data['author_username'] = request.user.username
            # Get profile picture URL if available
            if hasattr(request.user, 'profile_picture') and request.user.profile_picture:
                response_data['author_profile_picture_url'] = request.user.profile_picture.url
            else:
                response_data['author_profile_picture_url'] = '/media/profile_pictures/default.png'
            
            # Include updated comments count
            comments_count = Comment.objects.filter(post_id=id).count()
            response_data['comments_count'] = comments_count
            
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, id):
        comments = Comment.objects.filter(post_id=id).order_by('-created_at') if not request.user.is_admin_user() else Comment.objects.all().order_by('-created_at')
        paginator = CommentPagination()
        paginated_comments = paginator.paginate_queryset(comments, request)
        serializer = CommentSerializer(paginated_comments, many=True)
        return paginator.get_paginated_response(serializer.data)
  
    def put(self, request, id):
        try:
            comment = Comment.objects.get(id=request.data['id'], post_id=id)
        except Comment.DoesNotExist:
            return Response({"error": "Comment not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user != comment.author and not request.user.is_admin_user():
            return Response({"error": "You do not have permission to edit this comment."}, status=status.HTTP_403_FORBIDDEN)

        serializer = CommentSerializer(comment, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, id):
        try:
            comment = Comment.objects.get(id=request.data['id'], post_id=id)
        except Comment.DoesNotExist:
            return Response({"error": "Comment not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user != comment.author and not request.user.is_admin_user():
            return Response({"error": "You do not have permission to delete this comment."}, status=status.HTTP_403_FORBIDDEN)
    
        comment.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

import logging

logger = logging.getLogger(__name__)

class LikesView(APIView):
    """View to like and unlike posts"""
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        try:
            post = Post.objects.get(id=id)
            user = request.user
            
            # Check if user already liked this post
            like_exists = Likes.objects.filter(post=post, user=user).exists()
            
            # Toggle like status
            if like_exists:
                # Unlike the post
                Likes.objects.filter(post=post, user=user).delete()
                liked = False
            else:
                # Like the post
                Likes.objects.create(post=post, user=user)
                liked = True
                
            # Return updated like count and status
            likes_count = post.likes.count()
            return Response({
                'liked': liked,
                'likes_count': likes_count
            }, status=status.HTTP_200_OK)
        
        except Post.DoesNotExist:
            return Response({"error": "Post not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
      
    def delete(self, request, id):
        try:
            like = Likes.objects.get(post_id=id, user=request.user)
        except Likes.DoesNotExist:
            return Response({"error": "Like not found."}, status=status.HTTP_404_NOT_FOUND)
        
        like.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class PostDetailView(APIView):
    """View to retrieve, update, and delete post details"""
    permission_classes = [IsAuthenticated, IsPostAuthor]

    def get(self, request, pk):  # Change 'id' to 'pk'
        try:
            post = Post.objects.get(pk=pk)
        except Post.DoesNotExist:
            return Response({"error": "Post not found."}, status=status.HTTP_404_NOT_FOUND)
        
        self.check_object_permissions(request, post)
        return Response({"content": post.content})

    def put(self, request, pk):  # Change 'id' to 'pk'
        """Update the privacy of a post"""
        try:
            post = Post.objects.get(pk=pk)
        except Post.DoesNotExist:
            return Response({"error": "Post not found."}, status=status.HTTP_404_NOT_FOUND)

        # Check if the user is the author or an admin
        if request.user != post.author and not request.user.is_admin_user():
            return Response({"error": "You do not have permission to edit this post."}, status=status.HTTP_403_FORBIDDEN)

        # Update the `is_private` field
        is_private = request.data.get('is_private', None)
        if is_private is not None:
            post.is_private = is_private
            post.save()
            return Response({"message": "Post privacy updated successfully."}, status=status.HTTP_200_OK)

        return Response({"error": "Invalid data provided."}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):  # Change 'id' to 'pk'
        try:
            post = Post.objects.get(pk=pk)
        except Post.DoesNotExist:
            return Response({"error": "Post not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user != post.author and not request.user.is_admin_user():
            return Response({"error": "You do not have permission to delete this post."}, status=status.HTTP_403_FORBIDDEN)

        post.delete()
        return Response({"message": "Post deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
      
def cache_stats(request):
    """View to check cache statistics"""
    stats = {
        'hits': cache._cache.get('hits', 0),
        'misses': cache._cache.get('misses', 0),
        'calls': cache._cache.get('calls', 0),
    }
    return JsonResponse(stats)
  

class CacheTestCase(TestCase):
    def setUp(self):
        # Clear cache before each test
        cache.clear()
        
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword'
        )
        
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
        
def delete_cache_by_pattern(pattern):
    """Delete all cache keys that match the given pattern"""
    import re
    pattern_regex = re.compile(pattern.replace('*', '.*'))
    keys_to_delete = [k for k in cache._cache.keys() if pattern_regex.match(k)]
    for key in keys_to_delete:
        cache.delete(key)