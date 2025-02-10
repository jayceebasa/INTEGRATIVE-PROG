from django.db import IntegrityError
from django.forms import ValidationError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate, get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth.password_validation import validate_password
from .permissions import IsPostAuthor
from .models import User, Post, Comment, Likes
from .serializers import UserSerializer, PostSerializer, CommentSerializer, LikesSerializer
from .singletons.config_manager import ConfigManager
from .singletons.logger_singleton import LoggerSingleton
from .factories.post_factory import PostFactory
from rest_framework.pagination import PageNumberPagination
from .pagination import CommentPagination

config = ConfigManager()
config.set_setting("DEFAULT_PAGE_SIZE", 50)

logger = LoggerSingleton().get_logger()
logger.info("API initialized successfully.")

@csrf_exempt
@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
def create_superuser(request):
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
    data = request.data
    serializer = UserSerializer(data=data)
    if serializer.is_valid():
        password = data.get('password')
        try:
            validate_password(password)
            user = serializer.save()
            user.set_password(password)
            user.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response({'password': e.messages}, status=status.HTTP_400_BAD_REQUEST)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
def login(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)
    
    if user is not None:
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key}, status=status.HTTP_200_OK)
    else:
        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

@csrf_exempt
@api_view(['POST'])
def logout(request):
    request.user.auth_token.delete()
    return Response(status=status.HTTP_200_OK)


class ProtectedView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "Authenticated!"})

class UserListCreate(APIView):
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
                author=request.user
            )
            return Response({'message': 'Post created successfully!', 'post_id': post.id}, status=status.HTTP_201_CREATED)
        except ValueError as e:
            logger.error(f"Error creating post: {e}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
          
    def get(self, request):
            if request.user.is_admin:
                posts = Post.objects.all()
            else:
                posts = Post.objects.filter(author=request.user)
            
            post_data = []
            for post in posts:
                serializer = PostSerializer(post)
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
      
    def put(self, request):
      try:
        post = Post.objects.get(id=request.data['id'])
      except Post.DoesNotExist:
        return Response({"error": "Post not found."}, status=status.HTTP_404_NOT_FOUND)
      
      if request.user != post.author and not request.user.is_admin:
        return Response({"error": "You do not have permission to edit this post."}, status=status.HTTP_403_FORBIDDEN)
      
      serializer = PostSerializer(post, data=request.data, partial=True)
      if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
      return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
      
    def delete(self, request):
      try:
        post = Post.objects.get(id=request.data['id'])
      except Post.DoesNotExist:
        return Response({"error": "Post not found."}, status=status.HTTP_404_NOT_FOUND)
      
      if request.user != post.author and not request.user.is_admin:
        return Response({"error": "You do not have permission to delete this post."}, status=status.HTTP_403_FORBIDDEN)
      
      post.delete()
      return Response(status=status.HTTP_204_NO_CONTENT)

class CreateCommentView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        data = request.data.copy()
        data['post'] = id
        serializer = CommentSerializer(data=data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, id):
      comments = Comment.objects.filter(post_id=id).order_by('-created_at') if not request.user.is_admin else Comment.objects.all().order_by('-created_at')
      paginator = CommentPagination()
      paginated_comments = paginator.paginate_queryset(comments, request)
      serializer = CommentSerializer(paginated_comments, many=True)
      return paginator.get_paginated_response(serializer.data)
  
    def put(self, request, id):
        try:
            comment = Comment.objects.get(id=request.data['id'], post_id=id)
        except Comment.DoesNotExist:
            return Response({"error": "Comment not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user != comment.author and not request.user.is_admin:
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

        if request.user != comment.author and not request.user.is_admin:
            return Response({"error": "You do not have permission to delete this comment."}, status=status.HTTP_403_FORBIDDEN)
    
        comment.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


import logging

logger = logging.getLogger(__name__)

class LikesView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        logger.debug(f"Request data: {request.data}")
        if not request.data:
            return Response({"error": "Request data is missing or not properly formatted."}, status=status.HTTP_400_BAD_REQUEST)
        
        data = request.data.copy()
        data['post'] = id
        serializer = LikesSerializer(data=data, context={'request': request})
        if serializer.is_valid():
            try:
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except IntegrityError:
                return Response({"error": "You have already liked this post."}, status=status.HTTP_400_BAD_REQUEST)
        logger.debug(f"Serializer errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
      
    def delete(self, request, id):
        try:
            like = Likes.objects.get(post_id=id, user=request.user)
        except Likes.DoesNotExist:
            return Response({"error": "Like not found."}, status=status.HTTP_404_NOT_FOUND)
        
        like.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
class PostDetailView(APIView):
    permission_classes = [IsAuthenticated, IsPostAuthor]

    def get(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
        except Post.DoesNotExist:
            return Response({"error": "Post not found."}, status=status.HTTP_404_NOT_FOUND)
        
        self.check_object_permissions(request, post)
        return Response({"content": post.content})