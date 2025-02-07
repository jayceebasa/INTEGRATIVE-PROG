#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#
from django.forms import ValidationError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate, get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.password_validation import validate_password
from .permissions import IsPostAuthor
from .models import User, Post, Comment
from .serializers import UserSerializer, PostSerializer, CommentSerializer
from .singletons.config_manager import ConfigManager
from .singletons.logger_singleton import LoggerSingleton
from .factories.post_factory import PostFactory

config1 = ConfigManager()
config2 = ConfigManager()

assert config1 is config2  # Both instances should be the same
config1.set_setting("DEFAULT_PAGE_SIZE", 50)
assert config2.get_setting("DEFAULT_PAGE_SIZE") == 50

logger = LoggerSingleton().get_logger()
logger.info("API initialized successfully.")


class CreatePostView(APIView):
    def post(self, request):
        data = request.data
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
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


#create ng superuser
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
            validate_password(password)  # Validate the password
            user = serializer.save()
            user.set_password(password)  # Set the hashed password
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

class PostListCreate(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated, IsPostAuthor]

    def get(self, request):
        print("GET request received")
        print(f"Authenticated user: {request.user}")
        if request.user.is_authenticated:
            print("User is authenticated")
        else:
            print("User is not authenticated")
        
        posts = Post.objects.filter(author=request.user)
        print(f"Posts found: {posts.count()}")
        for post in posts:
            print(f"Post: {post.title} by {post.author.username}")
        
        serializer = PostSerializer(posts, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(author=request.user)  # Set the author to the authenticated user
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        try:
            post = Post.objects.get(id=request.data['id'])
        except Post.DoesNotExist:
            return Response({"error": "Post not found."}, status=status.HTTP_404_NOT_FOUND)

        # Check if the user is the author or an admin
        if request.user != post.author and not request.user.is_admin:
            return Response({"error": "You do not have permission to edit this post."}, status=status.HTTP_403_FORBIDDEN)

        serializer = PostSerializer(post, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        try:
            post = Post.objects.get(id=request.data['id'])
        except Post.DoesNotExist:
            return Response({"error": "Post not found."}, status=status.HTTP_404_NOT_FOUND)

        # Check if the user is the author or an admin
        if request.user != post.author and not request.user.is_admin:
            return Response({"error": "You do not have permission to delete this post."}, status=status.HTTP_403_FORBIDDEN)

        post.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class CommentListCreate(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        comments = Comment.objects.all()
        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = CommentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        try:
            comment = Comment.objects.get(id=request.data['id'])
        except Comment.DoesNotExist:
            return Response({"error": "Comment not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user != comment.author and not request.user.is_admin:
            return Response({"error": "You do not have permission to edit this comment."}, status=status.HTTP_403_FORBIDDEN)

        serializer = CommentSerializer(comment, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        try:
            comment = Comment.objects.get(id=request.data['id'])
        except Comment.DoesNotExist:
            return Response({"error": "Comment not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user != comment.author and not request.user.is_admin:
            return Response({"error": "You do not have permission to delete this comment."}, status=status.HTTP_403_FORBIDDEN)
    
        comment.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
      
      
class PostDetailView(APIView):
    permission_classes = [IsAuthenticated, IsPostAuthor]

    def get(self, request, pk):
        post = Post.objects.get(pk=pk)
        self.check_object_permissions(request, post)
        return Response({"content": post.content})
