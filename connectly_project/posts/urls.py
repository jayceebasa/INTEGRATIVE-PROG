from django.urls import path
from . import views
from .views import UserListCreate, PostListCreate, CommentListCreate, login, create_superuser, logout, CreatePostView, create_user


urlpatterns = [
    path('users/', UserListCreate.as_view(), name='user-list-create'),
    path('posts/', PostListCreate.as_view(), name='post-list-create'),
    path('comments/', CommentListCreate.as_view(), name='comment-list-create'),
    path('login/', login, name='login'),
    path('create_admin/', create_superuser, name='create_superuser'),
    path('register/', create_user, name='create_user'),
    path('logout/', logout, name='logout'),
    path('create_post/', CreatePostView.as_view(), name='create_post'),
]
