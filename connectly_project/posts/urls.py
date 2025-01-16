from django.urls import path
from . import views
from .views import UserListCreate, PostListCreate, CommentListCreate

urlpatterns = [
    path('users/', UserListCreate.as_view(), name='user-list-create'),
    path('posts/', PostListCreate.as_view(), name='post-list-create'),
    path('comments/', CommentListCreate.as_view(), name='comment-list-create'),

]
