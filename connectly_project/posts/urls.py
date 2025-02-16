from django.urls import path
from . import views
from .views import UserListCreate, CreateCommentView, CreatePostView, login, create_superuser, logout, create_user, LikesView


urlpatterns = [
    path('', views.home, name='home'),
    path('users/', UserListCreate.as_view(), name='user-list-create'),
    path('posts/', CreatePostView.as_view(), name='post-list-create'),
    path('<int:id>/comment/', CreateCommentView.as_view(), name='comment-list-create'),
    path('<int:id>/like/', LikesView.as_view(), name='likes-list-create'),

    path('create_admin/', create_superuser, name='create_superuser'),
    path('register/', create_user, name='create_user'),
    
    path('login/', login, name='login'),
    path('logout2/', logout, name='logout'),
    path('logout/', views.logout_view, name='logout'), 
]
