from django.urls import path

from django.conf import settings
from django.conf.urls.static import static
from . import views
from .views import UserListCreate, CreateCommentView, CreatePostView, login, create_superuser, logout, create_user, LikesView, PostDetailView


urlpatterns = [
    path('', views.login_page, name='login'),
    path('users/', UserListCreate.as_view(), name='user-list-create'),
    path('posts/', CreatePostView.as_view(), name='post-list-create'),
    path('posts/<int:id>/', PostDetailView.as_view(), name='post-detail'),
    path('<int:id>/comment/', CreateCommentView.as_view(), name='comment-list-create'),
    path('<int:id>/like/', LikesView.as_view(), name='likes-list-create'),
    path('api/auth/check/', views.check_auth, name='check-auth'),

    path('create_admin/', create_superuser, name='create_superuser'),
    path('register/', create_user, name='create_user'),
    
    path('login/', login, name='login'),
    path('logout/', logout, name='logout'),
    path('logout2/', views.logout_view, name='logout'),
    
    path('signup/', views.signup, name='signup'),
    
    #pages
    path('homepage/', views.homepage, name='homepage'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)