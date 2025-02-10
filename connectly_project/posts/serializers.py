from rest_framework import serializers
from .models import User, Post, Comment


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            email=validated_data['email']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

    def run_validation(self, data):
        username = data.get('username')
        email = data.get('email')
        errors = {}

        if User.objects.filter(username=username).exists():
            errors["username"] = "USERNAME IS ALREADY TAKEN >-<"
        if User.objects.filter(email=email).exists():
            errors["email"] = "EMAIL IS ALREADY TAKEN >-<."

        if errors:
            raise serializers.ValidationError(errors)

        return super().run_validation(data)
    


        
class PostSerializer(serializers.ModelSerializer):
    comments = serializers.StringRelatedField(many=True, read_only=True)

    class Meta:
        model = Post
        fields = ['id', 'content', 'author', 'created_at', 'comments']

    def run_validation(self, data):
        author_id = data.get('author')
        if not User.objects.filter(id=author_id).exists():
            raise serializers.ValidationError({"author": "Author not found."})
        if not data.get('content'):
            raise serializers.ValidationError({"content": "Post content cannot be empty."})
        return super().run_validation(data)

class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = ['id', 'text', 'author', 'post', 'created_at']

    def run_validation(self, data):
        author_id = data.get('author')
        post_id = data.get('post')
        if not User.objects.filter(id=author_id).exists():
            raise serializers.ValidationError({"author": "Author not found."})
        if not Post.objects.filter(id=post_id).exists():
            raise serializers.ValidationError({"post": "Post not found."})
        return super().run_validation(data)