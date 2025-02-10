from rest_framework import serializers
from .models import User, Post, Comment, Likes


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

class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = ['text', 'post', 'created_at']
        extra_kwargs = {'author': {'required': False}}

    def create(self, validated_data):
        request = self.context.get('request')
        validated_data['author'] = request.user
        return super().create(validated_data)

    def run_validation(self, data):
        post_id = data.get('post')
        if not Post.objects.filter(id=post_id).exists():
            raise serializers.ValidationError({"post": "Post not found."})
        return super().run_validation(data)

class PostSerializer(serializers.ModelSerializer):
    comments = CommentSerializer(many=True, read_only=True)
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

class LikesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Likes
        fields = ['post']
        extra_kwargs = {'user': {'required': False}}

    def create(self, validated_data):
        request = self.context.get('request')
        validated_data['user'] = request.user
        post_id = validated_data.get('post')
        validated_data['post'] = Post.objects.get(id=post_id)
        return super().create(validated_data)

    def validate_post(self, value):
        if isinstance(value, Post):
            return value.id
        return value

    def validate(self, data):
        request = self.context.get('request')
        if 'user' not in data:
            data['user'] = request.user
        return data

    def run_validation(self, data):
        data = super().run_validation(data)
        post_id = data.get('post')
        if not Post.objects.filter(id=post_id).exists():
            raise serializers.ValidationError({"post": "Post not found."})
        return data