from ..models import Post, User

class PostFactory:
    @staticmethod
    def create_post(post_type, title, content='', metadata=None, author=None, is_private=False):
        if metadata is None:
            metadata = {}

        if post_type not in dict(Post.POST_TYPES):
            raise ValueError("Invalid post type")

        # Validate type-specific requirements
        if post_type == 'image' and 'file_size' not in metadata:
            raise ValueError("Image posts require 'file_size' in metadata")
        if post_type == 'video' and 'duration' not in metadata:
            raise ValueError("Video posts require 'duration' in metadata")

        if author is None:
            raise ValueError("Author is required")

        return Post.objects.create(
            title=title,
            content=content,
            post_type=post_type,
            metadata=metadata,
            author=author,
            is_private=is_private
        )