from rest_framework.pagination import PageNumberPagination

class CommentPagination(PageNumberPagination):
    page_size = 2  # Number of comments per page
    page_size_query_param = 'page_size'
    max_page_size = 100