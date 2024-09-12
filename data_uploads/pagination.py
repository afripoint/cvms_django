from rest_framework.pagination import PageNumberPagination



class VinPagination(PageNumberPagination):
    page_size = 10


class AllUnveriifiedUsers(PageNumberPagination):
    page_size = 8