from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class VinPagination(PageNumberPagination):
    page_size = 10


class AllUnverifiedUsersPegination(PageNumberPagination):
    page_size = 5

    def get_paginated_response(self, data):
        return Response(
            {
                "metadata": {
                    "count": self.page.paginator.count,
                    "next": self.get_next_link(),
                    "previous": self.get_previous_link(),
                    "has_next" : True if self.get_next_link() else False,
                    "has_previous" : True if self.get_previous_link() else False,
                    "current_page": self.page.number,  # Current page number
                    "total_pages": self.page.paginator.num_pages,  # Total number of pages
                },
                "data": data,
            }
        )
