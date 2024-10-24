from django.shortcuts import render
from rest_framework.decorators import APIView
# from axes.utils import is_already_locked



class CustomLockout(APIView):
    def post(self, request, *args, **kwargs):
        pass

