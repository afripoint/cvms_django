from django.shortcuts import render, get_object_or_404
from drf_yasg.utils import swagger_auto_schema
from datetime import datetime
from rest_framework.views import APIView
from drf_yasg import openapi
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import ListAPIView
from .utils import make_external_api_request

class AccountSearchRatesAPIListView(APIView):
    """
    View to list the results from the external API
    """
    def get(self, request, *args, **kwargs):
        start_date = request.query_params.get('startDate')
        end_date = request.query_params.get('endDate')

        params = {
            'startDate': start_date,
            'endDate': end_date
        }

        data = make_external_api_request('accounts-search-rates', params)

        if "error" in data:
            return Response(data, status=status.HTTP_400_BAD_REQUEST)

        return Response(data, status=status.HTTP_200_OK)



class SignUpSearchComparisonAPIListView(APIView):
    """
    View to list the results from the external API
    """
    def get(self, request, *args, **kwargs):
        start_date = request.query_params.get('startDate')
        end_date = request.query_params.get('endDate')

        params = {
            'startDate': start_date,
            'endDate': end_date
        }

        data = make_external_api_request('signup-search-comparison', params)

        if "error" in data:
            return Response(data, status=status.HTTP_400_BAD_REQUEST)

        return Response(data, status=status.HTTP_200_OK)
    

class VinSearchGrowthAPIListView(APIView):
    """
    View to list the results from the external API
    """
    def get(self, request, *args, **kwargs):
        start_date = request.query_params.get('startDate')
        end_date = request.query_params.get('endDate')

        params = {
            'startDate': start_date,
            'endDate': end_date
        }

        data = make_external_api_request('vin-search-growth', params)

        if "error" in data:
            return Response(data, status=status.HTTP_400_BAD_REQUEST)

        return Response(data, status=status.HTTP_200_OK)



class RegistrationAPIListView(APIView):
    """
    View to list the results from the external API
    """
    def get(self, request, *args, **kwargs):
        start_date = request.query_params.get('startDate')
        end_date = request.query_params.get('endDate')

        params = {
            'startDate': start_date,
            'endDate': end_date
        }

        data = make_external_api_request('registrations', params)

        if "error" in data:
            return Response(data, status=status.HTTP_400_BAD_REQUEST)

        return Response(data, status=status.HTTP_200_OK)


class TopAccountsAPIListView(APIView):
    """
    View to list the results from the external API
    """
    def get(self, request, *args, **kwargs):
        start_date = request.query_params.get('startDate')
        end_date = request.query_params.get('endDate')

        params = {
            'startDate': start_date,
            'endDate': end_date
        }

        data = make_external_api_request('top-accounts', params)

        if "error" in data:
            return Response(data, status=status.HTTP_400_BAD_REQUEST)

        return Response(data, status=status.HTTP_200_OK)
    
class AccountsDistributionAPIListView(APIView):
    """
    View to list the results from the external API
    """
    def get(self, request, *args, **kwargs):
        start_date = request.query_params.get('startDate')
        end_date = request.query_params.get('endDate')

        params = {
            'startDate': start_date,
            'endDate': end_date
        }

        data = make_external_api_request('accounts-distribution', params)

        if "error" in data:
            return Response(data, status=status.HTTP_400_BAD_REQUEST)

        return Response(data, status=status.HTTP_200_OK)



