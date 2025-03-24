from django.shortcuts import render
from django.http import JsonResponse

# Create your views here.
def test_cors(request):
    response = JsonResponse({"message": "CORS test successful"})
    return response
