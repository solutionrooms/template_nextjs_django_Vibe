from django.urls import path, include
from api.api import urls as api_urls

urlpatterns = [
    path('', include(api_urls)),
]