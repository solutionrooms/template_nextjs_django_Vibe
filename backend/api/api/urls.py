from django.urls import path
from .views import LoginView, LogoutView, ClubListView, ClubCreateView, ClubDetailView, ClubAdminStatusView, ClubMembersView, ClubMemberDetailView, TestLoginView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('test-login/', TestLoginView.as_view(), name='test-login'),  # Special test login endpoint
    path('logout/', LogoutView.as_view(), name='logout'),
