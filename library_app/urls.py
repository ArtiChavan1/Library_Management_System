from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AdminSignupView, admin_login, BookViewSet, student_view, api_home, login_page, signup_page, add_book, update_book, delete_book, student_readonly_view

router = DefaultRouter()
router.register(r'books', BookViewSet)

urlpatterns = [
    path('', api_home, name='api_home'),  # 👈 Now /api/ will work

    path('admin/signup/', AdminSignupView.as_view(), name='admin_signup'),
    path('admin/signup-page/', signup_page, name='signup_page'),
    path('admin/login/', admin_login, name='admin_login'),
    path('admin/login-page/', login_page, name='login_page'),
    path('student/books/', student_view, name='student_books'),
    # path('student/view/', student_readonly_view, name='student_view'),
    path('student/view/', student_readonly_view, name='student_readonly_view'),  # Make sure this matches the reverse lookup name


    path('books/add/', add_book, name='add_book'),
    path('books/update/<int:pk>/', update_book, name='update_book'),
    path('books/delete/<int:pk>/', delete_book, name='delete_book'),

    path('', include(router.urls)),
]

