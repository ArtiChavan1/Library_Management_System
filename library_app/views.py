from rest_framework import generics, permissions, viewsets, status 
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view
from django.shortcuts import render, redirect
from django.contrib.auth import logout as auth_logout, login as auth_login
from django.db import IntegrityError
from django.contrib.auth import authenticate, login as auth_login

from django.http import JsonResponse


from .models import Admin, Book
from .serializers import AdminSerializer, BookSerializer

def api_home(request):
    return render(request, 'home.html')


class AdminSignupView(generics.CreateAPIView):
    """API endpoint for admin signup"""
    queryset = Admin.objects.all()
    serializer_class = AdminSerializer

    def create(self, request, *args, **kwargs):
        try:
            return super().create(request, *args, **kwargs)
        except IntegrityError:
            return Response({'error': 'Admin with this email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import redirect

@api_view(['GET', 'POST'])
def admin_login(request):
    if request.method == 'GET':
        # Redirect GET requests to the login page to avoid 405 error
        return redirect('login_page')
    # POST request handling for login
    email = request.data.get('email')
    password = request.data.get('password')
    try:
        admin = Admin.objects.get(email=email)
        if admin.check_password(password):
            refresh = RefreshToken.for_user(admin)
            return Response({'refresh': str(refresh), 'access': str(refresh.access_token)})
        return Response({'error': 'Invalid credentials'}, status=400)
    except Admin.DoesNotExist:
        return Response({'error': 'Admin not found'}, status=404)

def login_page(request):
    """Render and process the admin login form"""
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        try:
            admin = Admin.objects.get(email=email)
            if admin.check_password(password):
                # Log the user in using Django's session framework
                auth_login(request, admin)
                return redirect('student_books')  # Redirect to book list page after login
            else:
                return render(request, 'login.html', {'error': 'Invalid credentials'})
        except Admin.DoesNotExist:
            return render(request, 'login.html', {'error': 'Admin not found'})
    else:
        return render(request, 'login.html')

def signup_page(request):
    """Render and process the admin signup form"""
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        if not email or not password:
            return render(request, 'signup.html', {'error': 'Email and password are required'})
        try:
            admin = Admin.objects.create_user(email=email, password=password)
            admin.save()
            return redirect('login_page')  # Redirect to login page after successful signup
        except Exception as e:
            return render(request, 'signup.html', {'error': str(e)})
    else:
        return render(request, 'signup.html')

class BookViewSet(viewsets.ModelViewSet):
    """API ViewSet for managing books (CRUD)"""
    queryset = Book.objects.all()
    serializer_class = BookSerializer
    permission_classes = [permissions.IsAuthenticated]

def student_view(request):
    """Renders the list of books for students"""
    books = Book.objects.all()
    return render(request, 'book_list.html', {'books': books})


from django.shortcuts import get_object_or_404

import re
from django.core.exceptions import ValidationError

def validate_isbn(isbn):
    isbn_pattern = re.compile(r'^(97(8|9))?\d{9}(\d|X)$')
    if not isbn_pattern.match(isbn):
        raise ValidationError('Invalid ISBN format. Must be ISBN-10 or ISBN-13.')

def add_book(request):
    """Render and process form to add a new book"""
    if request.method == 'POST':
        title = request.POST.get('title')
        author = request.POST.get('author')
        published_date = request.POST.get('published_date')
        isbn = request.POST.get('isbn')
        category = request.POST.get('category')
        available_copies = request.POST.get('available_copies')

        # Validate required fields
        if not title or not author or not published_date or not isbn or available_copies is None:
            return render(request, 'book_form.html', {'error': 'Title, author, published date, ISBN, and available copies are required.'})

        try:
            validate_isbn(isbn)
        except ValidationError as e:
            return render(request, 'book_form.html', {'error': str(e)})

        try:
            available_copies = int(available_copies)
            if available_copies < 0:
                raise ValueError
        except ValueError:
            return render(request, 'book_form.html', {'error': 'Available copies must be a non-negative integer.'})

        try:
            from datetime import datetime
            published_date_obj = datetime.strptime(published_date, '%Y-%m-%d').date()
        except ValueError:
            return render(request, 'book_form.html', {'error': 'Published date must be in YYYY-MM-DD format.'})

        Book.objects.create(title=title, author=author, published_date=published_date_obj, isbn=isbn, available_copies=available_copies)
        return redirect('student_books')
    else:
        return render(request, 'book_form.html')

def update_book(request, pk):
    """Render and process form to update an existing book"""
    book = get_object_or_404(Book, pk=pk)
    if request.method == 'POST':
        title = request.POST.get('title')
        author = request.POST.get('author')
        published_date = request.POST.get('published_date')
        isbn = request.POST.get('isbn')
        # category = request.POST.get('category')
        available_copies = request.POST.get('available_copies')
        if not title or not author or not published_date or not isbn or available_copies is None:
            return render(request, 'book_form.html', {'error': 'All fields are required.', 'book': book})
        try:
            validate_isbn(isbn)
        except ValidationError as e:
            return render(request, 'book_form.html', {'error': str(e), 'book': book})
        try:
            available_copies = int(available_copies)
            if available_copies < 0:
                raise ValueError
        except ValueError:
            return render(request, 'book_form.html', {'error': 'Available copies must be a non-negative integer.', 'book': book})
        try:
            from datetime import datetime
            published_date_obj = datetime.strptime(published_date, '%Y-%m-%d').date()
        except ValueError:
            return render(request, 'book_form.html', {'error': 'Published date must be in YYYY-MM-DD format.', 'book': book})
        book.title = title
        book.author = author
        book.published_date = published_date_obj
        book.isbn = isbn
        # book.category = category
        book.available_copies = available_copies
        book.save()
        return redirect('student_books')
    else:
        return render(request, 'book_form.html', {'book': book})

def delete_book(request, pk):
    """Delete a book and redirect to book list"""
    book = get_object_or_404(Book, pk=pk)
    if request.method == 'POST':
        book.delete()
        return redirect('student_books')
    return render(request, 'confirm_delete.html', {'book': book})


def student_readonly_view(request):
    """Renders the list of books for students without CRUD operations."""
    books = Book.objects.all()  # Fetch all books
    return render(request, 'student_book_list.html', {'books': books})