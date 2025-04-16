 HEAD
# Library_Management_System
=======
# Library Management System — Django REST API Project

## 📚 Project Overview

This project is a **Library Management System** built using **Django** and **Django REST Framework**.
It allows:
- Admins to manage (Create, Read, Update, Delete) books via secured REST API endpoints.
- Students to view the available books through a public API endpoint.

The project focuses on clean API design, proper authentication, error handling, and clear documentation.

## ✅ Key Features

- Admin Signup & Login (unique email-based)
- Token-based Authentication for secure admin operations
- CRUD Operations on books (Create, Read, Update, Delete)
- Student View API to list all available books
- Proper HTTP responses & error messages
- Secure data handling using Django ORM & MySQL

## ⚙️ Tech Stack

- **Backend Framework** : Django (version 4.x)
- **REST API** : Django REST Framework
- **Database** : MySQL
- **Authentication** : Token-based Authentication
- **Language** : Python 3.x

## 📂 Project Structure

```text
LibraryManagement/
│
├── library_app/
│   ├── migrations/
│   ├── Templates/
│   ├── models.py
│   ├── serializers.py
│   ├── views.py
│   ├── urls.py
│   
├── LibraryManagement/
│   ├── settings.py
│   ├── urls.py
│
├── manage.py
├── requirements.txt
├── README.md
```

---

## 🛠️ Setup Instructions

> Please follow the steps carefully to set up and run the project on your system:

### 1. Clone the Repository
```bash
git clone 
cd Django_Library_Management_System
```

### 2. Set Up Virtual Environment
```bash
python -m venv venv
```
For Linux/Mac:
```bash
source venv/bin/activate
```
For Windows:
```bash
venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Database Setup
- Create a database in MySQL (Example: `library_db`)
- In `settings.py`, configure your database:
```python
DATABASES = {
   'default': {
       'ENGINE': 'django.db.backends.mysql',
       'NAME': 'library_db',
       'USER': 'your_mysql_user',
       'PASSWORD': 'your_mysql_password',
       'HOST': 'localhost',
       'PORT': '3306',
   }
}
```

### 5. Migrate Database
```bash
python manage.py makemigrations
python manage.py migrate
```

### 6. Run the Server
```bash
python manage.py runserver
```
Now your server will be running on:
[http://127.0.0.1:8000/](http://127.0.0.1:8000/)


## 🚀 API Endpoints

| Method | Endpoint                 | Description                           |
|--------|--------------------------|---------------------------------------|
| POST   | /api/admin/signup/       | Register a new admin account          |
| POST   | /api/admin/login/        | Login with email & password           |
| POST   | /api/admin/token/        | Get authentication token              |
| POST   | /api/books/              | Add a new book (admin only)           |
| GET    | /api/books/              | List all books                        |
| PUT    | /api/books/<id>/         | Update book details (admin only)      |
| DELETE | /api/books/<id>/         | Delete a book (admin only)            |

### 📖 Student View

| Method | Endpoint                  | Description                           |
|--------|---------------------------|---------------------------------------|
| GET    | /api/student/books/       | List all books (public access)        |


## ✅ API Testing (Using Requests Library)

A test script (`test_requests.py`) is provided to demonstrate API testing.

### What is covered in the test script:
- Admin signup
- Admin login and token generation
- Book creation (authorized with token)
- Retrieving book list (student view)
- Updating book details
- Deleting a book
- Handling duplicate admin signup

### How to run the API tests:
```bash
# Make sure the Django server is running
python manage.py runserver

# Navigate to the project directory in terminal
python tests/test_requests.py
```

## 🔐 Authentication & Error Handling

### Authentication:
Token-based authentication is implemented for all admin operations.
After a successful admin login, use the `/api/admin/token/` endpoint to generate a token.

### Passing the Token:
For all admin API requests (create, update, delete books), include the token in the request header:
```http
Authorization: Bearer <your-token>
```

### Error Handling:
The API returns appropriate HTTP status codes for various scenarios:
- **400 Bad Request** — for invalid input data or missing fields
- **401 Unauthorized** — for missing or invalid authentication tokens
- **404 Not Found** — when the requested resource does not exist

In case of duplicate admin signup or invalid login attempts, the API responds with descriptive error messages.

## ✅ Assumptions

- Admin email addresses are unique and validated during signup.
- Students do not need authentication to view books.
- Only authenticated admins can perform book management operations.

## ✅ Conclusion

This project demonstrates the implementation of a secure, well-structured Django REST API for Library Management.
The repository is built with clean code, modular structure, and follows best practices for authentication and error handling.

## ⭐ Feel free to fork this repository, raise issues, or contribute to enhancements!

 12cae98 (first commit)
