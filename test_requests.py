import requests

BASE_URL = "http://127.0.0.1:8000/api"

def admin_signup(email, password):
    data = {"email": email, "password": password}
    response = requests.post(f"{BASE_URL}/admin/signup/", json=data)
    print("Signup Response:", response.status_code, response.json())

def admin_login(email, password):
    data = {"email": email, "password": password}
    response = requests.post(f"{BASE_URL}/admin/login/", json=data)
    print("Login Response:", response.status_code, response.json())
    if response.status_code == 200:
        return response.json().get('access')
    return None

def create_book(token, title, author, published_date, isbn, available_copies):
    headers = {"Authorization": f"Bearer {token}"}
    data = {
        "title": title,
        "author": author,
        "published_date": published_date,
        "isbn": isbn,
        "available_copies": available_copies
    }
    response = requests.post(f"{BASE_URL}/books/", json=data, headers=headers)
    print("Create Book Response:", response.status_code, response.json())

def get_books():
    response = requests.get(f"{BASE_URL}/student/books/")
    print("Student Books List:", response.status_code)
    print("Content length:", len(response.text))

def delete_book(token, book_id):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.delete(f"{BASE_URL}/books/{book_id}/", headers=headers)
    print("Delete Book Response:", response.status_code, response.text)

def update_book(token, book_id, title, author, published_date, isbn, available_copies):
    headers = {"Authorization": f"Bearer {token}"}
    data = {
        "title": title,
        "author": author,
        "published_date": published_date,
        "isbn": isbn,
        "available_copies": available_copies
    }
    response = requests.put(f"{BASE_URL}/books/{book_id}/", json=data, headers=headers)
    print("Update Book Response:", response.status_code, response.json())

def test_duplicate_admin_signup():
    data = {"email": "admin10@gmail.com", "password": "somepassword"}
    response = requests.post(f"{BASE_URL}/admin/signup/", json=data)
    print("Duplicate Signup Response:", response.status_code, response.json())

if __name__ == "__main__":
    # Step 1: Admin signup (uncomment if needed)
    # admin_signup("admin10@gmail.com", "adminpassword10")

    # Step 2: Admin login
    admin_token = admin_login("admin10@gmail.com", "adminpassword10")

    # Step 3: Create a book
    # if admin_token:
    #     create_book(
    #         admin_token,
    #         title="Test Book Using Requests",
    #         author="Test Author",
    #         published_date="2025-01-01",
    #         isbn="9876543210987",
    #         available_copies=7
    #     )

    # Step 4: View books list (student view)
    get_books()

    # Step 5: Update book (change book_id accordingly)
    # update_book(admin_token, book_id=2, title="Updated Book", author="Updated Author", published_date="2025-02-01", isbn="111122223333", available_copies=10)

    # Step 6: Delete a book (change book_id accordingly)
    # delete_book(admin_token, book_id=1)

    # Step 7: Test duplicate admin signup
    # test_duplicate_admin_signup()
