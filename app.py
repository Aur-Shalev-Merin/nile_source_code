# Imports the Flask library and some other helper libraries.
from dataclasses import dataclass
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from flask import Flask, redirect, request, render_template, session

# Initializes the Flask web server.
app = Flask(__name__)
# Set secret key to enable signed session cookies, preventing users from tampering with session data
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-change-in-production')

'''
This code sets up the data structures which are used to store all of the information used by the app.
'''
@dataclass
class User:
    username: str
    password: str
    balance: int
    is_admin: bool

@dataclass
class Product:
    product_id: int
    name: str
    description: str
    price: int
    image_url: str

@dataclass
class Purchase:
    user: User
    product: Product
    quantity: int

# The user database is a dictionary where the keys are usernames and the values are User structs.
# Passwords are hashed client-side using SHA-256 for security
user_database: Dict[str, User] = {
    'admin': User(username='admin', password='8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', balance=1000, is_admin=True),
    'test': User(username='test', password='9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', balance=100, is_admin=False),
}

# The product database is a pre-populated list of every available product.
product_database: List[Product] = [
    Product(product_id=0, name='Toaster', description='It does everything! Well, it toasts. Just that, really.', price=23, image_url='toaster.jpg'),
    Product(product_id=1, name='Stapler', description='Excuse me, I believe we have what will soon be your favorite stapler!', price=12, image_url='stapler.jpg'),
    Product(product_id=2, name='One Sock', description='Have you ever lost one sock, but you can\'t replace it because they\'re only sold in pairs? Well look no further!', price=2, image_url='sock.jpg'),
    Product(product_id=3, name='Laptop', description='A perfect gift for your friend who doesn\'t have enough screens in their life.', price=800, image_url='laptop.jpg'),
    Product(product_id=4, name='Worm on a String', description='You will never find a closer confidant, a more dutiful servant, or a more loyal friend than this worm on a string.', price=1, image_url='worm_on_string.jpg'),
    Product(product_id=5, name='Grand Piano', description='At $170, this piano is a steal! Seriously, at that price it must be stolen right? Or haunted? What\'s the catch?', price=170, image_url='piano.jpg'),
    Product(product_id=6, name='Oud', description='It\'s like a guitar, except you now get confused looks when you bring it to jam night.', price=65, image_url='oud.jpg'),
    Product(product_id=7, name='Sewall Hall', description='Yep, we\'re selling the entirety of Sewall hall! Students not included. No refunds.', price=1000000, image_url='sewall_hall.jpg'),
]

# The purchase database starts empty, but will get filled as purchases are made
purchase_database: List[Purchase] = []

# Track failed login attempts for rate limiting
# Dictionary mapping username to list of failed attempt timestamps
failed_login_attempts: Dict[str, List[datetime]] = {}

# Configuration for login rate limiting
MAX_LOGIN_ATTEMPTS = 5  # Maximum failed attempts before lockout
LOCKOUT_DURATION = timedelta(minutes=15)  # How long to lock accounts

'''
These routes handle the main user-facing pages, including viewing products and purchasing them.
'''
@app.route("/", methods=["GET"])
def index():
    '''Displays the home page of the website.'''

    # If the user is not logged in, redirect them to the login page.
    username = get_current_user()
    if not username:
        return redirect("/login")

    balance = user_database[username].balance
    products = product_database

    return render_template("index.html", username=username, balance=balance, products=products)

@app.route("/product/<int:product_id>", methods=["GET"])
def product(product_id: int):
    '''Displays the details of a specific product.'''

    # If the user is not logged in, redirect them to the login page.
    username = get_current_user()
    if not username:
        return redirect("/login")

    # Validate that the product_id exists in the database
    if product_id < 0 or product_id >= len(product_database):
        return render_template("error.html", error="Product not found")

    user = user_database[username]
    product = product_database[product_id]

    return render_template("product.html", product=product, username=username, admin=user.is_admin)

@app.route("/purchase", methods=["POST"])
def purchase():
    '''Purchases a product.'''

    # If the user is not logged in, redirect them to the login page.
    username = get_current_user()
    if not username:
        return redirect("/login")

    product_id = request.form.get("product_id", type=int)
    quantity = request.form.get("quantity", type=int)

    if product_id is None or quantity is None:
        return render_template("error.html", error="Request is missing required fields")
    
    if quantity <= 0:
        return render_template("error.html", error="Quantity must be a positive number")

    # Validate that the product_id exists in the database
    if product_id < 0 or product_id >= len(product_database):
        return render_template("error.html", error="Invalid product")

    # Get all product information from the database instead of trusting any form data
    product = product_database[product_id]
    price = product.price
    new_balance = user_database[username].balance - (price * quantity)

    if new_balance < 0:
        return render_template("error.html", error="Cannot make purchase due to insufficient funds")
    else:
        logging.info(f"New purchase: {username} bought {quantity}x {product_id}")
        user_database[username].balance = new_balance

    purchase_record = Purchase(
        user=user_database[username],
        product=product_database[product_id],
        quantity=quantity
    )
    purchase_database.append(purchase_record)
    
    # Store purchase details in session for display on confirmation page
    # This implements the POST-Redirect-GET pattern to prevent duplicate purchases
    # when the page is refreshed by avoiding direct template rendering
    session['last_purchase'] = {
        'product_name': product.name,
        'product_image': product.image_url,
        'quantity': quantity,
        'user_balance': new_balance
    }
    
    # Redirect to GET endpoint instead of rendering template directly
    # This prevents the browser from re-submitting the POST request on refresh
    return redirect("/purchase_success")

@app.route("/purchase_success", methods=["GET"])
def purchase_success():
    '''Displays purchase confirmation page.'''
    # New GET route implementing the POST-Redirect-GET pattern
    # This prevents duplicate purchases when users refresh the confirmation page
    
    # If the user is not logged in, redirect them to the login page.
    username = get_current_user()
    if not username:
        return redirect("/login")
    
    # Retrieve purchase details from session instead of processing transaction again
    # This ensures refreshing the page doesn't trigger another purchase
    purchase_data = session.get('last_purchase')
    if not purchase_data:
        return redirect("/")
    
    # Clear the purchase data from session after displaying
    # This prevents stale data and ensures one-time display for security
    session.pop('last_purchase', None)
    
    return render_template("purchase_success.html", username=username, purchase_data=purchase_data)

'''
These routes are only used by administrators.
'''
@app.route("/admin", methods=["GET"])
def admin_dashboard():
    '''Allows admins to view recent purchases.'''

    # Check admin authentication and authorization
    auth_error = require_admin()
    if auth_error:
        return auth_error

    # Gets the 10 most recent purchases
    recent_purchases = purchase_database[-10:]
    return render_template("admin.html", purchases=recent_purchases)

@app.route("/update_product", methods=["POST"])
def update_product():
    '''Allows admins to change the product description.'''

    # Check admin authentication and authorization
    auth_error = require_admin()
    if auth_error:
        return auth_error

    product_id = request.form.get("product_id", type=int)
    new_description = request.form.get("description")

    if product_id is None or new_description is None:
        return render_template("error.html", error="Request is missing required fields")

    # Validate that the product_id exists in the database
    if product_id < 0 or product_id >= len(product_database):
        return render_template("error.html", error="Invalid product")

    product_database[product_id].description = new_description

    return redirect(f"/product/{product_id}")

'''
These routes handle logging in, creating accounts, and determining who is currently logged in.
'''
@app.route("/login", methods=["GET"])
def login_get():
    '''Return the login page of the website.'''

    # Clear any existing session data to ensure user starts with a clean slate
    session.pop('username', None)
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login_post():
    '''Logs the user in, if they supply the correct password.'''

    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return render_template("error.html", error="Username and password are both required")

    # Check if the account is currently locked due to too many failed attempts
    if is_account_locked(username):
        return render_template("error.html", error="Account temporarily locked due to too many failed login attempts. Please try again in 15 minutes.")

    user = user_database.get(username)
    if user is None:
        # Record failed attempt even for non-existent users to prevent username enumeration timing attacks
        record_failed_login(username)
        return render_template("error.html", error="Invalid username or password")

    # Password arrives already hashed from client-side, so compare hashes directly
    if user.password == password:
        # Successful login - clear any failed attempts and log in the user
        clear_failed_logins(username)
        session['username'] = username
        return redirect("/")
    else:
        # Failed login - record the attempt and return error
        record_failed_login(username)
        return render_template("error.html", error="Invalid username or password")

@app.route("/create_account", methods=["GET"])
def create_account_get():
    '''Return the create_account page of the website.'''

    return render_template("create_account.html")

@app.route("/create_account", methods=["POST"])
def create_account_post():
    '''Creates a new account.'''

    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return render_template("error.html", error="Username and password are both required")

    if username in user_database:
        return render_template("error.html", error="A user with that username already exists")

    user_database[username] = User(
        username=username,
        # Password arrives already hashed from client-side, store as-is
        password=password,
        balance=100,
        is_admin=False
    )

    # Log in as the newly created user using secure signed session.
    session['username'] = username
    return redirect("/")

@app.route("/logout", methods=["GET"])
def logout():
    '''Logs the user out.'''

    # Remove username from signed session (more secure than deleting raw cookies)
    session.pop('username', None)
    return redirect("/")

def get_current_user() -> Optional[str]:
    '''Return the current logged-in user if they exist, otherwise return None.'''

    # Use signed session instead of raw cookies to prevent user impersonation
    return session.get('username')

def require_admin():
    '''Check if the current user is logged in and has admin privileges. 
    Returns an error response if not, otherwise returns None to continue.'''
    
    # Check if user is logged in
    username = get_current_user()
    if not username:
        return render_template("error.html", error="You must be logged in to perform this action")
    
    # Check if user is admin
    user = user_database.get(username)
    if not user or not user.is_admin:
        return render_template("error.html", error="Access denied: Admin privileges required")
    
    # Return None if all checks pass
    return None

def is_account_locked(username: str) -> bool:
    '''Check if an account is currently locked due to too many failed login attempts.'''
    if username not in failed_login_attempts:
        return False
    
    now = datetime.now()
    attempts = failed_login_attempts[username]
    
    # Remove old attempts that are outside the lockout window
    recent_attempts = [attempt for attempt in attempts if now - attempt < LOCKOUT_DURATION]
    failed_login_attempts[username] = recent_attempts
    
    # Check if we have too many recent attempts
    return len(recent_attempts) >= MAX_LOGIN_ATTEMPTS

def record_failed_login(username: str):
    '''Record a failed login attempt for the given username.'''
    now = datetime.now()
    if username not in failed_login_attempts:
        failed_login_attempts[username] = []
    
    failed_login_attempts[username].append(now)
    
    # Clean up old attempts to prevent memory bloat
    cutoff_time = now - LOCKOUT_DURATION
    failed_login_attempts[username] = [
        attempt for attempt in failed_login_attempts[username] 
        if attempt > cutoff_time
    ]

def clear_failed_logins(username: str):
    '''Clear failed login attempts for a user (called on successful login).'''
    if username in failed_login_attempts:
        failed_login_attempts[username] = []

# Run the app
app.run(debug=True, port=8000)