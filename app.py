from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask_login import UserMixin, LoginManager, login_required, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import os
import sys
import traceback
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.urls import url_parse

# Enhanced logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app with configurations
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)  # Add support for proxy headers

# Database configuration with error handling
def get_database_url():
    db_url = os.environ.get('DATABASE_URL')
    if db_url and db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    return db_url or 'sqlite:///finance.db'

app.config.update(
    SQLALCHEMY_DATABASE_URI=get_database_url(),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-key-change-this'),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=7)
)

# Initialize extensions with error handling
try:
    db = SQLAlchemy(app)
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    logger.info("Successfully initialized database and login manager")
except Exception as e:
    logger.error(f"Failed to initialize extensions: {str(e)}")
    raise

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Enhanced debug helpers
def debug_request(request):
    """Debug helper to log request details"""
    logger.debug("=== Request Details ===")
    logger.debug(f"Method: {request.method}")
    logger.debug(f"Form Data: {dict(request.form)}")  # Convert to dict for better logging
    logger.debug(f"URL: {request.url}")
    logger.debug(f"Headers: {dict(request.headers)}")
    logger.debug(f"Cookies: {dict(request.cookies)}")

def log_user_state():
    """Debug helper to log current user state"""
    logger.debug("=== User State ===")
    logger.debug(f"Is authenticated: {current_user.is_authenticated}")
    if current_user.is_authenticated:
        logger.debug(f"Current user: {current_user.username}")

# Enhanced database initialization
def init_db():
    """Initialize database with proper error handling"""
    try:
        with app.app_context():
            # Check if database exists
            inspector = db.inspect(db.engine)
            existing_tables = inspector.get_table_names()
            logger.info(f"Existing tables: {existing_tables}")
            
            # Create tables if they don't exist
            db.create_all()
            logger.info("Database initialization completed successfully")
            
            # Verify all required tables are created
            required_tables = {'user', 'budget', 'expense'}
            actual_tables = set(inspector.get_table_names())
            missing_tables = required_tables - actual_tables
            
            if missing_tables:
                logger.error(f"Missing tables: {missing_tables}")
                raise Exception(f"Failed to create tables: {missing_tables}")
            
            logger.info("All required tables are present")
            
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}", exc_info=True)
        raise

# Database Models (reorder the models)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Define relationships after both models are defined
    budgets = db.relationship('Budget', backref='user', lazy=True, cascade="all, delete-orphan")
    expenses = db.relationship('Expense', backref='user', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        if not password or len(password) < 6:
            raise ValueError("Password must be at least 6 characters long")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not password:
            return False
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def validate_username(username):
        if not username or len(username) < 3:
            raise ValueError("Username must be at least 3 characters long")
        if not username.isalnum() and '_' not in username:
            raise ValueError("Username can only contain letters, numbers, and underscores")
        return username.strip()

    @staticmethod
    def validate_email(email):
        if not email or '@' not in email or '.' not in email:
            raise ValueError("Please enter a valid email address")
        return email.strip().lower()

class Budget(db.Model):
    """Budget model for storing monthly budgets"""
    id = db.Column(db.Integer, primary_key=True)
    month = db.Column(db.String(7), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'month', name='unique_user_month'),
    )

    def __repr__(self):
        return f'<Budget {self.month}: {self.amount}>'

class Expense(db.Model):
    """Expense model for storing daily expenses"""
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Expense {self.date} {self.category}: {self.amount}>'

# Add model validation functions
def validate_budget(amount):
    """Validate budget amount"""
    try:
        amount = float(amount)
        if amount <= 0:
            raise ValueError("Budget amount must be greater than 0")
        return amount
    except (TypeError, ValueError):
        raise ValueError("Invalid budget amount")

def validate_expense(amount):
    """Validate expense amount"""
    try:
        amount = float(amount)
        if amount < 0:
            raise ValueError("Expense amount cannot be negative")
        return amount
    except (TypeError, ValueError):
        raise ValueError("Invalid expense amount")

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    logger.error(f"404 error: {error}")
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {error}", exc_info=True)
    db.session.rollback()
    return render_template('error.html', error="Internal server error"), 500

# Enhanced registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        logger.debug("=== Starting Registration Process ===")
        debug_request(request)
        log_user_state()

        if current_user.is_authenticated:
            logger.debug("Authenticated user attempting to register - redirecting to index")
            return redirect(url_for('index'))

        if request.method == 'POST':
            logger.debug("Processing registration POST request")
            
            try:
                # Get and validate form data
                username = User.validate_username(request.form.get('username', ''))
                email = User.validate_email(request.form.get('email', ''))
                password = request.form.get('password', '')
                confirm_password = request.form.get('confirm_password', '')

                logger.debug(f"Validated username: {username}, email: {email}")

                # Check password match and length
                if password != confirm_password:
                    raise ValueError("Passwords do not match")
                
                if len(password) < 6:
                    raise ValueError("Password must be at least 6 characters long")

                # Check existing user
                if User.query.filter_by(username=username).first():
                    raise ValueError("Username already exists")
                
                if User.query.filter_by(email=email).first():
                    raise ValueError("Email already registered")

                # Create new user
                new_user = User(username=username, email=email)
                new_user.set_password(password)
                
                logger.debug("Adding new user to database")
                db.session.add(new_user)
                db.session.commit()
                logger.info(f"Successfully created user: {username}")

                # Log in the new user
                login_user(new_user)
                logger.debug(f"Logged in new user: {username}")
                
                flash('Registration successful! Welcome to Finance Tracker.', 'success')
                return redirect(url_for('index'))

            except ValueError as ve:
                logger.warning(f"Validation error during registration: {str(ve)}")
                return render_template('register.html', error=str(ve))
                
            except IntegrityError as ie:
                db.session.rollback()
                logger.error(f"Database integrity error: {str(ie)}")
                return render_template('register.html', 
                    error="A user with that username or email already exists.")
                
            except SQLAlchemyError as se:
                db.session.rollback()
                logger.error(f"Database error: {str(se)}")
                return render_template('register.html', 
                    error="Database error occurred. Please try again.")

        return render_template('register.html')

    except Exception as e:
        logger.error("Unexpected error in registration route", exc_info=True)
        return render_template('error.html', 
            error="An unexpected error occurred. Please try again later.")

# Enhanced login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        logger.debug("=== Starting Login Process ===")
        debug_request(request)
        log_user_state()

        if current_user.is_authenticated:
            logger.debug("Authenticated user attempting to login - redirecting to index")
            return redirect(url_for('index'))

        if request.method == 'POST':
            logger.debug("Processing login POST request")
            
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')

            logger.debug(f"Login attempt for username: {username}")

            if not username or not password:
                logger.warning("Missing username or password")
                return render_template('login.html', error="Please enter both username and password")

            try:
                user = User.query.filter_by(username=username).first()
                
                if user is None:
                    logger.warning(f"No user found with username: {username}")
                    return render_template('login.html', error="Invalid username or password")

                if not user.check_password(password):
                    logger.warning(f"Invalid password for user: {username}")
                    return render_template('login.html', error="Invalid username or password")

                login_user(user)
                logger.info(f"Successfully logged in user: {username}")

                # Handle next page
                next_page = request.args.get('next')
                if not next_page or url_parse(next_page).netloc != '':
                    next_page = url_for('index')
                
                flash('Login successful!', 'success')
                return redirect(next_page)

            except SQLAlchemyError as se:
                logger.error(f"Database error during login: {str(se)}")
                return render_template('login.html', 
                    error="Database error occurred. Please try again.")

        return render_template('login.html')

    except Exception as e:
        logger.error("Unexpected error in login route", exc_info=True)
        return render_template('error.html', 
            error="An unexpected error occurred. Please try again later.")

# Enhanced logout route
@app.route('/logout')
@login_required
def logout():
    try:
        logger.debug("=== Processing Logout ===")
        log_user_state()
        
        username = current_user.username
        logout_user()
        logger.info(f"Successfully logged out user: {username}")
        
        flash('You have been logged out successfully.', 'success')
        return redirect(url_for('login'))
    
    except Exception as e:
        logger.error("Error during logout", exc_info=True)
        return redirect(url_for('login'))

# Main routes
@app.route('/')
@login_required
def index():
    current_month = datetime.now().strftime('%Y-%m')
    budget = Budget.query.filter_by(
        month=current_month,
        user_id=current_user.id
    ).first()
    return render_template('budget_setup.html', budget=budget)

@app.route('/expense')
@login_required
def expense():
    categories = ['Auto', 'Online Food', 'College Mess', 'Instamart', 'Miscellaneous']
    return render_template('expense.html', categories=categories)

@app.route('/add_expense', methods=['POST'])
def add_expense():
    data = request.get_json()
    date_str = data.get('date')
    categories = data.get('categories')
    date = datetime.strptime(date_str, '%Y-%m-%d').date()
    for category, amount in categories.items():
        amount = float(amount)
        expense = Expense.query.filter_by(date=date, category=category).first()
        if expense:
            expense.amount = amount
        else:
            if amount > 0:
                expense = Expense(date=date, category=category, amount=amount)
                db.session.add(expense)
        db.session.commit()
    return jsonify({'status': 'success'})

@app.route('/api/expenses')
@login_required
def get_expenses():
    start_date = request.args.get('start')
    end_date = request.args.get('end')
    
    if start_date and end_date:
        start = datetime.strptime(start_date, '%Y-%m-%d').date()
        end = datetime.strptime(end_date, '%Y-%m-%d').date()
        
        expenses = Expense.query.filter(
            Expense.date >= start,
            Expense.date <= end,
            Expense.user_id == current_user.id
        ).all()
        
        expense_data = {}
        for expense in expenses:
            date_str = expense.date.strftime('%Y-%m-%d')
            if date_str not in expense_data:
                expense_data[date_str] = {
                    'total': 0,
                    'categories': {}
                }
            expense_data[date_str]['categories'][expense.category] = expense.amount
            expense_data[date_str]['total'] += expense.amount
            
        return jsonify(expense_data)
    
    date_str = request.args.get('date')
    if date_str:
        date = datetime.strptime(date_str, '%Y-%m-%d').date()
        expenses = Expense.query.filter_by(
            date=date,
            user_id=current_user.id
        ).all()
        expense_data = {expense.category: expense.amount for expense in expenses}
        return jsonify(expense_data)
    
    return jsonify({'error': 'Invalid date parameters'}), 400

@app.route('/api/summary')
def get_summary():
    current_month = datetime.now().strftime('%Y-%m')
    budget = Budget.query.filter_by(month=current_month).first()
    if not budget:
        return jsonify({'error': 'Budget not set'}), 400
    start_date = datetime.strptime(current_month, '%Y-%m').date()
    end_date = start_date.replace(day=28) + timedelta(days=4)
    expenses = Expense.query.filter(Expense.date >= start_date, Expense.date <= end_date).all()
    category_totals = {}
    total_spent = 0
    for expense in expenses:
        category_totals[expense.category] = category_totals.get(expense.category, 0) + expense.amount
        total_spent += expense.amount
    remaining_budget = budget.amount - total_spent
    return jsonify({
        'total_spent': total_spent,
        'remaining_budget': remaining_budget,
        'category_totals': category_totals
    })

@app.route('/calendar')
def calendar():
    return render_template('calendar.html')

@app.route('/summary')
def summary():
    return render_template('summary.html')

@app.route('/api/update_budget', methods=['POST'])
@login_required
def update_budget():
    try:
        data = request.get_json()
        new_budget = data.get('budget')
        
        if new_budget is None or new_budget <= 0:
            return jsonify({'message': 'Invalid budget amount'}), 400
            
        current_month = datetime.now().strftime('%Y-%m')
        budget = Budget.query.filter_by(
            month=current_month,
            user_id=current_user.id
        ).first()
        
        if budget:
            budget.amount = new_budget
        else:
            budget = Budget(
                month=current_month,
                amount=new_budget,
                user_id=current_user.id
            )
            db.session.add(budget)
            
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Budget updated successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

# Create error.html template
@app.route('/error')
def error():
    return render_template('error.html')

# Initialize the application
init_db()

# Application startup
if __name__ == '__main__':
    try:
        port = int(os.environ.get('PORT', 10000))
        app.run(host='0.0.0.0', port=port)
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}\n{traceback.format_exc()}")
        raise