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
from urllib.parse import urlparse
from flask_wtf.csrf import CSRFProtect, CSRFError
from decimal import Decimal, InvalidOperation

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

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Update the app configuration
app.config.update(
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///finance.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-key-change-this'),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,  # 1 hour
    WTF_CSRF_SSL_STRICT=True,
    WTF_CSRF_SECRET_KEY=os.environ.get('WTF_CSRF_SECRET_KEY', 'csrf-key-change-this')
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

# Add this function before init_db()
def recreate_tables():
    """Drop all tables and recreate them"""
    try:
        with app.app_context():
            logger.info("Dropping all tables...")
            db.drop_all()
            logger.info("Creating all tables...")
            db.create_all()
            logger.info("Tables recreated successfully")
    except Exception as e:
        logger.error(f"Failed to recreate tables: {str(e)}", exc_info=True)
        raise

# Update the init_db function
def init_db():
    """Initialize database with proper error handling"""
    try:
        with app.app_context():
            # Check if database exists
            inspector = db.inspect(db.engine)
            existing_tables = inspector.get_table_names()
            logger.info(f"Existing tables: {existing_tables}")
            
            # Define required tables
            required_tables = {'user', 'budget', 'expense'}
            actual_tables = set(existing_tables)
            missing_tables = required_tables - actual_tables
            
            if missing_tables:
                logger.warning(f"Missing tables detected: {missing_tables}")
                logger.info("Attempting to recreate all tables...")
                recreate_tables()
                
                # Verify tables after recreation
                inspector = db.inspect(db.engine)
                existing_tables = inspector.get_table_names()
                if not required_tables.issubset(set(existing_tables)):
                    raise Exception(f"Failed to create required tables. Current tables: {existing_tables}")
            
            logger.info("All required tables are present")
            
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}", exc_info=True)
        raise

# Database Models (reorder the models)
class User(db.Model, UserMixin):
    """User model for authentication"""
    __tablename__ = 'user'  # Explicitly set table name
    
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
    __tablename__ = 'budget'  # Explicitly set table name
    
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
    __tablename__ = 'expense'  # Explicitly set table name
    
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

# Add CSRF error handler
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    logger.error(f"CSRF error occurred: {str(e)}")
    flash('The form expired. Please try again.', 'error')
    return redirect(url_for('login'))

# Enhanced registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        if current_user.is_authenticated:
            return redirect(url_for('expense'))

        if request.method == 'POST':
            try:
                username = User.validate_username(request.form.get('username', ''))
                email = User.validate_email(request.form.get('email', ''))
                password = request.form.get('password', '')
                confirm_password = request.form.get('confirm_password', '')

                if password != confirm_password:
                    raise ValueError("Passwords do not match")
                
                if len(password) < 6:
                    raise ValueError("Password must be at least 6 characters long")

                if User.query.filter_by(username=username).first():
                    raise ValueError("Username already exists")
                
                if User.query.filter_by(email=email).first():
                    raise ValueError("Email already registered")

                new_user = User(username=username, email=email)
                new_user.set_password(password)
                
                db.session.add(new_user)
                db.session.commit()

                login_user(new_user)
                flash('Registration successful! Welcome to Finance Tracker.', 'success')
                return redirect(url_for('budget_setup'))

            except ValueError as ve:
                flash(str(ve), 'error')
                return render_template('register.html')
                
            except Exception as e:
                db.session.rollback()
                logger.error(f"Registration error: {str(e)}", exc_info=True)
                flash('An error occurred during registration. Please try again.', 'error')
                return render_template('register.html')

        return render_template('register.html')

    except Exception as e:
        logger.error(f"Unexpected registration error: {str(e)}", exc_info=True)
        flash('An unexpected error occurred. Please try again later.', 'error')
        return render_template('register.html')

# Enhanced login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    try:
        if current_user.is_authenticated:
            return redirect(url_for('expense'))

        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            user = User.query.filter_by(username=username).first()
            
            if user and user.check_password(password):
                login_user(user)
                
                # Check if user has set up budget for current month
                current_month = datetime.now().strftime('%Y-%m')
                has_budget = Budget.query.filter_by(
                    user_id=user.id,
                    month=current_month
                ).first()
                
                next_page = request.args.get('next')
                if not next_page or not next_page.startswith('/'):
                    next_page = url_for('budget_setup' if not has_budget else 'expense')
                
                return redirect(next_page)
            
            flash('Invalid username or password', 'error')
        
        return render_template('login.html')
    except Exception as e:
        logger.error(f"Login error: {str(e)}", exc_info=True)
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('login'))

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

@app.route('/', methods=['GET', 'POST'])
@app.route('/budget_setup', methods=['GET', 'POST'])
@login_required
def budget_setup():
    """Handle budget setup for new users"""
    try:
        logger.debug(f"Budget setup route accessed - Method: {request.method}")
        debug_request(request)
        
        if request.method == 'POST':
            logger.debug("Processing budget setup POST request")
            
            try:
                budget_amount = request.form.get('budget')
                logger.debug(f"Received budget amount: {budget_amount}")
                
                # Validate budget amount
                budget_amount = validate_budget(budget_amount)
                
                # Get current month in YYYY-MM format
                current_month = datetime.now().strftime('%Y-%m')
                
                # Check if budget already exists for this month
                existing_budget = Budget.query.filter_by(
                    user_id=current_user.id,
                    month=current_month
                ).first()

                try:
                    if existing_budget:
                        logger.debug(f"Updating existing budget for {current_month}")
                        existing_budget.amount = budget_amount
                    else:
                        logger.debug(f"Creating new budget for {current_month}")
                        new_budget = Budget(
                            month=current_month,
                            amount=budget_amount,
                            user_id=current_user.id
                        )
                        db.session.add(new_budget)

                    db.session.commit()
                    logger.info(f"Budget successfully set/updated for user {current_user.id}")
                    flash('Budget set successfully!', 'success')
                    return redirect(url_for('expense'))
                
                except SQLAlchemyError as db_error:
                    logger.error(f"Database error: {str(db_error)}")
                    db.session.rollback()
                    flash('Database error occurred. Please try again.', 'error')
                    return redirect(url_for('budget_setup'))

            except ValueError as ve:
                logger.warning(f"Validation error: {str(ve)}")
                flash(str(ve), 'error')
                return redirect(url_for('budget_setup'))

        # GET request - show the budget setup form
        logger.debug("Rendering budget setup form")
        current_month = datetime.now().strftime('%Y-%m')
        current_budget = Budget.query.filter_by(
            user_id=current_user.id,
            month=current_month
        ).first()
        
        return render_template('budget_setup.html', budget=current_budget)

    except Exception as e:
        logger.error(f"Unexpected error in budget_setup: {str(e)}", exc_info=True)
        db.session.rollback()
        flash('An unexpected error occurred. Please try again.', 'error')
        return redirect(url_for('budget_setup'))

# Initialize the application
init_db()

# Application startup
if __name__ == '__main__':
    try:
        with app.app_context():
            # Initialize database
            init_db()
            
            # Start the application
            port = int(os.environ.get('PORT', 10000))
            app.run(host='0.0.0.0', port=port)
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}", exc_info=True)
        raise