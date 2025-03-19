from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session, g
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, timezone
from flask_login import UserMixin, LoginManager, login_required, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, CSRFError
import logging
import os
import sys
import traceback
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from decimal import Decimal, InvalidOperation
from sqlalchemy import inspect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from sqlalchemy.orm import Session
from pathlib import Path
from urllib.parse import urlparse

# Initialize Flask app
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

# Initialize logging
logging.basicConfig(
    level=logging.DEBUG if app.debug else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('app.log') if os.environ.get('FLASK_DEBUG', 'False').lower() == 'true' else logging.NullHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Database configuration
if os.environ.get('FLASK_ENV') == 'production':
    database_url = os.environ.get('DATABASE_URL', '')
    
    if not database_url:
        logger.error("❌ FATAL ERROR: DATABASE_URL not set in production!")
        raise RuntimeError("DATABASE_URL environment variable is required in production")

    # Force PostgreSQL format
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    logger.info(f"✅ Production database: {database_url.split('://')[0]}")
else:
    # Local (SQLite)
    # Create instance directory if it doesn't exist
    instance_path = Path(app.instance_path)
    instance_path.mkdir(exist_ok=True)
    
    # Set SQLite database path
    sqlite_path = instance_path / 'finance.db'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{sqlite_path}'
    logger.info(f"Using SQLite database at {sqlite_path} in development mode")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Update the app configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-key-change-this'),
    SESSION_COOKIE_SECURE=False if app.debug else True,  # True in production
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    REMEMBER_COOKIE_SECURE=False if app.debug else True,  # True in production
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_DURATION=timedelta(days=7),
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,  # 1 hour
    WTF_CSRF_SSL_STRICT=False if app.debug else True  # True in production
)

# Initialize extensions
db = SQLAlchemy(app)
with app.app_context():
    try:
        db.create_all()
        logger.info("Initialized database tables")
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")
        logger.error(traceback.format_exc())

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Database Models
class User(db.Model, UserMixin):
    """User model for authentication"""
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
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
    __tablename__ = 'budget'
    
    id = db.Column(db.Integer, primary_key=True)
    month = db.Column(db.String(7), nullable=False)  # Store as YYYY-MM
    amount = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'month', name='unique_user_month'),
    )

    def __repr__(self):
        return f'<Budget {self.month}: {self.amount}>'

class Expense(db.Model):
    """Expense model for storing daily expenses"""
    __tablename__ = 'expense'
    
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<Expense {self.date} {self.category}: {self.amount}>'

def verify_database():
    """Verify database integrity and connectivity"""
    try:
        # Check database connection type
        db_type = str(db.engine.url).split('://')[0]
        app.logger.info(f"Database type: {db_type}")
        
        # Check if tables exist
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        app.logger.info(f"Database tables found: {tables}")
        
        # Verify required tables exist
        required_tables = ['user', 'budget', 'expense']
        missing_tables = [table for table in required_tables if table not in tables]
        if missing_tables:
            app.logger.error(f"Missing required tables: {missing_tables}")
            # Create missing tables
            app.logger.info("Attempting to create missing tables...")
            db.create_all()
            app.logger.info("Tables created. Rechecking...")
            tables = inspect(db.engine).get_table_names()
            app.logger.info(f"Tables after creation: {tables}")
        
        # Count users
        user_count = User.query.count()
        app.logger.info(f"Total users in database: {user_count}")
        
        # List all users for debugging (only in development)
        if os.environ.get('FLASK_DEBUG', 'False').lower() == 'true':
            users = User.query.all()
            for user in users:
                app.logger.debug(f"User: {user.username}, Email: {user.email}")
        
        # Only perform write test in development mode
        if os.environ.get('FLASK_DEBUG', 'False').lower() == 'true':
            # Test write capability
            test_user = User(
                username="test_verify_db",
                email="test_verify_db@test.com"
            )
            test_user.set_password("test123")
            db.session.add(test_user)
            db.session.commit()
            db.session.delete(test_user)
            db.session.commit()
            app.logger.info("Database write test successful")
        else:
            # In production, just check if we can start a transaction
            with db.engine.begin() as conn:
                conn.execute(db.text("SELECT 1"))
            app.logger.info("Database connection test successful")
        
        return True
    except Exception as e:
        app.logger.error(f"Database verification failed: {str(e)}")
        app.logger.error(traceback.format_exc())
        return False

@app.before_request
def before_request():
    """Actions to perform before each request"""
    g.user = current_user
    if current_user.is_authenticated:
        session.permanent = True
        app.permanent_session_lifetime = timedelta(days=7)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Handle CSRF token errors"""
    logger.error(f"CSRF error occurred: {str(e)}")
    flash("Security error occurred. Please try again.", "error")
    return render_template('error.html', error="CSRF token validation failed"), 400

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    logger.error(f"404 error: {request.url}")
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    logger.error(f"500 error: {str(error)}")
    logger.error(traceback.format_exc())
    return render_template('error.html', error="Internal server error"), 500

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data.lower()).first()
        if user:
            raise ValidationError('Email already registered')
        
@app.route('/health')
def health_check():
    return jsonify({"status": "healthy"}), 200

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route"""
    if current_user.is_authenticated:
        return redirect(url_for('expense'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            if form.password.data != form.confirm_password.data:
                flash('Passwords do not match', 'error')
                return render_template('register.html', form=form)
            
            user = User(username=form.username.data, email=form.email.data.lower())
            user.set_password(form.password.data)
            
            db.session.add(user)
            db.session.commit()
            logger.info(f"New user registered: {user.username}")
            
            login_user(user)
            flash('Registration successful! Welcome to Finance Tracker.', 'success')
            return redirect(url_for('budget_setup'))
            
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
            logger.error(f"Registration error: {str(e)}")
            logger.error(traceback.format_exc())
            
    return render_template('register.html', form=form)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route"""
    if current_user.is_authenticated:
        return redirect(url_for('expense'))
        
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            logger.info(f"User logged in: {user.username}")
            
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('expense')
                
            flash('Login successful!', 'success')
            return redirect(next_page)
        else:
            flash('Invalid username or password', 'error')
            logger.warning(f"Failed login attempt for username: {form.username.data}")
            
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """User logout route"""
    username = current_user.username
    logout_user()
    logger.info(f"User logged out: {username}")
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/budget_setup', methods=['GET', 'POST'])
@login_required
def budget_setup():
    """Budget setup route"""
    if request.method == 'POST':
        month = request.form.get('month')
        budget_amount = request.form.get('budget')
        
        app.logger.debug(f"Received month: {month}, budget_amount: {budget_amount}")
        
        if not month or not budget_amount:
            flash('Month and amount are required', 'error')
            return redirect(url_for('budget_setup'))
        
        try:
            # Validate month format (YYYY-MM)
            datetime.strptime(month, '%Y-%m')
            
            # Validate budget amount
            amount = float(budget_amount)
            if amount <= 0:
                raise ValueError("Budget amount must be positive")
                
        except ValueError as e:
            flash(str(e) if "Budget amount" in str(e) else 'Amount must be a positive number', 'error')
            return redirect(url_for('budget_setup'))
        
        try:
            existing_budget = Budget.query.filter_by(
                user_id=current_user.id,
                month=month
            ).first()
            
            if existing_budget:
                existing_budget.amount = amount
                logger.info(f"Updated budget for {month}: {amount}")
                flash_message = 'Budget updated successfully!'
            else:
                new_budget = Budget(
                    month=month,
                    amount=amount,
                    user_id=current_user.id
                )
                db.session.add(new_budget)
                logger.info(f"Created new budget for {month}: {amount}")
                flash_message = 'Budget created successfully!'
            
            db.session.commit()
            flash(flash_message, 'success')
            return redirect(url_for('expense'))
            
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error in budget_setup: {str(e)}")
            flash('An error occurred while saving your budget. Please try again.', 'error')
            return redirect(url_for('budget_setup'))

    # Get existing budget for the current month if any
    current_month = datetime.now(timezone.utc).strftime('%Y-%m')
    existing_budget = Budget.query.filter_by(
        user_id=current_user.id,
        month=current_month
    ).first()
    
    # Ensure categories are defined
    categories = get_categories()
    if categories is None:
        categories = []

    return render_template('budget_setup.html', 
                          categories=categories, 
                          budget=existing_budget,
                          current_month=current_month)

@app.route('/')
@app.route('/expense')
@login_required
def expense():
    """Main expense tracking page"""
    categories = get_categories()
    if categories is None:
        categories = []

    app.logger.debug(f"Categories: {categories}")

    # Check if date parameter is provided
    selected_date = request.args.get('date')
    if selected_date:
        try:
            # Validate the date format
            datetime.fromisoformat(selected_date)
        except ValueError:
            # If invalid, ignore it and use current date
            selected_date = None
    
    # Get current month's budget
    if selected_date:
        budget_month = selected_date[:7]  # Extract YYYY-MM from YYYY-MM-DD
    else:
        budget_month = datetime.now(timezone.utc).strftime('%Y-%m')
    
    budget = Budget.query.filter_by(
        user_id=current_user.id,
        month=budget_month
    ).first()
    
    # If no budget exists, redirect to budget setup
    if not budget:
        flash('Please set up your monthly budget first', 'info')
        return redirect(url_for('budget_setup'))

    return render_template('expense.html', 
                          categories=categories,
                          budget=budget,
                          selected_date=selected_date)

def get_categories():
    """Function to return expense categories"""
    # Categories from CONTEXT.md
    return ["Auto", "Online Food", "College Mess", "Instamart", "Miscellaneous"]

@app.route('/api/expenses', methods=['POST'])
@login_required
def add_expense():
    """API endpoint to add new expenses"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        date_str = data.get('date')
        expenses = data.get('expenses', {})
        
        if not date_str:
            return jsonify({"error": "Date is required"}), 400
            
        if not expenses:
            return jsonify({"error": "No expense data provided"}), 400
        
        try:
            expense_date = datetime.fromisoformat(date_str).date()
        except ValueError:
            try:
                expense_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            except ValueError:
                return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
        
        # Delete existing expenses for this date
        Expense.query.filter_by(
            user_id=current_user.id,
            date=expense_date
        ).delete()
        
        # Add new expenses
        valid_categories = get_categories()
        for category, amount in expenses.items():
            if category not in valid_categories:
                logger.warning(f"Invalid category: {category}")
                continue
                
            try:
                amount = float(amount)
                if amount > 0:
                    expense = Expense(
                        date=expense_date,
                        category=category,
                        amount=amount,
                        user_id=current_user.id
                    )
                    db.session.add(expense)
            except (ValueError, InvalidOperation):
                logger.warning(f"Invalid amount for {category}: {amount}")
                continue
        
        db.session.commit()
        logger.info(f"Expenses saved for {date_str}")
        return jsonify({"message": "Expenses saved successfully"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving expenses: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/expenses', methods=['GET'])
@login_required
def get_expenses():
    """API endpoint to get expenses for a date range"""
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        if not start_date or not end_date:
            return jsonify({"error": "Both start_date and end_date are required"}), 400
        
        try:
            start = datetime.fromisoformat(start_date).date()
        except ValueError:
            try:
                start = datetime.strptime(start_date, '%Y-%m-%d').date()
            except ValueError:
                return jsonify({"error": "Invalid start_date format. Use YYYY-MM-DD"}), 400
            
        try:
            end = datetime.fromisoformat(end_date).date()
        except ValueError:
            try:
                end = datetime.strptime(end_date, '%Y-%m-%d').date()
            except ValueError:
                return jsonify({"error": "Invalid end_date format. Use YYYY-MM-DD"}), 400
        
        if start > end:
            return jsonify({"error": "start_date cannot be after end_date"}), 400
        
        expenses = Expense.query.filter(
            Expense.user_id == current_user.id,
            Expense.date >= start,
            Expense.date <= end
        ).all()
        
        expense_data = {}
        for expense in expenses:
            date_str = expense.date.strftime('%Y-%m-%d')
            if date_str not in expense_data:
                expense_data[date_str] = {}
            expense_data[date_str][expense.category] = expense.amount
        
        logger.debug(f"Retrieved expenses for period {start_date} to {end_date}")
        return jsonify(expense_data)

    except Exception as e:
        logger.error(f"Error retrieving expenses: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/budget', methods=['GET'])
@login_required
def get_budget():
    """API endpoint to get budget for a specific month"""
    try:
        month = request.args.get('month')
        if not month:
            return jsonify({"error": "Month parameter is required"}), 400
        
        try:
            # Validate month format
            datetime.strptime(month, '%Y-%m')
        except ValueError:
            return jsonify({"error": "Invalid month format. Use YYYY-MM"}), 400
        
        budget = Budget.query.filter_by(
            user_id=current_user.id,
            month=month
        ).first()
        
        if budget:
            logger.debug(f"Retrieved budget for {month}")
            return jsonify({"amount": budget.amount})
        else:
            logger.debug(f"No budget found for {month}")
            return jsonify({"amount": 0})
            
    except Exception as e:
        logger.error(f"Error retrieving budget: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/update_budget', methods=['POST'])
@login_required
def update_budget():
    """API endpoint to update or create a budget"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        month = data.get('month')
        budget_amount = data.get('budget')
        
        if not month or not budget_amount:
            return jsonify({"error": "Month and budget amount are required"}), 400
        
        try:
            # Validate month format
            datetime.strptime(month, '%Y-%m')
        except ValueError:
            return jsonify({"error": "Invalid month format. Use YYYY-MM"}), 400
            
        try:
            amount = float(budget_amount)
            if amount <= 0:
                return jsonify({"error": "Budget amount must be positive"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid budget amount"}), 400
            
        existing_budget = Budget.query.filter_by(
            user_id=current_user.id,
            month=month
        ).first()
        
        if existing_budget:
            existing_budget.amount = amount
            message = "Budget updated successfully"
        else:
            new_budget = Budget(
                month=month,
                amount=amount,
                user_id=current_user.id
            )
            db.session.add(new_budget)
            message = "Budget created successfully"
            
        db.session.commit()
        logger.info(f"{message} for {month}: {amount}")
        return jsonify({"message": message, "amount": amount})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating budget: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/summary')
@login_required
def summary():
    """Monthly expense summary page"""
    # Get current month
    current_month = datetime.now(timezone.utc).strftime('%Y-%m')
    
    # Check if budget exists for current month
    budget = Budget.query.filter_by(
        user_id=current_user.id,
        month=current_month
    ).first()
    
    if not budget:
        flash('Please set up your monthly budget first', 'info')
        return redirect(url_for('budget_setup'))
        
    return render_template('summary.html', current_month=current_month)

@app.route('/api/summary')
@login_required
def get_summary():
    """API endpoint to get summary data for a month"""
    try:
        month = request.args.get('month')
        if not month:
            return jsonify({"error": "Month parameter is required"}), 400
            
        try:
            # Validate month format
            datetime.strptime(month, '%Y-%m')
        except ValueError:
            return jsonify({"error": "Invalid month format. Use YYYY-MM"}), 400
            
        # Get budget for the month
        budget = Budget.query.filter_by(
            user_id=current_user.id,
            month=month
        ).first()
        
        budget_amount = budget.amount if budget else 0
        
        # Get all expenses for the month
        month_start = f"{month}-01"
        next_month = f"{int(month[:4]) + int(month[5:]) // 12}-{(int(month[5:]) % 12) + 1:02d}"
        month_end = f"{next_month}-01"
        
        try:
            start_date = datetime.strptime(month_start, '%Y-%m-%d').date()
            end_date = datetime.strptime(month_end, '%Y-%m-%d').date() - timedelta(days=1)
        except ValueError:
            return jsonify({"error": "Error calculating date range"}), 500
            
        expenses = Expense.query.filter(
            Expense.user_id == current_user.id,
            Expense.date >= start_date,
            Expense.date <= end_date
        ).all()
        
        # Calculate total spent and category breakdown
        total_spent = 0
        category_breakdown = {}
        
        for expense in expenses:
            total_spent += expense.amount
            if expense.category in category_breakdown:
                category_breakdown[expense.category] += expense.amount
            else:
                category_breakdown[expense.category] = expense.amount
                
        # Calculate remaining budget
        remaining_budget = budget_amount - total_spent
        
        # Prepare summary data
        summary_data = {
            "month": month,
            "budget": budget_amount,
            "total_spent": total_spent,
            "remaining_budget": remaining_budget,
            "category_breakdown": category_breakdown
        }
        
        logger.debug(f"Generated summary for {month}")
        return jsonify(summary_data)
        
    except Exception as e:
        logger.error(f"Error generating summary: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/calendar')
@login_required
def calendar():
    """Calendar view of expenses"""
    # Check if budget exists for current month
    current_month = datetime.now(timezone.utc).strftime('%Y-%m')
    budget = Budget.query.filter_by(
        user_id=current_user.id,
        month=current_month
    ).first()
    
    if not budget:
        flash('Please set up your monthly budget first', 'info')
        return redirect(url_for('budget_setup'))
        
    return render_template('calendar.html')

@app.route('/api/calendar_events')
@login_required
def get_calendar_events():
    """API endpoint to get expense data for calendar view"""
    try:
        start_date = request.args.get('start')
        end_date = request.args.get('end')
        
        if not start_date or not end_date:
            return jsonify({"error": "Both start and end parameters are required"}), 400
            
        try:
            # Handle different date formats that might come from FullCalendar
            # Remove timezone info if present
            if 'T' in start_date:
                start_date = start_date.split('T')[0]
            if 'T' in end_date:
                end_date = end_date.split('T')[0]
                
            start = datetime.strptime(start_date, '%Y-%m-%d').date()
            end = datetime.strptime(end_date, '%Y-%m-%d').date()
            
            logger.debug(f"Parsed date range: {start} to {end}")
        except ValueError as e:
            logger.error(f"Date parsing error: {str(e)}, start_date={start_date}, end_date={end_date}")
            return jsonify({"error": f"Invalid date format: {str(e)}"}), 400
            
        expenses = Expense.query.filter(
            Expense.user_id == current_user.id,
            Expense.date >= start,
            Expense.date <= end
        ).all()
        
        # Group expenses by date and category
        events = []
        date_totals = {}
        
        for expense in expenses:
            date_str = expense.date.strftime('%Y-%m-%d')
            
            # Track daily totals
            if date_str in date_totals:
                date_totals[date_str] += expense.amount
            else:
                date_totals[date_str] = expense.amount
                
            # Create event for each expense
            events.append({
                'title': f"{expense.category}: ₹{expense.amount:.2f}",
                'start': date_str,
                'category': expense.category,
                'amount': expense.amount
            })
            
        # Add daily total events
        for date_str, total in date_totals.items():
            events.append({
                'title': f"Total: ₹{total:.2f}",
                'start': date_str,
                'allDay': True,
                'display': 'background',
                'backgroundColor': '#4299e1',
                'isTotal': True
            })
            
        return jsonify(events)
        
    except Exception as e:
        logger.error(f"Error retrieving calendar events: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/system/db_status')
def db_status():
    """API endpoint to check database status - for debugging only"""
    try:
        # Check database connection
        db_type = str(db.engine.url).split('://')[0]
        
        # Check if tables exist
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        # Count users
        user_count = User.query.count()
        
        # Get database info
        status = {
            "status": "connected",
            "database_type": db_type,
            "tables": tables,
            "user_count": user_count,
            "environment": "production" if not app.debug else "development",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error checking database status: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 500

if __name__ == '__main__':
    # Create all database tables
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created successfully")
            
            # Verify database setup
            if verify_database():
                logger.info("Database verification successful")
            else:
                logger.error("Database verification failed")
        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")
            logger.error(traceback.format_exc())
    
    # Start the application
    if os.environ.get('FLASK_ENV') == 'production':
        # Render (bind to port 10000)
        port = int(os.environ.get('PORT', 10000))
        app.run(host='0.0.0.0', port=port)
    else:
        # Local (default port 5000)
        app.run(debug=True)
else:
    # When running with gunicorn or other WSGI server, initialize the database
    with app.app_context():
        try:
            # Check if database is PostgreSQL
            is_postgresql = str(db.engine.url).startswith('postgresql')
            logger.info(f"Production mode with {'PostgreSQL' if is_postgresql else 'SQLite'} database")
            
            # Create tables if they don't exist
            db.create_all()
            logger.info("Database tables created successfully in production mode")
            
            # Verify database setup
            if verify_database():
                logger.info("Database verification successful in production mode")
            else:
                logger.error("Database verification failed in production mode")
                
        except Exception as e:
            logger.error(f"Database initialization error in production mode: {str(e)}")
            logger.error(traceback.format_exc())