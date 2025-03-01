from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session, g
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask_login import UserMixin, LoginManager, login_required, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, CSRFError
import logging
import os
import sys
import traceback
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from urllib.parse import urlparse
from decimal import Decimal, InvalidOperation
from sqlalchemy import inspect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length

# Initialize Flask app
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

# Enhanced logging configuration
logging.basicConfig(
    level=logging.DEBUG if app.debug else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('app.log')
    ]
)
logger = logging.getLogger(__name__)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Update the app configuration
app.config.update(
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///finance.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-key-change-this'),
    SESSION_COOKIE_SECURE=False,  # Changed to False for development
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    REMEMBER_COOKIE_SECURE=False,  # Changed to False for development
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_DURATION=timedelta(days=7),
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,  # 1 hour
    WTF_CSRF_SSL_STRICT=False  # Changed to False for development
)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database Models
class User(db.Model, UserMixin):
    """User model for authentication"""
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
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
    __tablename__ = 'expense'
    
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Expense {self.date} {self.category}: {self.amount}>'

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

def verify_database():
    """Verify database integrity and connectivity"""
    try:
        # Check if tables exist
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        app.logger.info(f"Database tables found: {tables}")
        
        # Count users
        user_count = User.query.count()
        app.logger.info(f"Total users in database: {user_count}")
        
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
    return jsonify({"error": "CSRF token validation failed"}), 400

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

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route"""
    if current_user.is_authenticated:
        return redirect(url_for('expense'))
    
    if request.method == 'POST':
        try:
            username = User.validate_username(request.form.get('username'))
            email = User.validate_email(request.form.get('email'))
            password = request.form.get('password')
            
            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'error')
                return render_template('register.html')
            
            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'error')
                return render_template('register.html')
            
            user = User(username=username, email=email)
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            logger.info(f"New user registered: {username}")
            
            login_user(user)
            return redirect(url_for('budget_setup'))
            
        except ValueError as e:
            flash(str(e), 'error')
            logger.warning(f"Registration validation error: {str(e)}")
        except Exception as e:
            flash('Registration failed. Please try again.', 'error')
            logger.error(f"Registration error: {str(e)}")
            logger.error(traceback.format_exc())
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route"""
    if current_user.is_authenticated:
        return redirect(url_for('expense'))
    
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username=form.username.data).first()
            if user and user.check_password(form.password.data):
                login_user(user, remember=form.remember_me.data)
                app.logger.info(f"User logged in successfully: {user.username}")
                
                next_page = request.args.get('next')
                if not next_page or urlparse(next_page).netloc != '':
                    next_page = url_for('expense')
                return redirect(next_page)
            else:
                flash('Invalid username or password', 'error')
                app.logger.warning(f"Failed login attempt for user: {form.username.data}")
        except Exception as e:
            flash('Login failed. Please try again.', 'error')
            app.logger.error(f"Login error: {str(e)}")
            app.logger.error(traceback.format_exc())
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """User logout route"""
    username = current_user.username
    logout_user()
    logger.info(f"User logged out: {username}")
    return redirect(url_for('login'))

@app.route('/budget_setup', methods=['GET', 'POST'])
@login_required
def budget_setup():
    """Budget setup route"""
    if request.method == 'POST':
        try:
            month = request.form.get('month')
            amount = request.form.get('amount')
            
            if not month or not amount:
                raise ValueError("Month and amount are required")
            
            try:
                amount = float(amount)
                if amount <= 0:
                    raise ValueError
            except (ValueError, InvalidOperation):
                raise ValueError("Amount must be a positive number")
            
            existing_budget = Budget.query.filter_by(
                user_id=current_user.id,
                month=month
            ).first()
            
            if existing_budget:
                existing_budget.amount = amount
                logger.info(f"Updated budget for {month}: {amount}")
            else:
                new_budget = Budget(
                    month=month,
                    amount=amount,
                    user_id=current_user.id
                )
                db.session.add(new_budget)
                logger.info(f"Created new budget for {month}: {amount}")
            
            db.session.commit()
            flash('Budget saved successfully!', 'success')
            return redirect(url_for('expense'))
            
        except ValueError as e:
            flash(str(e), 'error')
            logger.warning(f"Budget setup validation error: {str(e)}")
        except Exception as e:
            flash('Failed to save budget. Please try again.', 'error')
            logger.error(f"Budget setup error: {str(e)}")
            logger.error(traceback.format_exc())
    
    return render_template('budget_setup.html')

@app.route('/')
@app.route('/expense')
@login_required
def expense():
    """Main expense tracking page"""
    return render_template('expense.html')

@app.route('/api/expenses', methods=['POST'])
@login_required
def add_expense():
    """API endpoint to add new expenses"""
    try:
        data = request.get_json()
        if not data:
            raise ValueError("No data provided")
        
        date_str = data.get('date')
        expenses = data.get('expenses', {})
        
        try:
            expense_date = datetime.fromisoformat(date_str).date()
        except ValueError:
            expense_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        
        # Delete existing expenses for this date
        Expense.query.filter_by(
            user_id=current_user.id,
            date=expense_date
        ).delete()
        
        # Add new expenses
        for category, amount in expenses.items():
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
        return jsonify({"error": str(e)}), 400

@app.route('/api/expenses', methods=['GET'])
@login_required
def get_expenses():
    """API endpoint to get expenses for a date range"""
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        try:
            start = datetime.fromisoformat(start_date).date()
        except ValueError:
            start = datetime.strptime(start_date, '%Y-%m-%d').date()
            
        try:
            end = datetime.fromisoformat(end_date).date()
        except ValueError:
            end = datetime.strptime(end_date, '%Y-%m-%d').date()
        
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
        return jsonify({"error": str(e)}), 400

@app.route('/api/budget', methods=['GET'])
@login_required
def get_budget():
    """API endpoint to get budget for a specific month"""
    try:
        month = request.args.get('month')
        if not month:
            raise ValueError("Month parameter is required")
        
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
        return jsonify({"error": str(e)}), 400

@app.route('/summary')
@login_required
def summary():
    """Monthly expense summary page"""
    return render_template('summary.html')

@app.route('/calendar')
@login_required
def calendar():
    """Calendar view of expenses"""
    return render_template('calendar.html')

if __name__ == '__main__':
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Verify database setup
        if verify_database():
            logger.info("Database verification successful")
        else:
            logger.error("Database verification failed")
        
        # Start the application
        app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))