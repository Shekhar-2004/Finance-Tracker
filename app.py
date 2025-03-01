from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask_login import UserMixin, LoginManager, login_required, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app with configurations
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///finance.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')

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
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    
    budgets = db.relationship('Budget', backref='user', lazy=True, cascade="all, delete-orphan")
    expenses = db.relationship('Expense', backref='user', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    month = db.Column(db.String(7))
    amount = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'month'),)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date)
    category = db.Column(db.String(50))
    amount = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Create tables
def init_db():
    with app.app_context():
        db.create_all()

# Initialize database
init_db()

# Authentication routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            if not all([username, email, password, confirm_password]):
                flash('All fields are required')
                return render_template('register.html', error='All fields are required')

            if password != confirm_password:
                flash('Passwords do not match')
                return render_template('register.html', error='Passwords do not match')

            if len(password) < 6:
                flash('Password must be at least 6 characters long')
                return render_template('register.html', error='Password must be at least 6 characters long')

            if User.query.filter_by(username=username).first():
                flash('Username already exists')
                return render_template('register.html', error='Username already exists')

            if User.query.filter_by(email=email).first():
                flash('Email already registered')
                return render_template('register.html', error='Email already registered')

            new_user = User(username=username, email=email)
            new_user.set_password(password)

            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            flash('Registration successful!')
            return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {str(e)}", exc_info=True)
            return render_template('register.html', error='An error occurred during registration. Please try again.')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        
        return render_template('login.html', error="Invalid username or password")
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
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

# Add this at the end of the file
if __name__ == '__main__':
    # Get port from environment variable or default to 10000
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)