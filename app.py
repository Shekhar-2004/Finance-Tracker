from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///finance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Models
class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    month = db.Column(db.String(7), unique=True)
    amount = db.Column(db.Float)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date)
    category = db.Column(db.String(50))
    amount = db.Column(db.Float)

# Create tables
with app.app_context():
    db.create_all()

# Routes
@app.route('/', methods=['GET', 'POST'])
def index():
    current_month = datetime.now().strftime('%Y-%m')
    budget = Budget.query.filter_by(month=current_month).first()
    if request.method == 'POST':
        amount = float(request.form['budget'])
        if budget:
            budget.amount = amount
        else:
            budget = Budget(month=current_month, amount=amount)
            db.session.add(budget)
        db.session.commit()
        return redirect(url_for('expense'))
    return render_template('budget_setup.html', budget=budget)

@app.route('/expense')
def expense():
    # Define categories
    categories = ['Auto', 'Online Food', 'College Mess', 'Instamart', 'Miscellaneous']
    
    # Get today's date
    today = datetime.now().date()
    
    # Get existing expenses for today
    expenses = Expense.query.filter_by(date=today).all()
    expense_dict = {e.category: e.amount for e in expenses}
    
    # Pass ALL required variables to the template
    return render_template(
        'expense.html',
        categories=categories,  # <-- Add this line
        expenses=expense_dict,
        today=today.isoformat()
    )

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
def get_expenses():
    start_date = request.args.get('start')
    end_date = request.args.get('end')
    
    if start_date and end_date:
        # Convert string dates to datetime objects
        start = datetime.strptime(start_date, '%Y-%m-%d').date()
        end = datetime.strptime(end_date, '%Y-%m-%d').date()
        
        # Query expenses between start and end dates
        expenses = Expense.query.filter(
            Expense.date >= start,
            Expense.date <= end
        ).all()
        
        # Group expenses by date
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
    
    # Handle single date query (for clicking on a specific date)
    date_str = request.args.get('date')
    if date_str:
        date = datetime.strptime(date_str, '%Y-%m-%d').date()
        expenses = Expense.query.filter_by(date=date).all()
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
def update_budget():
    try:
        data = request.get_json()
        new_budget = data.get('budget')
        
        if new_budget is None or new_budget <= 0:
            return jsonify({'message': 'Invalid budget amount'}), 400
            
        current_month = datetime.now().strftime('%Y-%m')
        budget = Budget.query.filter_by(month=current_month).first()
        
        if budget:
            budget.amount = new_budget
        else:
            budget = Budget(month=current_month, amount=new_budget)
            db.session.add(budget)
            
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Budget updated successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

if __name__ == '__main__':
     app.run(host='0.0.0.0', port=10000)