# Finance Tracker

A web application for tracking personal finances, including expenses, budgets, and financial summaries.

## Features

- User registration and authentication
- Monthly budget setting
- Expense tracking with categories
- Calendar view of expenses
- Monthly summary with charts
- Responsive design

## Local Development
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Create a `.env` file:
   ```plaintext
   FLASK_ENV=development
   SECRET_KEY=your-secret-key
   ```
3. Run the app:
   ```bash
   python app.py
   ```
4. Access at: `http://localhost:5000`

## Render Deployment
1. Set environment variables in Render:
   ```plaintext
   FLASK_ENV=production
   DATABASE_URL=your-postgres-url
   SECRET_KEY=your-secret-key
   ```
2. Push changes to GitHub to trigger deployment.

## Database Configuration

The application supports both SQLite (development) and PostgreSQL (production):

- For local development, SQLite is used by default
- For production, set the `DATABASE_URL` environment variable to your PostgreSQL connection string

## Environment Variables

- `SECRET_KEY`: Used for session security (required)
- `DATABASE_URL`: PostgreSQL connection string (for production)
- `FLASK_DEBUG`: Set to "false" in production

## License

MIT
