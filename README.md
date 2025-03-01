# Finance Tracker

A web application for tracking personal finances, including expenses, budgets, and financial summaries.

## Features

- User registration and authentication
- Monthly budget setting
- Expense tracking with categories
- Calendar view of expenses
- Monthly summary with charts
- Responsive design

## Local Development Setup

1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the application:
   ```
   python app.py
   ```
4. Access the application at http://localhost:5000

## Database Configuration

The application supports both SQLite (development) and PostgreSQL (production):

- For local development, SQLite is used by default
- For production, set the `DATABASE_URL` environment variable to your PostgreSQL connection string

## Deployment to Render

This application is configured for deployment on Render:

1. Push your code to a Git repository
2. In Render dashboard, create a new Web Service
3. Connect to your repository
4. Render will automatically detect the configuration from `render.yaml`
5. The application will be deployed with a PostgreSQL database

## Environment Variables

- `SECRET_KEY`: Used for session security (required)
- `DATABASE_URL`: PostgreSQL connection string (for production)
- `FLASK_DEBUG`: Set to "false" in production

## License

MIT
