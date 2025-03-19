Finance Tracker

A modern, user-friendly web application designed to help you take control of your personal finances. Track your expenses, set monthly budgets, and gain valuable insights into your spending habits with intuitive visualizations and summaries.
🌟 Features

    User Authentication: Secure registration and login system.

    Monthly Budgets: Set and manage your monthly spending limits.

    Expense Tracking: Log daily expenses with customizable categories.

    Calendar View: Visualize your expenses on a calendar for better insights.

    Financial Summaries: Monthly summaries with charts to analyze your spending.

    Responsive Design: Works seamlessly on desktop, tablet, and mobile devices.

🚀 Live Demo

Access the live application here: Finance Tracker

⚠️ Important Note:
This application is hosted on Render's free tier. Due to server limitations, user data may be periodically deleted. For persistent data storage, it is recommended to clone the repository and run the application locally.
🛠️ Local Development
Prerequisites

    Python 3.11 or higher

    Pip (Python package manager)

Steps to Run Locally

    Clone the Repository:
    bash
    Copy

    git clone https://github.com/your-username/finance-tracker.git
    cd finance-tracker

    Install Dependencies:
    bash
    Copy

    pip install -r requirements.txt

    Set Up Environment Variables:
    Create a .env file in the root directory with the following content:
    plaintext
    Copy

    FLASK_ENV=development
    SECRET_KEY=your-secret-key

    Run the Application:
    bash
    Copy

    python app.py

    Access the Application:
    Open your browser and navigate to:
    http://localhost:5000

🚀 Render Deployment
Prerequisites

    A Render account

    A PostgreSQL database (free tier available)

Steps to Deploy

    Set Environment Variables in Render:

        FLASK_ENV: production

        DATABASE_URL: Your PostgreSQL connection string (from Render's database dashboard)

        SECRET_KEY: A secure secret key for session management

    Push Changes to GitHub:
    Render automatically deploys updates when changes are pushed to the linked repository.

    Access Your Live Application:
    Once deployed, your application will be available at the URL provided by Render.

🗃️ Database Configuration

The application supports two database systems:

    SQLite: Used for local development (default).

    PostgreSQL: Used for production deployments.

For Production

    Set the DATABASE_URL environment variable to your PostgreSQL connection string.
    Example:
    plaintext
    Copy

    DATABASE_URL=postgresql://user:password@host:5432/database

🔒 Environment Variables
Variable	Description
SECRET_KEY	A secret key for securing sessions (required).
DATABASE_URL	PostgreSQL connection string (required for production).
FLASK_ENV	Set to development for local development or production for deployment.
FLASK_DEBUG	Set to false in production for better performance and security.

📜 License

This project is licensed under the MIT License. Feel free to use, modify, and distribute it as per the license terms.
💡 Why Use This Application?

    Simple and Intuitive: Designed for ease of use, even for non-technical users.

    Customizable: Add your own expense categories and tailor the app to your needs.

    Open Source: Fully transparent codebase—contribute or customize as you see fit.

⚠️ Disclaimer

This application is hosted on Render's free tier, which has limitations on data persistence. User data may be deleted periodically. For a reliable experience, it is highly recommended to:

    Clone the repository.

    Run the application locally.

    Use a local or cloud-based PostgreSQL database for persistent storage.

🔗 Links

    Live Application: https://finance-tracker-pxk6.onrender.com

    GitHub Repository: https://github.com/Shekhar-2004/Finance-Tracker

🙏 Acknowledgments

    Built with Flask and SQLAlchemy.

    Hosted on Render.

    Inspired by the need for simple, effective personal finance tools.

Feel free to explore, contribute, or provide feedback! Happy budgeting! 🎉