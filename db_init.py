from app import app, db, init_db, recreate_tables
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def setup_database():
    """Setup database and create all tables"""
    with app.app_context():
        try:
            logger.info("Starting database setup...")
            recreate_tables()
            logger.info("Database setup completed successfully")
        except Exception as e:
            logger.error(f"Database setup failed: {str(e)}", exc_info=True)
            raise

if __name__ == "__main__":
    setup_database() 