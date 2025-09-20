import time
import psycopg2
import os

# Read database configuration from environment
db_host = os.environ.get("DB_HOST")
db_user = os.environ.get("DB_USER")
db_pass = os.environ.get("DB_PASSWORD")
db_name = os.environ.get("DB_NAME")
db_port = int(os.environ.get("DB_PORT", 5432))

print("Waiting for database...")

while True:
    try:
        conn = psycopg2.connect(
            host=db_host,
            user=db_user,
            password=db_pass,
            dbname=db_name,
            port=db_port,
            sslmode=os.environ.get("DB_SSLMODE", "require")
        )
        conn.close()
        print("Database ready!")
        break
    except psycopg2.OperationalError as e:
        print(f"Database not ready yet ({e}), retrying in 3 seconds...")
        time.sleep(3)
