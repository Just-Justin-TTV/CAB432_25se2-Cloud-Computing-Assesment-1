import time
import MySQLdb
import os

# ----- Wait for Database -----
# Fetch database connection details from environment variables.
# If any variable is missing, use the default values specified below.
db_host = os.environ.get("DB_HOST", "db")
db_user = os.environ.get("DB_USER", "CAB432user")
db_pass = os.environ.get("DB_PASSWORD", "CAB432pass")
db_name = os.environ.get("DB_NAME", "CAB432db")

print("Waiting for database...")

# Keep attempting to connect to the database until it's ready.
# This loop handles the case where the database container may not be fully started yet.
while True:
    try:
        # Attempt to establish a connection using the provided credentials
        conn = MySQLdb.connect(host=db_host, user=db_user, passwd=db_pass, db=db_name)
        conn.close()  # Close immediately since we just want to check availability
        print("Database ready!")  # Successful connection, exit loop
        break
    except MySQLdb.OperationalError:
        # Connection failed (database not ready yet)
        print("Database not ready yet, retrying in 3 seconds...")
        time.sleep(3)  # Wait a bit before retrying to avoid spamming attempts
