import time
import MySQLdb
import os

db_host = os.environ.get("DB_HOST", "db")
db_user = os.environ.get("DB_USER", "CAB432user")
db_pass = os.environ.get("DB_PASSWORD", "CAB432pass")
db_name = os.environ.get("DB_NAME", "CAB432db")

print("Waiting for database...")

while True:
    try:
        conn = MySQLdb.connect(host=db_host, user=db_user, passwd=db_pass, db=db_name)
        conn.close()
        print("Database ready!")
        break
    except MySQLdb.OperationalError:
        print("Database not ready yet, retrying in 3 seconds...")
        time.sleep(3)
