import sqlite3

# Path to your SQLite database file
DB_PATH = 'jobtrack.db'

try:
    # Connect to the database
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    # Add the `profile_picture` column to the `info` table
    cursor.execute("ALTER TABLE info ADD COLUMN profile_picture TEXT")
    connection.commit()

    print("Column 'profile_picture' added successfully to the 'info' table.")
except sqlite3.OperationalError as e:
    # Handle errors (e.g., column already exists)
    if "duplicate column name" in str(e).lower():
        print("Column 'profile_picture' already exists.")
    else:
        print(f"An error occurred: {e}")
finally:
    connection.close()
