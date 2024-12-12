import sqlite3

# Path to your SQLite database file
DB_PATH = 'jobtrack.db'

try:
    # Connect to the database
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    # Check the schema of the `info` table
    cursor.execute("PRAGMA table_info(info)")
    columns = cursor.fetchall()

    # Print the table schema
    print("Table 'info' schema:")
    for column in columns:
        print(column)
finally:
    connection.close()
