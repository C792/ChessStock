import sqlite3
def initialize():
    DATABASE = 'stock_data.db'

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # Create the accounts table
    c.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            username TEXT PRIMARY KEY, 
            password TEXT, 
            money REAL
        )
    ''')

    # Create the user_stocks table
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_stocks (
            username TEXT, 
            stock_name TEXT, 
            quantity INTEGER,
            FOREIGN KEY (username) REFERENCES accounts (username)
        )
    ''')

    # Create the transactions table
    c.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            username TEXT,
            stock_name TEXT,
            quantity INTEGER,
            price REAL,
            timestamp TEXT
        )
    ''')

    conn.commit()
    conn.close()

    print("Database initialized.")
