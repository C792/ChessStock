import streamlit as st
import requests
import hashlib
import sqlite3
from datetime import datetime
import pandas as pd
import schedule
import time
import os
import extra_streamlit_components as stx

# Constants
STARTING_MONEY = 20000
ADMIN_USERNAME = "admin"
DATABASE = 'stock_data.db'

if not os.path.exists(DATABASE):
    from init import initialize
    initialize()

def get_manager():
    return stx.CookieManager()

cookie_manager = get_manager()

#st.subheader("All Cookies:")
#cookies = cookie_manager.get_all()
#st.write(cookies)


# Initialize session state for the logged-in user
if 'logged_in_user' not in st.session_state:
    st.session_state['logged_in_user'] = cookie_manager.get("username")

# Function to initialize database connection
def get_db_connection():
    return sqlite3.connect(DATABASE, check_same_thread=False)

# Initialize database connection
conn = get_db_connection()

# Stock class to handle each stock
class Stock:
    def __init__(self, name, gametype, username):
        self.name = name
        if not username:
            raise ValueError("username must be provided.")
        self.dbname = username + "_" + gametype
        self.api_url = f"https://api.chess.com/pub/player/{username}/stats"
        self.gametype = gametype
        self.db_conn = get_db_connection()
        self.create_tables()

    def create_tables(self):
        self.db_conn.execute(f'''
            CREATE TABLE IF NOT EXISTS {self.dbname}_history (
                timestamp TEXT, 
                price REAL
            )
        ''')
        self.db_conn.commit()

    def fetch_latest_rating(self):
        try:
            response = requests.get(self.api_url, headers={"User-Agent": "Mozilla/5.0"})
            data = response.json()
            return data[f'chess_{self.gametype}']['last']['rating']
        except Exception as e:
            st.error(f"Error fetching data: {e}")
            return None

    def update_stock_values(self):
        rating = self.fetch_latest_rating()
        if rating is not None:
            self.db_conn.execute(f'INSERT INTO {self.dbname}_history VALUES (?, ?)', 
                                 (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), rating))
            self.db_conn.commit()
        return rating

    def display_stock_history(self):
        c = self.db_conn.cursor()
        c.execute(f'SELECT timestamp, price FROM {self.dbname}_history ORDER BY timestamp ASC')
        history = c.fetchall()
        if history:
            df = pd.DataFrame(history, columns=["Time", "Rating"])
            df["Time"] = pd.to_datetime(df["Time"])
            df.set_index("Time", inplace=True)
            st.line_chart(df["Rating"])

# Initialize the stocks
stocks = [
    Stock('임재휘 불릿', 'bullet', "limbaksa"),
    Stock('송이안 블리츠', 'blitz', "tookavooo"),
    Stock('변상훈 래피드', 'rapid', "ekdn55"),
    Stock('조현욱 불릿', 'bullet', "telperion0715")
]

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to handle user login or registration
def handle_user():
    st.session_state['logged_in_user'] = None
    st.session_state['accounts'] = load_all_users()

    username = st.text_input("Enter your username:")
    password = st.text_input("Enter your password:", type='password')
    st.text("계정이 아직 없나요? 아이디와 비밀번호를 입력하면 계정 생성 버튼이 나타납니다.")
    
    if username and password:
        password_hash = hash_password(password)
        c = conn.cursor()
        c.execute('SELECT * FROM accounts WHERE username=?', (username,))
        existing_user = c.fetchone()
        if existing_user is None:
            if st.button("Register"):
                c.execute('INSERT INTO accounts VALUES (?, ?, ?)', 
                          (username, password_hash, STARTING_MONEY))
                conn.commit()
                st.session_state['accounts'][username] = {'password': password_hash, 'money': STARTING_MONEY, 'stocks': {}}
                st.success(f"Account created for {username} with ${STARTING_MONEY}.")
                st.session_state['logged_in_user'] = username
                cookie_manager.set("username", username)
                st.rerun()
        else:
            stored_password_hash = existing_user[1]
            if stored_password_hash == password_hash:
                st.session_state['accounts'][username] = {'password': password_hash, 'money': existing_user[2], 'stocks': load_user_stocks(username)}
                st.success(f"Welcome back, {username}!")
                st.session_state['logged_in_user'] = username
                cookie_manager.set("username", username)
                st.rerun()
            else:
                st.error("Incorrect password. Please try again.")
    return None

# Function to update user data in SQLite
def update_data(username):
    c = conn.cursor()
    user_data = st.session_state['accounts'][username]
    c.execute('UPDATE accounts SET money=? WHERE username=?', 
              (user_data['money'], username))
    c.execute('DELETE FROM user_stocks WHERE username=?', (username,))
    for stock_name, quantity in user_data['stocks'].items():
        c.execute('INSERT INTO user_stocks VALUES (?, ?, ?)', 
                  (username, stock_name, quantity))
    conn.commit()

# Function to load user data from SQLite
def load_user_data(username):
    c = conn.cursor()
    c.execute('SELECT * FROM accounts WHERE username=?', (username,))
    user_data = c.fetchone()
    if user_data:
        st.session_state['accounts'][username] = {'password': user_data[1], 'money': user_data[2], 
                                                  'stocks': load_user_stocks(username)}
    else:
        st.session_state['accounts'][username] = {'password': '', 'money': STARTING_MONEY, 
                                                  'stocks': {}}

# Function to load user stocks from SQLite
def load_user_stocks(username):
    c = conn.cursor()
    c.execute('SELECT stock_name, quantity FROM user_stocks WHERE username=?', (username,))
    stocks = c.fetchall()
    return {stock[0]: stock[1] for stock in stocks}

# Function to load all users data from SQLite
def load_all_users():
    c = conn.cursor()
    c.execute('SELECT * FROM accounts')
    users = c.fetchall()
    accounts = {}
    for user_data in users:
        accounts[user_data[0]] = {'password': user_data[1], 'money': user_data[2], 'stocks': load_user_stocks(user_data[0])}
    return accounts

# Function to display the overview of stocks
def display_overview():
    for stock in stocks:
        rating = stock.update_stock_values()
        st.write(f"Latest Rating of {stock.name.capitalize()}: {rating}")
        stock.display_stock_history()

# Function to display the ranking of users
def display_ranking():
    c = conn.cursor()
    c.execute('SELECT username, money FROM accounts WHERE username != ? ORDER BY money DESC', (ADMIN_USERNAME,))
    ranking = c.fetchall()
    st.write("User Rankings:")
    for i, (username, money) in enumerate(ranking):
        st.write(f"{i + 1}. {username}: ${int(money)}")

# Function to handle logout
def handle_logout():
    st.session_state['logged_in_user'] = None
    cookie_manager.delete('username')
    # st.rerun()

# Function to display account information for admin
def display_account_info():
    username = st.text_input("Enter the username to retrieve password:")
    if st.button("Retrieve Password"):
        c = conn.cursor()
        c.execute('SELECT password FROM accounts WHERE username=?', (username,))
        user_data = c.fetchone()
        if user_data:
            st.write(f"Password hash for {username}: {user_data[0]}")
        else:
            st.error("User not found.")

# Function to delete an account
def delete_account():
    username = st.text_input("Enter the username to delete:")
    if st.button("Delete Account"):
        c = conn.cursor()
        c.execute('DELETE FROM accounts WHERE username=?', (username,))
        c.execute('DELETE FROM user_stocks WHERE username=?', (username,))
        conn.commit()
        st.success(f"Deleted account for {username}")

# Function to change the password
def change_password():
    current_password = st.text_input("Enter your current password:", type='password')
    new_password = st.text_input("Enter your new password:", type='password')
    confirm_password = st.text_input("Confirm your new password:", type='password')
    if st.button("Change Password"):
        if new_password != confirm_password:
            st.error("New passwords do not match.")
            return

        user = st.session_state['logged_in_user']
        current_password_hash = hash_password(current_password)
        c = conn.cursor()
        c.execute('SELECT password FROM accounts WHERE username=?', (user,))
        user_data = c.fetchone()
        if user_data and user_data[0] == current_password_hash:
            new_password_hash = hash_password(new_password)
            c.execute('UPDATE accounts SET password=? WHERE username=?', (new_password_hash, user))
            conn.commit()
            st.success("Password changed successfully.")
        else:
            st.error("Current password is incorrect.")

# Function to change any user's password (admin only)
def change_user_password():
    username = st.text_input("Enter the username:")
    new_password = st.text_input("Enter the new password:", type='password')
    confirm_password = st.text_input("Confirm the new password:", type='password')
    if st.button("Change User Password"):
        if new_password != confirm_password:
            st.error("New passwords do not match.")
            return

        c = conn.cursor()
        c.execute('SELECT username FROM accounts WHERE username=?', (username,))
        user_data = c.fetchone()
        if user_data:
            new_password_hash = hash_password(new_password)
            c.execute('UPDATE accounts SET password=? WHERE username=?', (new_password_hash, username))
            conn.commit()
            st.success(f"Password for {username} changed successfully.")
        else:
            st.error("User not found.")

# Main app logic
def main():
    st.title("ChesStock")
    st.subheader("체스 레이팅으로 거래하는 주식")
    
    user = st.session_state['logged_in_user']
    if not user:
        user = cookie_manager.get("username")
    if user:
        st.sidebar.write(f"User: {user}")
        st.sidebar.button("Logout", on_click=handle_logout)

        if user == ADMIN_USERNAME:
            menu = st.sidebar.selectbox("Menu", ["Retrieve Password", "Delete Account", "Change User Password"])
            if menu == "Retrieve Password":
                display_account_info()
            elif menu == "Delete Account":
                delete_account()
            elif menu == "Change User Password":
                change_user_password()
        else:
            menu = st.sidebar.selectbox("Menu", ["Trade", "Overview", "Ranking", "Change Password"])
            if menu == "Trade":
                stock_choice = st.selectbox("Select stock to trade", [stock.name for stock in stocks])
                for sst in stocks:
                    if sst.name == stock_choice:
                        buy_price = sst.update_stock_values()
                st.subheader(f"현재 {stock_choice} 가격: {buy_price}")
                st.write(f"Current Balance: ${int(st.session_state['accounts'][user]['money'])}")

                # Buy stocks
                buy_quantity = st.number_input(f"Buy {stock_choice} stocks", min_value=1, step=1)
                # buy_price = stocks[0].update_stock_values() if stock_choice == 'hikaru' else stocks[1].update_stock_values()
                if st.button(f"Buy {stock_choice}"):
                    total_cost = buy_price * buy_quantity
                    if st.session_state['accounts'][user]['money'] >= total_cost:
                        st.session_state['accounts'][user]['money'] -= total_cost
                        if stock_choice in st.session_state['accounts'][user]['stocks']:
                            st.session_state['accounts'][user]['stocks'][stock_choice] += buy_quantity
                        else:
                            st.session_state['accounts'][user]['stocks'][stock_choice] = buy_quantity
                        c = conn.cursor()
                        c.execute('INSERT INTO transactions VALUES (?, ?, ?, ?, ?)', 
                                  (user, stock_choice, buy_quantity, buy_price, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                        conn.commit()
                        st.success(f"Bought {buy_quantity} stocks of {stock_choice} for ${total_cost}.")
                        update_data(user)
                        st.rerun()
                    else:
                        st.error("Insufficient funds.")

                # Sell stocks
                sell_quantity = st.number_input(f"Sell {stock_choice} stocks", min_value=1, step=1)
                if st.button(f"Sell {stock_choice}"):
                    if stock_choice in st.session_state['accounts'][user]['stocks'] and st.session_state['accounts'][user]['stocks'][stock_choice] >= sell_quantity:
                        revenue = buy_price * sell_quantity
                        st.session_state['accounts'][user]['money'] += revenue
                        st.session_state['accounts'][user]['stocks'][stock_choice] -= sell_quantity
                        c = conn.cursor()
                        c.execute('INSERT INTO transactions VALUES (?, ?, ?, ?, ?)', 
                                  (user, stock_choice, -sell_quantity, buy_price, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                        conn.commit()
                        st.success(f"Sold {sell_quantity} stocks of {stock_choice} for ${revenue}.")
                        update_data(user)
                        st.rerun()
                    else:
                        st.error("Insufficient stocks.")
                
                st.write(f"Owned Stocks ({stock_choice}): {st.session_state['accounts'][user]['stocks'].get(stock_choice, 0)}")
                st.write(f"Last updated: {time.ctime()}")
                stocks[0].display_stock_history() if stock_choice == 'hikaru' else stocks[1].display_stock_history()
            elif menu == "Overview":
                display_overview()
            elif menu == "Ranking":
                display_ranking()
            elif menu == "Change Password":
                change_password()
    else:
        handle_user()

# Schedule to update stock values every minute
def schedule_updates():
    schedule.every().minute.do(lambda: [stock.update_stock_values() for stock in stocks])
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    import threading
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    threading.Thread(target=schedule_updates).start()
    main()
