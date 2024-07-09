import streamlit as st
import requests
import hashlib
import sqlite3
from datetime import datetime
import pandas as pd
import schedule
import time
import os
import altair as alt
import extra_streamlit_components as stx
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive

# Constants
STARTING_MONEY = 20000
ADMIN_USERNAME = "admin"
DATABASE = 'stock_data.db'

def backup_database():
    gauth = GoogleAuth()
    gauth.LoadCredentialsFile("mycreds.txt")
    
    drive = GoogleDrive(gauth)
    gfile = drive.CreateFile({'title': os.path.basename(DATABASE+str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))})
    gfile.SetContentFile(DATABASE)
    gfile.Upload()
    return True

def load_database():
    gauth = GoogleAuth()
    gauth.LoadCredentialsFile("mycreds.txt")
    
    drive = GoogleDrive(gauth)
    # from the files with the title such like 'stock_data.db2024-07-09 04:35:31', get the latest one
    file_list = drive.ListFile({'q': "title contains 'stock_data.db' and trashed=false"}).GetList()
    file_list.sort(key=lambda x: x['title'], reverse=True)
    file_list[0].GetContentFile(DATABASE)
    return True

if not os.path.exists(DATABASE):
    load_database()
    if not os.path.exists(DATABASE):
        from init import initialize
        initialize()

def get_manager():
    return stx.CookieManager()

cookie_manager = get_manager()

# Initialize session state for the logged-in user
if 'logged_in_user' not in st.session_state:
    st.session_state['logged_in_user'] = cookie_manager.get("username")

# Function to initialize database connection
def get_db_connection():
    return sqlite3.connect(DATABASE, check_same_thread=False)

# Initialize database connection and threading lock
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
            c = self.db_conn.cursor()
            c.execute(f'SELECT timestamp, price FROM {self.dbname}_history ORDER BY timestamp DESC LIMIT 1')
            last_entry = c.fetchone()

            if not last_entry or last_entry[1] != rating:
                if last_entry:
                    # Update the timestamp of the last same value entry before the change
                    self.db_conn.execute(f'UPDATE {self.dbname}_history SET timestamp = ? WHERE timestamp = ?',
                                         (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), last_entry[0]))
                # Insert the new value
                self.db_conn.execute(f'INSERT INTO {self.dbname}_history (timestamp, price) VALUES (?, ?)', 
                                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), rating))
                self.db_conn.commit()
        return rating

    def get_rating(self):
        c = self.db_conn.cursor()
        c.execute(f'SELECT price FROM {self.dbname}_history ORDER BY timestamp DESC LIMIT 1')
        rating = c.fetchone()
        return int(rating[0]) if rating else None

    def display_stock_history(self):
        c = self.db_conn.cursor()
        c.execute(f'SELECT timestamp, price FROM {self.dbname}_history ORDER BY timestamp ASC')
        history = c.fetchall()
        if history:
            df = pd.DataFrame(history, columns=["Time", "Rating"])
            df["Time"] = pd.to_datetime(df["Time"])
            df.set_index("Time", inplace=True)
            chart = alt.Chart(df.reset_index()).mark_line().encode(
                x='Time',
                y=alt.Y('Rating', scale=alt.Scale(zero=False)),
            )
            st.altair_chart(chart, use_container_width=True)
        print(len(history))
    
    def compress_db(self):
        c = self.db_conn.cursor()
        c.execute(f'SELECT timestamp, price FROM {self.dbname}_history ORDER BY timestamp ASC')
        history = c.fetchall()
        
        if not history: return
        
        filtered_history = []
        last_price = history[0][1]
        filtered_history.append(history[0])
        
        for i in range(1, len(history)):
            if history[i][1] != last_price:
                filtered_history.append(history[i - 1])
                filtered_history.append(history[i])
                last_price = history[i][1]
        filtered_history.append(history[-1])
        
        self.db_conn.execute(f'DELETE FROM {self.dbname}_history')
        
        for entry in filtered_history:
            self.db_conn.execute(f'INSERT INTO {self.dbname}_history (timestamp, price) VALUES (?, ?)', entry)
        
        self.db_conn.commit()

# Initialize the stocks
STOCKS = [
    Stock('임재휘 불렛', 'bullet', "limbaksa"),
    Stock('송이안 블리츠', 'blitz', "tookavooo"),
    Stock('변상훈 래피드', 'rapid', "ekdn55"),
    Stock('조현욱 불렛', 'bullet', "telperion0715"),
    Stock('송이안 불렛', 'bullet', "tookavooo"),
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
    
    if username and password or st.button("Login"):
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
                st.text("비밀번호를 잊으셨나요? 관리자에게 문의하세요.")
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
    # in user_stocks, remove stocks with quantity 0
    c.execute('DELETE FROM user_stocks WHERE quantity=0')
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

# Function to display user portfolio
def display_portfolio():
    username = st.session_state['logged_in_user']
    if username is None:
        st.error("You must be logged in to view your portfolio.")
        return

    user_data = st.session_state['accounts'][username]
    st.write(f"### Portfolio of {username}")
    st.write(f"**Money:** ${int(user_data['money'])}")
    st.write("**Stocks:**")
    for stock_name, quantity in user_data['stocks'].items():
        st.write(f"- {stock_name}: {quantity} shares")

# Function to display the overview of stocks
def display_overview():
    for stock in STOCKS:
        rating = stock.update_stock_values()
        st.write(f"Latest Rating of {stock.name.capitalize()}: {rating}")
        stock.display_stock_history()

# Function to display the ranking of users
def display_ranking():
    c = conn.cursor()
    c.execute('SELECT username, money FROM accounts WHERE username != ? ORDER BY money DESC', (ADMIN_USERNAME,))
    ranking = c.fetchall()
    ranking_data = []
    for username, money in ranking:
        owned = {}
        user_stocks = load_user_stocks(username)
        total_value = money
        for stock_name, quantity in user_stocks.items():
            owned[stock_name] = quantity
            for stock in STOCKS:
                if stock.name == stock_name:
                    latest_price = stock.get_rating()
                    if latest_price:
                        total_value += latest_price * quantity
        ranking_data.append((username, total_value, owned, money))
    ranking_data.sort(key=lambda x: (x[1], x[3]), reverse=True)
    st.write("User Rankings:")
    for i, (username, total_value, owned, money) in enumerate(ranking_data):
        own_str = ', '.join(f'{n.split()[0]} {owned[n]}' for n in owned if owned[n])
        towrite = f"{i + 1}. {username}: \${int(total_value)}"
        if own_str: towrite += f"(\${int(money)}, {own_str})"
        st.write(towrite)


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

# Function to clear all stocks of a specific user
def clear_user_stocks(username):
    c = conn.cursor()
    c.execute('DELETE FROM user_stocks WHERE username=?', (username,))
    conn.commit()
    st.success(f"Cleared all stocks for {username}")

# Function to give specific amount of any stock to a user
def grant_stocks(username, stock_choice, quantity):
    if stock_choice:
        c = conn.cursor()
        c.execute('INSERT INTO user_stocks VALUES (?, ?, ?)',
                    (username, stock_choice.name, quantity))
        conn.commit()
        st.success(f"Granted {quantity} of {stock_choice.name} to {username}")
        return
    st.error("Stock not found.")

# Function to manage user balance
def manage_user_balance(username, amount, absv=True):
    if not username:
        st.error("Enter a username.")
        return
    c = conn.cursor()
    if absv:
        c.execute('UPDATE accounts SET money=? WHERE username=?', 
                    (amount, username))
        st.success(f"{username}'s balance has been set to ${abs(amount)} successfully.")
    else:
        c.execute('UPDATE accounts SET money=money+? WHERE username=?', 
                    (amount, username))
        action = "added to" if amount > 0 else "deducted from"
        st.success(f"${abs(amount)} has been {action} {username}'s balance")
    conn.commit()

def admin_update():
    if st.button("Update!!"):
        st.cache_resource.clear()
        st.success("Updated successfully.")
        schedule_updates()
    if st.button("COMPRESS!!"):
        for stock in STOCKS:
            stock.compress_db()
        st.success("Changes filtered and saved successfully.")
    if st.button("Backup Database"):
        if backup_database(): st.success(f"Database backup uploaded to Google Drive successfully.")
    if st.button("Load Database"):
        if load_database(): st.success(f"Database loaded from Google Drive successfully.")


def admin_manager():
    st.subheader("Clear User Stocks")
    username_clear = st.text_input("Enter the username to clear stocks:")
    if st.button("Clear Stocks"):
        clear_user_stocks(username_clear)

    st.subheader("Give User Stocks")
    username_give = st.text_input("Enter the username to give stocks:")
    stock_name = st.selectbox("Select stock", [stock.name for stock in STOCKS])
    for i in STOCKS:
        if i.name == stock_name:
            selected_stock = i
            break
    quantity = st.number_input("Enter quantity to give:", min_value=1, step=1)
    if st.button("Give Stocks"):
        grant_stocks(username_give, selected_stock, quantity)
    st.subheader("Manage User Balance")
    username_balance = st.text_input("Enter the username to manage balance:")
    amount = st.number_input("Enter amount to add/deduct (use negative for deduction):", step=100)
    if st.button("Update Balance"):
        manage_user_balance(username_balance, amount, absv=False)
    if st.button("Set balance"):
        manage_user_balance(username_balance, amount)

# Update the main function to include the admin page
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
            global stop_threads
            # stop_threads = True
            menu = st.sidebar.selectbox("Menu", ["Ranking", "Retrieve Password", "Delete Account", "Change User Password", "Update", "Stock Manager"])
            if menu == "Retrieve Password":
                display_account_info()
            elif menu == "Ranking":
                display_ranking()
            elif menu == "Delete Account":
                delete_account()
            elif menu == "Change User Password":
                change_user_password()
            elif menu == "Update":
                admin_update()
            elif menu == "Stock Manager":
                admin_manager()
        else:
            menu = st.sidebar.selectbox("Menu", ["Profile", "Trade", "Overview", "Ranking", "Change Password"])
            if menu == "Profile":
                display_portfolio()
            elif menu == "Trade":
                stock_choice = st.selectbox("Select stock to trade", [stock.name for stock in STOCKS])
                current_st = None
                for sst in STOCKS:
                    if sst.name == stock_choice:
                        current_st = sst
                        buy_price = sst.get_rating()
                st.subheader(f"현재 {stock_choice} 가격: {buy_price}")
                st.write(f"Current Balance: ${int(st.session_state['accounts'][user]['money'])}")

                # Buy stocks
                buy_quantity = st.number_input(f"Buy {stock_choice} stocks", min_value=1, step=1)
                if st.button(f"Buy {stock_choice} (-${buy_price*buy_quantity})"):
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
                if st.button(f"Sell {stock_choice} (+${buy_price*sell_quantity})"):
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
                current_st.display_stock_history()
            elif menu == "Overview":
                display_overview()
            elif menu == "Ranking":
                display_ranking()
            elif menu == "Change Password":
                change_password()
    else:
        handle_user()


# Schedule to update stock values every minute
@st.cache_resource()
def schedule_updates():
    schedule.every(10).minutes.do(lambda: [stock.update_stock_values() for stock in STOCKS])
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    main()
