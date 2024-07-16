import streamlit as st
import requests
import hashlib
import sqlite3
from datetime import datetime, timedelta
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
INTEREST_RATE = 0.05
INTEREST_INTERVAL_DAYS = 3
MAX_LOAN = 10000

def backup_database():
    gauth = GoogleAuth()
    if os.path.exists("mycreds.txt"):
        gauth.LoadCredentialsFile("mycreds.txt")
    else:
        print("!")
        gauth.LocalWebserverAuth()
        gauth.SaveCredentialsFile("mycreds.txt")
    
    drive = GoogleDrive(gauth)
    gfile = drive.CreateFile({'title': os.path.basename(DATABASE+str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))})
    gfile.SetContentFile(DATABASE)
    gfile.Upload()
    return True

def load_database():
    gauth = GoogleAuth()
    gauth.LoadCredentialsFile("mycreds.txt")
    
    drive = GoogleDrive(gauth)
    file_list = drive.ListFile({'q': "title contains 'stock_data.db' and trashed=false"}).GetList()
    file_list.sort(key=lambda x: x['title'], reverse=True)
    file_list[0].GetContentFile(DATABASE)
    # close the connection to the database
    return True

if not os.path.exists(DATABASE):
    load_database()
    if not os.path.exists(DATABASE):
        from init import initialize
        initialize()

cookie_manager = stx.CookieManager()
# st.write(cookie_manager.get_all())

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
            second_last_entry = c.execute(f'SELECT timestamp, price FROM {self.dbname}_history ORDER BY timestamp DESC LIMIT 1 OFFSET 1').fetchone()
            if second_last_entry is None: second_last_entry = [-1, -1]
            if not last_entry or last_entry[1] != rating:
                self.db_conn.execute(f'INSERT INTO {self.dbname}_history (timestamp, price) VALUES (?, ?)', 
                                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), rating))
            elif last_entry[1] == rating == second_last_entry[1]:
                self.db_conn.execute(f'UPDATE {self.dbname}_history SET timestamp = ? WHERE timestamp = ?',
                                        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), last_entry[0]))
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
        
        c.execute(f'DELETE FROM {self.dbname}_history')
        
        for entry in filtered_history:
            self.db_conn.execute(f'INSERT INTO {self.dbname}_history (timestamp, price) VALUES (?, ?)', entry)
        
        self.db_conn.commit()

class Futures(Stock):
    def __init__(self, name, dbname, game_info, table, adjustment=0):
        self.name = name
        self.games = [
            (f"https://api.chess.com/pub/player/{username}/stats", gametype) for username, gametype in game_info
        ]
        self.dbname = dbname
        self.table = table
        self.adjustment = adjustment
        self.db_conn = get_db_connection()
        self.create_tables()

    def fetch_latest_rating(self):
        ratings = []
        try:
            for api_url, gametype in self.games:
                response = requests.get(api_url, headers={"User-Agent": "Mozilla/5.0"})
                data = response.json()
                if data[f'chess_{gametype}']['last']['rating']:
                    ratings.append(data[f'chess_{gametype}']['last']['rating'])
        except Exception as e:
            st.error(f"Error fetching data: {e}")
            return None
        return sum(r * x for r, x in zip(ratings, self.table)) + self.adjustment

# Initialize the stocks
STOCKS = [
    Stock('임재휘 불렛', 'bullet', "limbaksa"),
    Stock('송이안 블리츠', 'blitz', "tookavooo"),
    Stock('변상훈 래피드', 'rapid', "ekdn55"),
    Stock('조현욱 불렛', 'bullet', "telperion0715"),
    #Stock('송이안 불렛', 'bullet', "tookavooo"),
    Futures('빡송 합작', 'ppagsong', [("tookavooo", "bullet"), ("ppagse", "rapid")], [1, 1], -1500)
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
        else:
            stored_password_hash = existing_user[1]
            if stored_password_hash == password_hash:
                st.session_state['accounts'][username] = {'password': password_hash, 'money': existing_user[2], 'stocks': load_user_stocks(username)}
                st.success(f"Welcome back, {username}!")
                st.session_state['logged_in_user'] = username
                cookie_manager.set("username", username)
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

def getloan(username):
    c = conn.cursor()
    c.execute('SELECT loan_amount, loan_date FROM loans WHERE username=?', (username,))
    loan_data = c.fetchone()
    return loan_data

def getProperty(username):
    total_value = int(st.session_state['accounts'][username]['money'])
    for stock_name, quantity in load_user_stocks(username).items():
        for stock in STOCKS:
            if stock.name == stock_name:
                latest_price = stock.get_rating()
                if latest_price:
                    total_value += latest_price * quantity
    return total_value

# Function to display user profile
def display_profile():
    username = st.session_state['logged_in_user']
    if username is None:
        if cookie_manager.get("username"):
            username = cookie_manager.get("username")
            st.session_state['logged_in_user'] = username
        else:
            return handle_user()

    loan_data = getloan(username)
    loan_amount = loan_data[0] if loan_data else 0
    if loan_amount > 0:
        loan_date = datetime.strptime(loan_data[1], '%Y-%m-%d %H:%M:%S')
        days_since_loan = (datetime.now() - loan_date).days
        if days_since_loan >= INTEREST_INTERVAL_DAYS:
            interest_due = int(((days_since_loan // INTEREST_INTERVAL_DAYS) * INTEREST_RATE) * loan_amount)
            st.session_state['accounts'][username]['money'] -= interest_due
            st.warning(f"이자로 ${int(interest_due)}({int(INTEREST_RATE * 100)}%, {days_since_loan}일)를 뜯어갔습니다.")
            new_loan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            c = conn.cursor()
            c.execute('UPDATE loans SET loan_date=? WHERE username=?', (new_loan_date, username))
            c.execute('UPDATE accounts SET money=? WHERE username=?', (st.session_state['accounts'][username]['money'], username))
            conn.commit()

    user_data = st.session_state['accounts'][username]
    st.write(f"### {username}님의 포트폴리오")
    total_value = int(user_data['money'])
    total_value = getProperty(username)
    towrite = f"#### 보유금액: \${int(user_data['money'])}, 자산: \${total_value}"
    if loan_amount > 0:
        towrite += f", 빚: \${int(loan_amount)}"
    st.write(towrite)
    st.write("**자산 목록:**")
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
        own_str = ''
        if getloan(username) and getloan(username)[0] > 0:
            own_str += f'빚 ${int(getloan(username)[0])}, '
        own_str += ', '.join(f'{n.split()[0]} {owned[n]}' for n in owned if owned[n])
        if own_str and own_str[-1] == ' ': own_str = own_str[:-2]
        towrite = f"{i + 1}. {username}: \${int(total_value)}"
        if own_str: towrite += f"(\${int(money)}, {own_str})"
        st.write(towrite)

def display_bank():
    username = st.session_state['logged_in_user']

    # Fetch loan details
    loan_data = getloan(username)
    loan_amount = loan_data[0] if loan_data else 0
    loan_date = datetime.strptime(loan_data[1], '%Y-%m-%d %H:%M:%S') if loan_data else None

    st.subheader("노변김 캐피탈")
    st.write(f"노변김 캐피탈은 아주 유명한 제3금융권입니다. 이자율은 {int(INTEREST_RATE * 100)}%이며, {INTEREST_INTERVAL_DAYS}일마다 이자를 강탈해갑니다. 당신의 추정 자산의 50%까지만 빌려줄겁니다. 최대 대출액은 ${MAX_LOAN}입니다.")
    st.write(f"현재 대출: {'$' + str(int(loan_amount)) if loan_amount else '빚이 없습니다!'}")

    # Calculate interest if there's an existing loan
    if loan_amount > 0:
        days_since_loan = (datetime.now() - loan_date).days
        st.warning(f"대출일로부터 {days_since_loan}일이 지났습니다. 몸조심하세요.")

    # Taking a loan
    maxloan = int(getProperty(username) - loan_amount) // 2 - int(loan_amount)
    maxloan = max(min(maxloan, MAX_LOAN), 0)
    loan_amount_input = st.number_input(f"대출할 금액을 입력하세요 (최대 ${maxloan}):", min_value=0, max_value=maxloan, step=100)
    if st.button("대출 시도"):
        if loan_amount + loan_amount_input > maxloan:
            st.error(f"최대 대출액은 ${maxloan}입니다. 현재 대출액: ${loan_amount:.2f}")
        else:
            c = conn.cursor()
            if loan_data:
                c.execute('UPDATE loans SET loan_amount=?, loan_date=? WHERE username=?',
                          (loan_amount + loan_amount_input, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username))
            else:
                c.execute('INSERT INTO loans (username, loan_amount, loan_date) VALUES (?, ?, ?)',
                          (username, loan_amount + loan_amount_input, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            st.session_state['accounts'][username]['money'] += loan_amount_input
            c.execute('UPDATE accounts SET money=? WHERE username=?', 
                      (st.session_state['accounts'][username]['money'], username))
            conn.commit()
            st.success(f"${loan_amount_input}을 노변김 캐피탈에서 빌렸습니다. 몸조심하세요.")
    
    # Repaying the loan
    if loan_amount > 0:
        if st.button("빚 갚기"):
            if st.session_state['accounts'][username]['money'] < loan_amount:
                st.error("돈이 부족합니다.")
            else:
                st.session_state['accounts'][username]['money'] -= loan_amount
                c = conn.cursor()
                c.execute('UPDATE accounts SET money=? WHERE username=?', 
                        (st.session_state['accounts'][username]['money'], username))
                c.execute('DELETE FROM loans WHERE username=?', (username,))
                conn.commit()
                st.success(f"{username}는 이제 무료로 해줍니다!")


# Function to handle logout
def handle_logout():
    st.session_state['logged_in_user'] = None
    global cookie_manager
    cookie_manager = stx.CookieManager()
    cookie_manager.delete('username')
    cookie_manager = stx.CookieManager()
    handle_user()

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
        curr_st = 0
        try: curr_st = load_user_stocks(username)[stock_choice.name]
        except: pass
        c.execute('INSERT INTO user_stocks VALUES (?, ?, ?)',
                    (username, stock_choice.name, curr_st + quantity))
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
        global conn
        conn.close()
        for stock in STOCKS:
            stock.db_conn.close()
        for stock in STOCKS:
            stock.db_conn = get_db_connection()
        conn = get_db_connection()
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
    if st.button("Save Creds"):
        gauth = GoogleAuth()
        gauth.LocalWebserverAuth()
        gauth.SaveCredentialsFile("mycreds.txt")
        st.success("Credentials saved successfully.")


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
            menu = st.sidebar.selectbox("Menu", ["Ranking", "Overview", "Retrieve Password", "Delete Account", "Change User Password", "Update", "Stock Manager"])
            if menu == "Retrieve Password":
                display_account_info()
            elif menu == "Ranking":
                display_ranking()
            elif menu == "Overview":
                display_overview()
            elif menu == "Delete Account":
                delete_account()
            elif menu == "Change User Password":
                change_user_password()
            elif menu == "Update":
                admin_update()
            elif menu == "Stock Manager":
                admin_manager()
        else:
            menu = st.sidebar.selectbox("Menu", ["Notice", "Profile", "Trade", "Overview", "Ranking", "Bank", "Change Password"])
            if menu == "Notice":
                st.write("국가권력급 인재인 송이안님께서 개발해낸 주식 시뮬레이터입니다. 주식의 가격은 chess.com에서의 실제 체스 레이팅을 기반으로 합니다. 가끔 새로운 종목 등을 업데이트합니다.")
                st.write("레이팅을 직접 반영하는 주식 종목과 파생금융상품이 있습니다.")
                st.write("빡송합작은 아래 식으로 레이팅이 계산됩니다.")
                st.latex(r'rapid_{ppagse} + bullet_{tookavooo} - 1500')
            elif menu == "Profile":
                display_profile()
            elif menu == "Trade":
                stock_choice = st.selectbox("Select stock to trade", [stock.name for stock in STOCKS])
                current_st = None
                for sst in STOCKS:
                    if sst.name == stock_choice:
                        current_st = sst
                        sst.update_stock_values()
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
            elif menu == "Bank":
                display_bank()
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
