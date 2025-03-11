import logging
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def home():
    return 'Hello, Flask!'


@app.route('/execute', methods=['POST'])
def execute_sql():
    data = request.get_json(silent=True) or {}
    sql_command = data.get('sql')
    logging.basicConfig(level=logging.INFO)
    logging.info(f"Executing SQL: {sql_command}")
    if not sql_command:
        return jsonify({'error': 'No SQL command provided'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        _ = cursor.execute(sql_command)
        conn.commit()
        conn.close()
        return jsonify({'message': 'SQL command executed successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    conn = get_db_connection()
    _ = conn.execute('CREATE TABLE IF NOT EXISTS example (id INTEGER PRIMARY KEY, name TEXT)')  # noqa: E501
    conn.commit()
    conn.close()
    app.run(debug=True)  # noqa: S201


# from typing import Any
# import os
# import hashlib
# import subprocess
# import sqlite3
# import base64
# import logging
# import unittest
# import coverage
# import sys


# API_KEY = "hardcodedsecretkey"
# DATABASE_PASSWORD = "password123"


# def infinite_recursion():
#     return infinite_recursion()

# def memory_leak() -> None:
#     data = [0] * 10**6
#     return memory_leak()


# class SonarqubeChallenges:
#     def run_command(self, command: str) -> None:
#         _ = os.system(command)  # noqa: S605

#     # SQL Injection vulnerability
#     def get_user_data(self, user_id: str) -> list[object]:
#         conn = sqlite3.connect('database.db')
#         cursor = conn.cursor()
#         query = f"SELECT * FROM users WHERE user_id = '{user_id}'"
#         _ = cursor.execute(query)
#         return cursor.fetchall()

#     def get_user_data_2(self, command: str) -> list[object]:
#         conn = sqlite3.connect('database.db')
#         cursor = conn.cursor()
#         _ = cursor.execute(command)
#         return cursor.fetchall()

#     # Weak password storage
#     def store_password(self, password: str):
#         with open("passwords.txt", "a") as file:
#             _ = file.write(password + "\n")

#     # Use of insecure hashing algorithm (MD5)
#     def hash_password(self, password: str):
#         return hashlib.md5(password.encode()).hexdigest()

#     # Use of base64 for encoding sensitive data (insecure)
#     def encode_sensitive_data(self, data: str):
#         encoded_data = base64.b64encode(data.encode())
#         return encoded_data

#     # Insecure logging of sensitive data
#     logging.basicConfig(level=logging.DEBUG)
#     def log_sensitive_data(self):
#         logging.debug(f"Logging sensitive data: {API_KEY}")

#     # Insecure file permissions
#     def write_to_file(self):
#         with open("insecure_file.txt", "w") as file:
#             _ = file.write("Sensitive data")

#     # Improper exception handling (generic)
#     def process_data(self):
#         try:
#             risky_code = 1 / 0
#             _ = risky_code
#         except Exception as e:
#             print("An error occurred:", e)

#     # Command injection vulnerability example
#     def inject_command(self):
#         user_input = ""
#         self.run_command(user_input)

#     def add(self, a: int, b: int) -> int:
#         return a+b

# # Call all functions to execute them
# if __name__ == "__main__":
#     memory_leak()
#     infinite_recursion()
#     t = SonarqubeChallenges()
#     t.run_command("echo Hello World")
#     t.store_password("mysecretpassword")
#     _ = t.hash_password("password123")
#     _ = t.encode_sensitive_data("secretdata")
#     t.log_sensitive_data()
#     t.write_to_file()
#     t.process_data()
#     t.inject_command()
