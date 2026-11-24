import sqlite3


connection = sqlite3.connect(
    "report/vulnx.db"
)

tables = connection.execute(
    "PRAGMA table_list"
).fetchall()

print("DATABASE TABLES:")

for table in tables:
    print(table)

print("\nMETASPLOIT MODULES SCHEMA:")

columns = connection.execute(
    "PRAGMA table_info(metasploit_modules)"
).fetchall()

for column in columns:
    print(column)

connection.close()