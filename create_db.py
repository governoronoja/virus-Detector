import sqlite3

db_name  = 'mydatabase.db'

conn = sqlite3.connect(db_name)
cur = conn.cursor()

cur.execute('''CREATE TABLE IF NOT EXISTS my_datas (
  size TEXT NOT NULL,
  sha1 TEXT NOT NULL);''')

conn.commit()
conn.close()