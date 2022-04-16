from flask import Flask, request, render_template 
from files import File
from data import Data
import sqlite3
from create_db import db_name
import json
import requests

app = Flask(__name__)
db_name = 'mydatabase.db'
user_hash = ""
data = ""

min_engine_malicious_status = 4

# This is the home route and it returns all the attributes 
# that is needed to be stored in the date base. We will display 
# them in the appropriate routes

@app.route('/',  methods = ['GET', 'POST'])
def get_User_Hash():
  if request.method == "POST":
    global user_hash                 #  A global variable to takes the user input(hash)
    user_hash = request.form['Id']
    Data.__init__(Data)
    check_hash = Data.search(Data, user_hash) # A check to see if the the hash exit in the database

    #if hash does not exist in the database, we call virus total else we get the details from the database
    if check_hash == None:

      url = "https://www.virustotal.com/api/v3/files/" + user_hash

      headers = {
      "Accept": "application/json",
      "x-apikey": "c749820807d2bef533708564acb0c49d970f2263b6633f99e04cc3a53c9cd7c8"
    }

      response = requests.request("GET", url, headers=headers)

      global data
      data = json.loads(response.text)

      size = get_size()
      File.size = get_size()
      File.md5_hash = get_md5()
      File.sha256_hash = get_sha256()
      File.sha1_hash = get_sha1()
      File.ssdeep_hash = get_ssdeep()
      File.total_malicious = get_Malicious()
      File.total_undetected = get_Undetected()
      File.is_malicious = get_isMaliciou()
      File.size = size
      engine_result = get_Engine()

      Data.store(Data, File)
      
      toPrint = Data.print_all(Data)

      #if the total_detected is more than the min_engine_malicious_status, 
      # that means the file has malware and we render the negative page else we render the positive page
      if File.total_malicious >= min_engine_malicious_status:
        return render_template('second_page_malware_negative.html', **locals(), **globals())
      else:
        return render_template('home.html', **locals(), **globals())
    else:
      #The get the information from the database
      toPrint = Data.print_all(Data)
      byId = Data.Select_byId(Data, user_hash)
      
      return render_template('database_positive.html', **locals())

  else:
    return render_template('added.html', **locals())


@app.route("/add")
def home():
  
  size = get_size()
  total_malicious = get_Malicious()
  total_undetected = get_Undetected()
  md5 = get_md5()
  sha256 = get_sha256()
  sha1 = get_sha1()
  ssdeep = get_ssdeep()
  Engine = get_Engine()
  displayed = display_datas()
  collected_hash = get_User_Hash()
  
  return render_template('front_page.html', **locals())

def get_size():
 
  d_size = data['data']['attributes']['size']

  return d_size

def get_Malicious():

  malicious = data['data']['attributes']['last_analysis_stats']['malicious']

  return malicious

def get_md5():

  d_md5 = data['data']['attributes']['md5']

  return d_md5

def get_sha256():

  sha_256 = data['data']['attributes']['sha256']

  return sha_256

def get_sha1():

  sha_1 = data['data']['attributes']['sha1']

  return sha_1

def get_isMaliciou():
  if get_Malicious == True:
    return True
  else:
    return False

def get_ssdeep():

  ss_deep = data['data']['attributes']['ssdeep']

  return ss_deep

def get_Undetected():

  undetected = data['data']['attributes']['last_analysis_stats']['undetected']

  return undetected

def get_Engine():

  engine = data['data']['attributes']['last_analysis_results']

  return engine

@app.route('/mydata', methods = ['GET', 'POST'])
def myhome():
  
  thisone = user_hash
  sha1 = get_sha1()

  return render_template('home.html', **locals())

def get_input_Hash():
  user_input = user_hash

  return user_input

def display_datas():
  conn = sqlite3.connect(db_name)
  cur = conn.cursor()
  cur.execute('''
  SELECT * FROM my_datas
  ''')
  test_data = cur.fetchall()
  return test_data

def insert_data(added_data):
  conn = sqlite3.connect(db_name)
  cur = conn.cursor()
  sql_exec = '''INSERT INTO my_datas (size, sha1) VALUES (?, ?);'''
  cur.execute(sql_exec, added_data)
  conn.commit()
  conn.close()

def add_data():

    added_data = get_size(), get_sha1()
    
    insert_data(added_data)

if __name__ == "__main__":
    app.run(debug=True)