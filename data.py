import sqlite3
from files import File

class Data:
    def __init__(self):
        #the number of files touched in the session, includes files that have been searched before
        self.num_this_session = 0
        #connection to the database
        self.conn = sqlite3.connect('proj_data.db', check_same_thread = False)
        #cursor for the database
        self.c = self.conn.cursor()

        #Create the table only once
        self.c.execute("""CREATE TABLE IF NOT EXISTS files (
                                        md5 text,
                                        sha256 text,
                                        sha1 text,
                                        ssdeep text,
                                        malicious integer,
                                        undetected integer,
                                        is_bad integer,
                                        size integer
                                        )""")


    #Given a file object, store all of the information in the database
    def store(self, the_file):
        #use context manager to automatically commit changes to the database
        with self.conn:
            self.c.execute("""INSERT INTO files VALUES (:md5, :sha256, :sha1, :ssdeep,
                                                        :malicious, :undetected, :is_bad, :size)""",
                                                        {'md5':the_file.md5_hash, 'sha256':the_file.sha256_hash,
                                                         'sha1':the_file.sha1_hash, 'ssdeep':the_file.ssdeep_hash,
                                                         'malicious':the_file.total_malicious,
                                                         'undetected':the_file.total_undetected,
                                                         'is_bad':the_file.is_malicious, 'size':the_file.size})
        self.num_this_session += 1

    #Given a hash name, search each of the possible hash values for a single file and return a file object containing
    #the relevant information. If no file matches, return None
    def search(self, hash_name):
        self.c.execute("SELECT * FROM files WHERE md5=:hash OR sha256=:hash OR sha1=:hash OR ssdeep=:hash",
                       {'hash':hash_name})
        record = self.c.fetchone()
        if record is None:
            #do not increase num_this_session because no file is touched if it isn't found
            #if not found, the total will be incremented when the file is stored
            return None
        else:
            #extract info from the tuple and store in file object
            md5, sha256, sha1, ssdeep, mal, und, is_mal, size = record
            the_file = File(md5_hash=md5, sha256_hash=sha256, sha1_hash=sha1, ssdeep_hash=ssdeep,
                            total_malicious=mal, total_undetected=und, is_malicious=is_mal, size=size)
            self.num_this_session += 1
            return the_file

    #prints all rows in the database, mostly used for debugging
    def print_all(self):
        self.c.execute("SELECT * FROM files")
        data = self.c.fetchall()
        return data
        #for x in data:
          #  print(x)

    def Select_byId(self, hash_name):
        self.c.execute("SELECT * FROM files where md5=:hash", {'hash':hash_name})
        data = self.c.fetchall()
        return data

