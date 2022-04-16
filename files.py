# Stores file information into a file object
class File:
    def __init__(self, md5_hash, sha256_hash, sha1_hash, ssdeep_hash, total_malicious, total_undetected, is_malicious, size):
        self.md5_hash = md5_hash
        self.sha256_hash = sha256_hash
        self.sha1_hash = sha1_hash
        self.ssdeep_hash = ssdeep_hash
        self.total_malicious = total_malicious
        self.total_undetected = total_undetected
        self.is_malicious = is_malicious
        self.size = size
