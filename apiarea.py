'''
This lines are comments.
After copying the API request function from Virus Total, the file was modified.
1 - We import json, and the reason for that was to load the response in json format. 
2 - We can set parameter if we want an only the attributes with the set parameter will be displayed.

'''
#Make this a class

import requests
import json

class virusRespose:

  def VTresponse(self):
    
    
    url = "https://www.virustotal.com/api/v3/files/f427567a0ab47880ed224c6948af9989"

    parameters = {

      'attribute' : 'size'
    }
    headers = {
      "Accept": "application/json",
      "x-apikey": "4ea24321e6e93aa4e19a1732d6348ed0bc67310ee85efe91e316d8072fba65c4"
    }

    response = requests.request("GET", url, params=parameters, headers=headers)

    data = json.loads(response.text)

    return data





