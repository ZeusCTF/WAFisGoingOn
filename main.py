import requests


#make the filtered request:
def filRequest():
    payload = {
        #data will theoretically be sent via this function after being parsed
    }
    r = requests.post("127.0.0.1:5000/login", data=payload)
    

