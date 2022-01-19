#This is the WAF/Reverse proxy project that will make me millions :^)
from logging.config import valid_ident
from flask import Flask, request
import requests

app = Flask(__name__)
'''
Gather URL params
https://stackoverflow.com/questions/15974730/how-do-i-get-the-different-parts-of-a-flask-requests-url
'''
'''
Returning a response object?
https://stackoverflow.com/questions/19568950/return-a-requests-response-object-from-flask
'''

def input_validation():
    X = {'userName': ['superMan'], 'password': ['superman']}
    



def info_gather(var):
    if request.method == 'GET':
        session = requests.Session()
        url = 'http://127.0.0.1:8000/' + var
        html = session.get(url).content
        return html
    elif request.method == 'POST':
        print(request.form.to_dict(flat=False))
        url = 'http://127.0.0.1:8000/' + var
        r = requests.post(url, data=request.form.to_dict(flat=False))
        return r.text


@app.route("/<reqPath>", methods=['GET','POST'])
def render(reqPath):
    #returning the {'Server':'127.0.0.1:8080'} header removes some server information that could be helpful for anyone trying to fingerprint the underlying server
    return info_gather(reqPath), {'Server':'127.0.0.1:5000'}


@app.route('/')
def main():
    #url = 'https://www.tesla.com'
    url = 'http://127.0.0.1:8000/'
    r = requests.get(url)
    return r.text, {'Server':'127.0.0.1:5000'}

#runs the app without having to set any of the env vars that are listed in the documentation
if __name__ == '__main__':
    app.run(debug=True)



