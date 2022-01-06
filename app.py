#This is the WAF/Reverse proxy project that will make me millions :^)

from flask import Flask, request, redirect, url_for
import requests
from requests.sessions import Request

app = Flask(__name__)
'''
Gather URL params
https://stackoverflow.com/questions/15974730/how-do-i-get-the-different-parts-of-a-flask-requests-url
'''
'''
Returning a response object?
https://stackoverflow.com/questions/19568950/return-a-requests-response-object-from-flask
'''

def info_gather(var):
    if request.method == 'GET':
        url = 'http://127.0.0.1:8080/' + var
        r = requests.get(url)
        return r.text
    elif request.method == 'POST':
        url = 'http://127.0.0.1:8080/' + var
        r = requests.post(url, data=request.form.to_dict(flat=False))
        return r.text

@app.route("/<reqPath>", methods=['GET','POST'])
def render(reqPath):
    return info_gather(reqPath)

#runs the app without having to set any of the env vars that are listed in the documentation
if __name__ == '__main__':
    app.run(debug=True)



