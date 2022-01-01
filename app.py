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

#create a model of the web server env:

def info_gather():
    uri = str(request.url_rule)
    print(request.method)
    print(str(request.url_rule))
    if request.method == 'GET':
        #print('yes')
        url = 'http://127.0.0.1:8080' + uri
        r = requests.get(url)
        print(r.text)

        #so we can return a redirect to the external URL with `redirect(url)` but this redirects them to the site, instead of having them submit requests through the proxy
        return redirect(url)



@app.route("/")
def main():
    info_gather()
    return ''


@app.route("/test")
def test():
    info_gather()
    return ""


@app.route("/home")
def home():
    info_gather()
    return ""


@app.route("/vault")
def vault():
    info_gather()
    return ""


@app.route("/login")
def login():
    return info_gather()
    





#runs the app without having to set any of the env vars that are listed in the documentation
if __name__ == '__main__':
    app.run(debug=True)



