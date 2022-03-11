#This is the WAF/Reverse proxy project that will make me millions :^)
from logging.config import valid_ident
from os import environ
import re
from flask import Flask, request
import requests

app = Flask(__name__)

def injection_dectector(userPayload, passPayload):
    import math
    import re
    from collections import Counter

    WORD = re.compile(r"\w+")


    def get_cosine(vec1, vec2):
        intersection = set(vec1.keys()) & set(vec2.keys())
        numerator = sum([vec1[x] * vec2[x] for x in intersection])

        sum1 = sum([vec1[x] ** 2 for x in list(vec1.keys())])
        sum2 = sum([vec2[x] ** 2 for x in list(vec2.keys())])
        denominator = math.sqrt(sum1) * math.sqrt(sum2)

        if not denominator:
            return 0.0
        else:
            return float(numerator) / denominator


    def text_to_vector(text):
        words = WORD.findall(text)
        return Counter(words)

    with open('data.txt', 'r') as f:  #replace data.txt with the wordlist of choice

        for inj in f.readlines():
            text2 = inj.rstrip('\n')
            
            vector1 = text_to_vector(str(userPayload))
            vector2 = text_to_vector(text2)
            vector3 = text_to_vector(str(passPayload))

            cosine = get_cosine(vector1, vector2)
            cosine2 = get_cosine(vector3, vector2)
            f.close()

    with open('data.txt', 'w') as f:
            if cosine >= .75:
                f.write(str(userPayload))
                return 'Injection decteted - neturalizing threat'
            elif cosine2 >= .75:
                f.write(str(passPayload))
                return 'Injection decteted - neturalizing threat'

def info_gather(var):
    if request.method == 'GET':
        session = requests.Session()
        url = 'http://127.0.0.1:8000/' + var
        html = session.get(url).content
        return html
    elif request.method == 'POST':
        
        req_params = request.form.to_dict(flat=False)
        userName = str(req_params['userName'][0])
        userPass = str(req_params['password'][0])
    

        url = 'http://127.0.0.1:8000/' + var
        r = requests.post(url, data=request.form.to_dict(flat=False))
        
        if injection_dectector(userName,userPass):
            return 'Injection decteted - neturalizing threat'
        else:
            return r.text


@app.route("/<reqPath>", methods=['GET','POST'])
def render(reqPath):
    #returning the {'Server':'127.0.0.1:8080'} header removes some server information that could be helpful for anyone trying to fingerprint the underlying server
    return info_gather(reqPath), {'Server':'127.0.0.1:5000'}


@app.route('/')
def main():
    url = 'http://127.0.0.1:8000/'
    r = requests.get(url)
    return r.text, {'Server':'127.0.0.1:5000'}

#runs the app without having to set any of the env vars that are listed in the documentation
if __name__ == '__main__':
    app.run(debug=True)



