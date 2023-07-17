import logging.config, yaml
from flask import Flask
from flask_restful import Api

file = open('config/log/logging.yml', 'r')
data = yaml.safe_load(file)
file.close()
logging.config.dictConfig(data)

app = Flask(__name__)
app.config.from_pyfile('config.py')
api_key = app.config.get('API_KEY')
api = Api(app)

from api.resources.autenticator import Login, GetApiKeyByAlias

api.add_resource(Login, '/aut/login')
api.add_resource(GetApiKeyByAlias, '/aut/getapibyalias/<alias>')

@app.route("/", methods = ['POST', 'GET'])
def hello():
    return "Pagina de prueba"