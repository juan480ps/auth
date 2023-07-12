from flask import Flask
from flask_jwt_extended import JWTManager
from flask_restful import Api

app = Flask(__name__)

app.config.from_pyfile('config.py')

api_key = app.config.get('API_KEY')

api = Api(app)

jwt = JWTManager(app)

from api.resources.autenticator import Login, GetApiKeyByAlias #Logout, Test, 

api.add_resource(Login, '/aut/login')
api.add_resource(GetApiKeyByAlias, '/aut/getapibyalias/<alias>')

# api.add_resource(Logout, '/aut/logout')
# api.add_resource(Test, '/aut/test')

@app.route("/", methods = ['POST', 'GET'])
def hello():
    return "Pagina de prueba"