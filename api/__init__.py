from flask import Flask
from flask_jwt_extended import JWTManager
from flask_restful import Api
from logging.config import dictConfig

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': 'auth %(levelname)s %(filename)s(%(lineno)d) %(funcName)s(): %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'DEBUG',
        'handlers': ['wsgi']
    }
})

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