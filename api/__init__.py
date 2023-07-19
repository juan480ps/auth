import logging.config, yaml
from flask import Flask
from flask_restful import Api

logging_file = open('config/log/logging.yaml', 'r')# se lee el archivo de configuracion para el logging
logging_data = yaml.safe_load(logging_file)
logging_file.close()
logging.config.dictConfig(logging_data)

app_config_file = open('config/app_config.yaml', 'r') # se lee el archivo de configuracion para la app. De este archivo se extrae la apikey para poder validar posteriormente, el vencimiento del token y el ambiente de la bd (postgres)
app_config_data = yaml.safe_load(app_config_file)
app_config_file.close()

API_KEY = app_config_data['API_KEY']
AMBIENTE_DB = app_config_data['AMBIENTE_DB']
VENCIMIENTO_TOKEN = app_config_data['VENCIMIENTO_TOKEN']

app = Flask(__name__)
api = Api(app)

from api.resources.autenticator import Login, GetApiKeyByAlias

api.add_resource(Login, '/aut/login') # url del servicio principal de autenticacion
api.add_resource(GetApiKeyByAlias, '/aut/getapibyalias/<alias>') # url para obtener la apikey del postgres mediante el alias de la aplicacion ej. kude => adas68-sdfas554-54sd54

@app.route("/", methods = ['POST', 'GET']) # url de prueba
def hello():
    return "Pagina de prueba"