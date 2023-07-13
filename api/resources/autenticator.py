import base64, psycopg2, api, random, string, logging, json
from flask_restful import Resource
from flask import request, make_response
from db.db_config_pstgr import postgresqlConfig
from functools import wraps

connpost = psycopg2.connect(postgresqlConfig)
vencimiento_token = 30
access_token = ""
objetoJson = []
arrayJson = []

def generate_token():
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for i in range(80))
    return password

class APIKeyManager:
    @staticmethod
    def validate_api_key(api_key):
        return api_key == api.api_key

def require_api_key(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        try:
            logging.debug("Verificar Api-Key Auth")
            data = request.get_json()
            params = data['params']
            api_key = params['apikey']
            if not api_key or not APIKeyManager.validate_api_key(api_key):
                descripcion = 'No autenticado'
                codigo = -1003
                objetoJson = []
                arrayJson = []            
                respuesta = {'codigo': codigo, 'descripcion': descripcion, 'objetoJson': objetoJson, 'arrayJson' : arrayJson}
                return respuesta
        except KeyError as e :
            descripcion = 'No se encuentra el parametro: ' + str(e)
            codigo = -1001
            return {'codigo': codigo, 'descripcion': descripcion, 'objetoJson': [], 'arrayJson' : {}}
        except Exception as e:
            descripcion = str(e)
            codigo = -1000
            return {'codigo': codigo, 'descripcion': descripcion, 'objetoJson': [], 'arrayJson' : {}}
        return func(*args, **kwargs)
    return decorated_function

class Login(Resource):
    @require_api_key
    def post(self):
        logging.debug("Entro POST Auth")
        global vencimiento_token, access_token, objetoJson, arrayJson
        try:
            logging.debug("HTTP REQUEST HEADERS: " + str(request.headers))
            logging.debug("HTTP REQUEST DATA: " + str(request.data))
            data = request.get_json()
            logging.info('@REQUEST POST ' + json.dumps(data))            
            operation = data['operation']
            params = data['params']            
            username = params['username']
            password = params['password']
            contexto = params['authcontext']            
            if operation == "get_token":         
                password = base64.b64encode(password.encode("utf-8")).decode("utf-8")                
                cursor = connpost.cursor()                
                query = f"""SELECT u.nombre username, p.passwd, u.estado est_usuario, r.nombre rol, c.nombre contexto
                            FROM testdta.usuario u 
                            join testdta."password" p on u.id = p.usuario_id
                            join testdta.usu_x_rol uxr on u.id = uxr.usuario_id 
                            join testdta.rol r on uxr.rol_id = r.id
                            join testdta.usu_x_contexto uxc on u.id = uxc.usuario_id 
                            join testdta.contexto c on uxc.contexto_id = c.id
                            where u.estado = 'ACT'
                            and u.nombre = '{username}'
                            and p.passwd = '{password}'
                            and c.nombre = '{contexto}';
                            """
                logging.debug(str(query))  
                cursor.execute(query)
                data = cursor.fetchone()
                cursor.close()                
                if data:            
                    access_token = generate_token()
                    listJson = {
                        'token' : access_token
                    }
                    descripcion = 'Sesion iniciada con exito'
                    codigo = 1000
                    arrayJson = [listJson]
                else:
                    descripcion = 'Usuario no autenticado'
                    codigo = -1003
            else:
                descripcion = 'Operación inválida'
                codigo = -1002
        except KeyError as e :
            logging.debug(e)
            logging.info("Peticion finalizada con error", exc_info = True)
            descripcion = 'No se encuentra el parametro: ' + str(e)
            codigo = -1001
        except Exception as e:
            logging.debug(e)
            logging.info("Peticion finalizada con error", exc_info = True)
            descripcion = str(e)
            codigo = -1000
        respuesta = {'codigo': codigo, 'descripcion': descripcion, 'objetoJson': objetoJson, 'arrayJson': arrayJson }
        if access_token:
            respuesta = make_response(respuesta)
            respuesta.set_cookie('cookie', access_token, max_age = vencimiento_token)
        connpost.commit()
        logging.info('@REQUEST GET ' + request.full_path + ' @RESPONSE ' + json.dumps(respuesta))
        return respuesta
        
class GetApiKeyByAlias(Resource):
    @require_api_key
    def post(self, alias):
        global objetoJson, arrayJson
        try:
            cursor = connpost.cursor()
            query = f"SELECT api_key FROM testdta.pool_access WHERE alias = '{alias}' "
            cursor.execute(query)
            data = cursor.fetchone()
            cursor.close()
            if data:            
                api_key_pool = data[0]
                
            listJson = {
                'apikey' : api_key_pool
            }  
            descripcion = 'OK'
            codigo = 1000
            arrayJson = [listJson]  
            
        except KeyError as e :
            descripcion = 'No se encuentra el parametro: ' + str(e)
            codigo = -1001
        except Exception as e:
            descripcion = str(e)
            codigo = -1000
        respuesta = {'codigo': codigo, 'descripcion': descripcion, 'objetoJson': objetoJson, 'arrayJson': arrayJson }    
        connpost.commit()
        return respuesta