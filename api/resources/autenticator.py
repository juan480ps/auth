import base64, psycopg2, api, random, string, logging, json
from flask_restful import Resource
from flask import request, make_response
from config.db.db_config_pstgr import postgresqlConfig
from functools import wraps

connpost = psycopg2.connect(postgresqlConfig) # cargamos la configuracion a la bd interna postgres
vencimiento_token = api.VENCIMIENTO_TOKEN # se asigna el valor del vencimiento del token en el archivo config a una variable
#variables globales
access_token = ""
objetoJson = {}
arrayJson = []

def generate_token(): #funcion para generar token aleatorio
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for i in range(80))
    return password

def require_api_key(func): #funcion para requerir apikey
    @wraps(func)
    def decorated_function(*args, **kwargs):
        try:
            logging.info("Verificar Api-Key Auth")
            data = request.get_json()
            params = data['params']
            api_key = params['apikey']
            if not api_key or not api_key == api.API_KEY:
                descripcion = 'No autenticado'
                codigo = -1003
                objetoJson = []
                arrayJson = []            
                respuesta = {'codigo': codigo, 'descripcion': descripcion, 'objetoJson': objetoJson, 'arrayJson' : arrayJson}
                logging.debug(descripcion)
                logging.error("Peticion finalizada con error; " + descripcion + " " + str(codigo), exc_info=True)
                return respuesta
        except KeyError as e :
            descripcion = 'No se encuentra el parametro: ' + str(e)
            codigo = -1001
            logging.debug(str(e))
            logging.error("Peticion finalizada con error; " + descripcion + " " + str(codigo), exc_info=True)
            return {'codigo': codigo, 'descripcion': descripcion, 'objetoJson': [], 'arrayJson' : {}}
        except Exception as e:
            descripcion = str(e)
            codigo = -1000
            logging.debug(str(e))
            logging.error("Peticion finalizada con error; " + descripcion + " " + str(codigo), exc_info=True)
            return {'codigo': codigo, 'descripcion': descripcion, 'objetoJson': [], 'arrayJson' : {}}
        return func(*args, **kwargs)
    return decorated_function

class Login(Resource):#clase que se encarga de loguear al cliente
    @require_api_key #se requiere apikey
    def post(self):
        global vencimiento_token, access_token, objetoJson, arrayJson
        logging.debug("Entro POST Auth") #logging de prueba
        try:
            logging.debug("HTTP REQUEST HEADERS: " + str(request.headers)) #logging de prueba
            logging.debug("HTTP REQUEST DATA: " + str(request.data)) #logging de prueba
            data = request.get_json()# se asigna a una variable el json recibido
            logging.info('@REQUEST POST ' + json.dumps(data)) #logging de prueba
            operation = data['operation']# se obtiene la key operacion del json
            params = data['params']# se obtiene la key params del json
            username = params['username'] # se obtiene la key username de params
            password = params['password'] # se obtiene la key password de params
            contexto = params['authcontext']# se obtiene la key authcontext de params
            if operation == "get_token": # se valida la operacion a realizar
                password = base64.b64encode(password.encode("utf-8")).decode("utf-8")# se codifica el password recibido ya que en la bd se guarda de esta manera
                cursor = connpost.cursor()# abrimos cursor de la bd interna postgres
                query = f"""SELECT u.nombre username, p.passwd, u.estado est_usuario, r.nombre rol, c.nombre contexto
                            FROM {api.AMBIENTE_DB}.usuario u 
                            join {api.AMBIENTE_DB}."password" p on u.id = p.usuario_id
                            join {api.AMBIENTE_DB}.usu_x_rol uxr on u.id = uxr.usuario_id 
                            join {api.AMBIENTE_DB}.rol r on uxr.rol_id = r.id
                            join {api.AMBIENTE_DB}.usu_x_contexto uxc on u.id = uxc.usuario_id 
                            join {api.AMBIENTE_DB}.contexto c on uxc.contexto_id = c.id
                            where u.estado = 'ACT'
                            and u.nombre = '{username}'
                            and p.passwd = '{password}'
                            and c.nombre = '{contexto}';
                            """ # query para vaidar si el usuario esta eutenticado y pertenece al contexto que menciona
                logging.debug(str(query))#logging de prueba
                cursor.execute(query) # se ejecuta el query
                data = cursor.fetchone() # se asigna a una variable la primera fila del resultado del query
                cursor.close()# se cierra el cursor
                if data:# se valida si el usuario fue autenticado, en caso afirmativo se devuelve el token autogenerado anteriormente
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
                    logging.debug(descripcion)#logging de prueba
                    logging.error("Peticion finalizada con error; " + descripcion + " " + str(codigo), exc_info=True)#logging de prueba
            else:
                descripcion = 'Operación inválida'
                codigo = -1002
                logging.debug(descripcion)#logging de prueba
                logging.error("Peticion finalizada con error; " + descripcion + " " + str(codigo), exc_info=True)#logging de prueba
        except KeyError as e :
            descripcion = 'No se encuentra el parametro: ' + str(e)
            codigo = -1001
            logging.debug(e)#logging de prueba
            logging.error("Peticion finalizada con error; " + descripcion + " " + str(codigo), exc_info=True)#logging de prueba
        except Exception as e:
            descripcion = str(e)
            codigo = -1000
            logging.debug(e)#logging de prueba
            logging.error("Peticion finalizada con error; " + descripcion + " " + str(codigo), exc_info=True)#logging de prueba
        respuesta = {'codigo': codigo, 'descripcion': descripcion, 'objetoJson': objetoJson, 'arrayJson': arrayJson }        
        logging.info('@REQUEST GET ' + request.full_path + ' @RESPONSE ' + json.dumps(respuesta))#logging de prueba
        if access_token:# en caso que la autenticacion fue exitosa, se genera cookie de sesion y se devuelve en la respuesta
            respuesta = make_response(respuesta)
            respuesta.set_cookie('cookie', access_token, max_age = vencimiento_token)
        connpost.commit()
        return respuesta
        
class GetApiKeyByAlias(Resource):#clase que se encarga de devolver la apikey de acuerdo al alias del ws
    @require_api_key#se requiere apikey
    def post(self, alias):
        global objetoJson, arrayJson
        try:
            logging.info('@REQUEST POST GetApiKeyByAlias')#logging de prueba
            cursor = connpost.cursor()# abrimos cursor de la bd interna postgres
            query = f"SELECT api_key FROM {api.AMBIENTE_DB}.pool_access WHERE alias = '{alias}' "# query para validar si al app cuenta que apikey asignada
            cursor.execute(query) # se ejecuta el query
            data = cursor.fetchone() # se asigna a una variable la primera fila del resultado del query
            cursor.close()# se cierra el cursor
            if data:# se valida si la app cuenta esta registrada en la bd, en caso afirmativo se devuelve la apikey
                api_key_pool = data[0]
                
                listJson = {
                    'apikey' : api_key_pool
                }  
                descripcion = 'OK'
                codigo = 1000
                arrayJson = [listJson]
            else:
                descripcion = 'API-Key no encontrado'
                codigo = -1001
                logging.debug(descripcion)#logging de prueba
                logging.error("Peticion finalizada con error; " + descripcion + " " + str(codigo), exc_info=True)#logging de prueba
            
        except KeyError as e :
            descripcion = 'No se encuentra el parametro: ' + str(e)
            codigo = -1001
            logging.debug(e)#logging de prueba
            logging.error("Peticion finalizada con error; " + descripcion + " " + str(codigo), exc_info=True)#logging de prueba
        except Exception as e:
            descripcion = str(e)
            codigo = -1000
            logging.debug(e)#logging de prueba
            logging.error("Peticion finalizada con error; " + descripcion + " " + str(codigo), exc_info=True)#logging de prueba
        respuesta = {'codigo': codigo, 'descripcion': descripcion, 'objetoJson': objetoJson, 'arrayJson': arrayJson }       
        logging.info('@REQUEST GET ' + request.full_path + ' @RESPONSE ' + json.dumps(respuesta)) 
        connpost.commit()
        return respuesta