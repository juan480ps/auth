from api import app #modulo principal que se usa para la entrada wsgi

if __name__=='__main__':
    app.run(debug=False, threaded=True, port=6001 )