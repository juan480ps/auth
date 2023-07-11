from api import app

if __name__=='__main__':
    app.run(debug=False, threaded=True, port=5001 )