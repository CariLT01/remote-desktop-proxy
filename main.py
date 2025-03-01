from gevent import monkey

monkey.patch_all()
from dotenv import load_dotenv
import os, logging
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, send, join_room, leave_room, rooms

logging.basicConfig(
    level=logging.DEBUG,  # Set the log level to DEBUG (can be INFO, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Define log message format
    datefmt='%Y-%m-%d %H:%M:%S',  # Define date and time format
)

# Initialize Flask app and SocketIO
app = Flask(__name__)
socketio = SocketIO(app, async_mode="gevent", logger=True, engineio_logger=True)

# Serve the webpage

valid_token = "dev_token"


n_clients = 0
providers = {}

def __init__():



    logging.info("1 thread started")


    load_dotenv(verbose = True)

    #app.add_url_rule("/", view_func=self.index)
    if os.getenv("ENV") == "dev":
        socketio.run(app, debug = True) # Reserved for local dev

@socketio.on("screenshot_response")
def screenshot_response_ev(_, data):
    logging.info(f"Proxy screenshot event" )
    socketio.emit("screenshot_response", data)
@socketio.on_error_default
def socketerror(e):
    logging.error(f"Proxy socket error: {e}")

    
@app.route("/")
def index():
    return render_template("index.html")

def handlescreenproxy(data):
    if 'data_providers' in rooms():
        logging.info("In room. OK")
        socketio.emit("screenshot_response", data)
    else:
        logging.info("Not in room")

def connectionidentification():
    ...

@socketio.on("connect")
def onconnect(authentication):
    global n_clients, providers
    logging.info("New client connected")
    logging.info(request.sid)
    if authentication:
        logging.info("Detected auth data. Checking authentication data")
        token = authentication.get("token")
        if token == None:
            logging.info("No token found.")
            n_clients += 1
            return
        if token == valid_token:
            logging.info("Token is valid.")
            join_room("data_providers")
            providers[request.sid] = True
        else:
            logging.info("Token is invalid.")
            n_clients += 1
    else:
        logging.info("No authentication data. No token found")
        n_clients += 1
        
    
    

@socketio.on("disconnect")
def ondisconnect():
    global providers, n_clients
    logging.info("Client disonnected")
    if providers.get(request.sid) != None:
        logging.info("Disconnected client is a provider")
        providers[request.sid] = None
        return
    n_clients -= 1











# Run the application
if __name__ == '__main__':

    m = __init__()
    