from gevent import monkey

# patch
monkey.patch_all()

from settings import *
from token_validation import *
from utils import *
from dotenv import load_dotenv
import os, logging, bcrypt, json, jwt, datetime
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, join_room, rooms, ConnectionRefusedError, emit

logging.basicConfig(
    level=logging.DEBUG,  # Set the log level to DEBUG (can be INFO, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Define log message format
    datefmt='%Y-%m-%d %H:%M:%S',  # Define date and time format
)



n_clients = 0
providers = {}

allowed_cors = None
logger = False
engineio_logger = False
if os.getenv("ENV") == "dev":
    logging.info("Running on local machine. Allowing CORS.")
    allowed_cors = "*"
    logger = False
    engineio_logger = False
app = Flask(__name__)
socketio = SocketIO(app, async_mode="gevent", cors_allowed_origins=allowed_cors, logger=logger, engineio_logger=engineio_logger)





def initialize():

    logging.info("Initializing")


    load_dotenv(verbose = True)

    #app.add_url_rule("/", view_func=self.index)
    if os.getenv("ENV") == "dev":
        logging.info("Running on local machine. Calling socketio.run()")
        socketio.run(app, debug = True, port=5000, host="127.0.0.1") # Reserved for local dev

@socketio.on("screenshot_response")
def screenshot_response_ev(data):
    logging.info(f"Proxy screenshot event" )
    socketio.emit("screenshot_response", data)
@socketio.on_error_default
def socketerror(e):
    logging.error(f"Proxy socket error: {e}")
@socketio.on("connect")
def onconnect(authentication):
    global n_clients, providers
    logging.info("New client connected")
    logging.info(request.sid)
    if authentication:
        logging.info("Detected auth data. Checking authentication data")
        if authentication.get("dist") == "provider":
            token = authentication.get("token")
            if token == None:
                logging.info("No token found.")
                raise ConnectionRefusedError("Dist provider. No valid token found.")
            if check_provider_token(token) == True:
                logging.info("Token is valid. New provider connected with no error.")
                join_room("data_providers")
                providers[request.sid] = True
            else:
                logging.info("Token is invalid.")
                raise ConnectionRefusedError("Dist provider. Token not valid.")
        elif authentication.get("dist") == "client":
            token = authentication.get("token")
            if token == None:
                logging.error("No token found. Dist client.")
                raise ConnectionRefusedError("Dist client. No token found.")
            if type(token) != str:
                logging.error("Token incorrect data type. Dist client.")
                raise ConnectionRefusedError("Dist client. Token incorrect data type.")
            if check_token(token) != True:
                logging.error("Invalid or expired token dist client")
                raise ConnectionRefusedError("Dist client. Invalid or expired token.")
            logging.info("New client connected without error.")
            n_clients += 1

            emit("provider_count", {"count": len(providers)})
        else:
            logging.error("No dist provided")
            raise ConnectionRefusedError("No dist provided. Please add key 'dist' to authentication data.")

    else:
        logging.info("No authentication data. No token found")
        raise ConnectionRefusedError("No authentication data found.")
@socketio.on("disconnect")
def ondisconnect(_):
    global providers, n_clients
    logging.info("Client disonnected")
    if providers.get(request.sid) != None:
        logging.info("Disconnected client is a provider")
        del providers[request.sid]
        socketio.emit("provider_disconnect", {})
        return
    n_clients -= 1
    
@app.route("/")
def index():
    return render_template("index.html")
@app.route("/login")
def loginpage():
    return render_template("login.html")
def handlescreenproxy(data):
    if 'data_providers' in rooms():
        logging.info("In room. OK")
        socketio.emit("screenshot_response", data)
    else:
        logging.info("Not in room")

@app.route("/admin/providers/tokens")
def tokenpage():
    return render_template("provider_tokens.html")


@app.route("/authentication", methods=["POST"])    
def check_login():
    if not request.is_json:
        return jsonify(success=False, message="Missing JSON in request"), 400

    data = request.get_json()
    # Extract username and password
    username = data.get('username')
    password = data.get('password')

    # Validate presence of fields
    if not username or not password:
        return jsonify(success=False, message="Username and password required"), 400
    
    user_data = get_user_in_database(username)
    if user_data == None:
        logging.error("User not found")
        return jsonify(success=False, message="Invalid credentials"), 400
    # Field = username: {password: (str)hashed bcrypt password}

    stored_password = user_data.get("password")
    if stored_password == None:
        logging.error("Field 'password' not found under user")
        return jsonify(success=False, message="Internal server error while authenticating"), 500
    if bcrypt.checkpw(password.encode(), stored_password.encode()) == False:
        logging.error("Passwords do not match")
        return jsonify(success=False, message="Invalid credentials"), 400
    logging.info(f"Sucessfully logged in user: {username}")
    return jsonify(success=True, message="Successfully authenticated", token=generate_jwt_token(username))





@app.route("/admin/providers/create_token")
def create_token_page():
    return render_template("create_tokens.html")
    

@app.route("/admin/create_token", methods=["POST"])
def create_provider_token():
    try:
        if check_token_request() == False:
            return jsonify(success=False, message="Invalid authorization"), 400


        data = request.get_json()

        token_name = data.get("token_name")
        if token_name == None:
            return jsonify(success=False, message="No token_name field"), 400
        if type(token_name) != str:
            return jsonify(success=False, message="Invalid datatype"), 400
        r = read_file("provider_tokens.json")
        d = json.loads(r)
        id = get_latest_id()
        d[str(id)] = {
            "name": str(token_name),
            "value": create_jwt_provider_token(token_name, id)
        }
        write_file("provider_tokens.json", json.dumps(d, indent=4))

        return jsonify(success=True, message="Created token")
    except Exception as e:
        logging.error(f"Failed to create provider token: {e}")
        return jsonify(success=False, message="Internal server error"), 500



@app.route("/admin/get_provider_tokens")
def get_provider_tokens():
    try:
        if check_token_request() == False:
            return jsonify(success=False, message="Invalid authorization"), 400
        
        return jsonify(success=True, users=get_provider_tokens_dict()), 200
    except Exception as e:
        logging.error(f"Failed to provide tokens: {e}")
        return jsonify(success=False, message="Internal server error"), 500
@app.route("/admin/get_token_value", methods=['POST'])
def get_token_value():
    try:
        if check_token_request() == False:
            return jsonify(success=False, message="Invalid authorization"), 400
        
        r = read_file("provider_tokens.json")
        d = json.loads(r)

        data = request.get_json()
        token_id = data.get("id")
        if token_id == None:
            return jsonify(success=False, message="No token ID provided"), 400
        
        a = d.get(str(token_id))
        if a == None:
            return jsonify(success=False, message="Token ID not found"), 500
        value = a.get("value")
        if value == None:
            return jsonify(success=False, message="No value found"), 500
        return jsonify(success=True, token=value)
    except Exception as e:
        logging.error(f"Failed to fetch token by ID: {e}")
        return jsonify(success=False, message="Internal server error"), 500














# Run the application
if __name__ == '__main__':

    m = initialize()
    