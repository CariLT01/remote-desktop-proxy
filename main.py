from gevent import monkey

monkey.patch_all()
from dotenv import load_dotenv
import os, logging, bcrypt, json, jwt, datetime
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, join_room, rooms, ConnectionRefusedError, emit

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
SECRET_KEY = "very_secret_key_temporary"

n_clients = 0
providers = {}

def __init__():



    logging.info("1 thread started")


    load_dotenv(verbose = True)

    #app.add_url_rule("/", view_func=self.index)
    if os.getenv("ENV") == "dev":
        socketio.run(app, debug = True) # Reserved for local dev

@socketio.on("screenshot_response")
def screenshot_response_ev(data):
    logging.info(f"Proxy screenshot event" )
    socketio.emit("screenshot_response", data)
@socketio.on_error_default
def socketerror(e):
    logging.error(f"Proxy socket error: {e}")

    
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

def connectionidentification():
    ...

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
            if token == valid_token:
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
                raise ConnectionRefusedError("Dist client. Invalid or expired token.")
            logging.info("New client connected without error.")
            n_clients += 1

            emit("provider_count", {"count": len(providers)})
        else:
            raise ConnectionRefusedError("No dist provided. Please add key 'dist' to authentication data.")

    else:
        logging.info("No authentication data. No token found")
        raise ConnectionRefusedError("No authentication data found.")


def read_file(file:str):
    try:
        with open(file, "r") as f:
            return f.read()
    except Exception as e:
        logging.error(f"Failed to read users file: {f}")
        return None
def get_user_in_database(username: str):
    try:
        decoded = json.loads(read_file("users.json"))
        users = decoded.get("users")
        if users == None:
            logging.error("No users entry in database")
            return None
        return users.get(username)

    except Exception as e:
        logging.error(f"Failed to get user in database: {e}")
        return None

def generate_jwt_token(username: str):

    payload = {
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1) # token wil expire in 1 hour
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return token
def check_token(token: str):
    try:
        _ = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return True
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False
    except Exception as e:
        logging.error(f"Unknown exception while decoding JWT token: {e}")

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











# Run the application
if __name__ == '__main__':

    m = __init__()
    