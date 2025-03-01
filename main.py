
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, send, join_room, leave_room, rooms
# Initialize Flask app and SocketIO
app = Flask(__name__)
socketio = SocketIO(app, async_mode="eventlet")

# Serve the webpage

valid_token = "dev_token"


n_clients = 0
providers = {}

def __init__():



    print("1 thread started")

    socketio.on_event("connect", onconnect)
    socketio.on_event("disconnect", ondisconnect)
    socketio.on_event("screenshot_response", handlescreenproxy)




    #app.add_url_rule("/", view_func=self.index)

    socketio.run(app)

def screenshot_response_ev(_, data):
    print(f"Proxy screenshot event" )
    socketio.emit("screenshot_response", data)


    
@app.route("/")
def index():
    return render_template("index.html")

def handlescreenproxy(data):
    if 'data_providers' in rooms():
        print("In room. OK")
        socketio.emit("screenshot_response", data)
    else:
        print("Not in room")

def connectionidentification():
    ...


def onconnect(authentication):
    global n_clients, providers
    print("New client connected")
    print(request.sid)
    if authentication:
        print("Detected auth data. Checking authentication data")
        token = authentication.get("token")
        if token == None:
            print("No token found.")
            n_clients += 1
            return
        if token == valid_token:
            print("Token is valid.")
            join_room("data_providers")
            providers[request.sid] = True
        else:
            print("Token is invalid.")
            n_clients += 1
    else:
        print("No authentication data. No token found")
        n_clients += 1
        
    
    


def ondisconnect():
    global providers, n_clients
    print("Client disonnected")
    if providers.get(request.sid) != None:
        print("Disconnected client is a provider")
        providers[request.sid] = None
        return
    n_clients -= 1











# Run the application
if __name__ == '__main__':

    m = __init__()
    