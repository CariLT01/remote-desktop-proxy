import logging, json

def read_file(file:str):
    try:
        with open(file, "r") as f:
            return f.read()
    except Exception as e:
        logging.error(f"Failed to read users file: {f}")
        return None
def write_file(filename:str, content:str):
    try:
        with open(filename, "w") as f:
            f.write(content)
    except Exception as e:
        logging.error(f"Failed to write file: {e}")
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
def get_provider_tokens_dict():

    r = read_file("provider_tokens.json")
    d: dict = json.loads(r)
    nd = {}
    for k in d.keys():
        nd[k] = {
            "name": d[k]["name"],
        }
        
    return nd
def get_latest_id():
    r = read_file("provider_tokens.json")
    d = json.loads(r)
    c = 0
    while d.get(str(c))!=None:
        c+=1
    
    return c
def is_admin_user(username:str)->bool:
    r = read_file("admin_users.json")
    d = json.loads(r)
    return d.get(username) != None