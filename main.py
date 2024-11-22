import json
import random
from datetime import timedelta
import traceback
import requests
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity

from log import Logger
from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from auth import Authenticate
from sms.sendSms import Sendsms
import const


app = Flask(__name__)
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config["JWT_SECRET_KEY"] = const.JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=12)
jwt = JWTManager(app)
api = Api(app)

logger = Logger.getLogger('server_requests', 'logs/server_requests')


def random_ref(length):
    sample_string = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'  # define the specific string
    # define the condition for random string
    return ''.join((random.choice(sample_string)) for x in range(length))


@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_data):
    return jsonify({"result": "error", "msg": "Token has expired"}), 401


@jwt.invalid_token_loader
def my_invalid_token_callback(jwt_data):
    return jsonify({"result": "error", "msg": "Invalid Token"}), 401


@jwt.unauthorized_loader
def my_unauthorized_loader_callback(jwt_data):
    return jsonify({"result": "error", "msg": "Missing Authorization Header"}), 401



def getAuthKey(userid):
    with open('auth.json') as f:
        data = json.load(f)
        for usr in data['user_list']:
            if usr['username'] == str(userid):
                return usr['authkey']


# TOKEN
class GetToken(Resource):
    def post(self):
        ref = random_ref(15)
        data = request.get_json()        
        logger.info(ref + " - " + str(request.remote_addr) + " - " + str(request.url) + " - " + str(request.headers))
        logger.info(ref + " - " + str(data))        
        return Authenticate.generateToken(data, ref)

# SMS
class SendSms(Resource):
    @jwt_required()
    def post(self):
        ref = random_ref(15)
        data = request.get_json()        
        logger.info(ref + " - " + str(request.remote_addr) + " - " + str(request.url) + " - " + str(request.headers))
        logger.info(ref + " - " + str(data))            
        return Sendsms.sendSms(data, ref)
 
# TOKEN
api.add_resource(GetToken, const.APP_ROUTE_TOKEN)

# SMS
api.add_resource(SendSms, const.APP_ROUTE_SMS)
 
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=33460)
    #serve(app, host='0.0.0.0', port=20001, threads=3)
