from flask_restful import Resource
from flask import jsonify,request
from models import UserModel
import datetime
from run import parser
from run import app
from run import jwt
from flask_jwt_extended import (JWTManager,create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
import requests

@app.route('/')
def welcome():
    return "HI!"

@jwt.expired_token_loader
def my_expired_token_callback(expired_token):
    #token_type = expired_token['type']
    curr_Refresh = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIyOWVmYjI4ZS0xYjM4LTRkOWQtOGQwZS03YjRhM2E3ZWIyNDUiLCJleHAiOjE1NjIzODgxNjIsImlhdCI6MTU1OTc5NjE2MiwidHlwZSI6InJlZnJlc2giLCJuYmYiOjE1NTk3OTYxNjIsImlkZW50aXR5IjoiREoifQ.i7au85N73KC3rWdmaAqIL3ISxNvd0J5pDYv-oIAx3mE'
    header = {'Authorization': 'Bearer ' + curr_Refresh}
    dictToSend = {'username':'DJ','password':'Kahlid'}
    res = requests.post('http://localhost:5000/token/refresh',json=dictToSend,headers=header)
    #return res.text 
    dictFromServer = res.json()
    new_Access = dictFromServer['access_token']
    header2 = {'Authorization': 'Bearer ' + new_Access}
    finalCall = requests.get('http://localhost:5000/secret',json=dictToSend,headers=header2)
    return finalCall.text
    
    

@app.route('/registration',methods=['POST'])
#class UserRegistration(Resource):
def register():
        data = parser.parse_args()
        if UserModel.find_by_username(data['username']):
            return jsonify({'message': 'User {} already exists'. format(data['username'])})
        new_user = UserModel(
            username = data['username'],
            password = UserModel.generate_hash(data['password'])
        )
        try:
            new_user.save_to_db()
            
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return jsonify({
                'message': 'User {} was created'.format(data['username']),
                'access_token': access_token,
                'refresh_token': refresh_token
                })
        except:
            return jsonify({'message': 'Something went wrong'}), 500
            

@app.route('/login',methods=['POST'])
#class UserLogin(Resource):
def login():
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])
        if not current_user:
            return jsonify({'message': 'User {} doesn\'t exist'.format(data['username'])})
        
        if UserModel.verify_hash(data['password'],current_user.password):
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return jsonify({
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
                })
        else:
            return jsonify({'message': 'Wrong credentials'})
      
@app.route('/logout/access',methods=['POST'])
def accessOut():
    return jsonify({'message': 'User logout'})
      
      
@app.route('/logout/refresh',methods=['POST'])
def accessOutRef():
    return jsonify({'message': 'User logout'})
      

#class TokenRefresh(Resource):
@app.route('/token/refresh',methods=['POST'])
@jwt_refresh_token_required
def tokenRefresh():
        current_user = get_jwt_identity()
        expires = datetime.timedelta(days=10)
        access_token = create_access_token(identity = current_user,expires_delta=expires)
        return jsonify({'access_token': access_token})

      
      
#class AllUsers(Resource):
@app.route('/users',methods=['GET','DELETE'])
def users():
    if request.method == 'GET':
        return jsonify(UserModel.return_all())
    else:
        return jsonify(UserModel.delete_all())
#def delete(self):
#    return UserModel.delete_all()
      


#class SecretResource(Resource):   
@app.route('/secret',methods=['GET'])
@jwt_required
def secret():
        return jsonify({
            'answer': 42
        })
        #return secret()
    #@jwt.expired_token_loader
    #def get(self):
        #token_type = expired_token['type']
    #    return {'message':'not working!'}

'''
class Expired_Token(Resource):
    @jwt.expired_token_loader 
    def isExpired():
        return TokenRefresh.post()
    @jwt_required
    def get(self):
        current_token = 

'''
