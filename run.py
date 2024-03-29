from flask import Flask
from flask_restful import reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
#from flask_restful import Api
app = Flask(__name__)
#api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'some-secret-string'
db = SQLAlchemy(app)

@app.before_first_request
def create_tables():
    db.create_all()

app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
jwt = JWTManager(app)

parser = reqparse.RequestParser()
parser.add_argument('username', help = 'This field cannot be blank', required = True)
parser.add_argument('password', help = 'This field cannot be blank', required = True)


#import views, models, resources

#api.add_resource(resources.UserRegistration, '/registration')
#api.add_resource(resources.UserLogin, '/login')
#api.add_resource(resources.UserLogoutAccess, '/logout/access')
#api.add_resource(resources.UserLogoutRefresh, '/logout/refresh')
#api.add_resource(resources.TokenRefresh, '/token/refresh')
#api.add_resource(resources.AllUsers, '/users')
#api.add_resource(resources.SecretResource, '/secret')
