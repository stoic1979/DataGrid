import os
from flask            import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask_login      import LoginManager
from flask_bcrypt     import Bcrypt

app = Flask(__name__, instance_relative_config=True)

# app.config['SQLALCHEMY_DATABASE_URI']        = "mysql+pymysql://root:123@localhost/intergrid_db"
app.config['SQLALCHEMY_DATABASE_URI']        = "mysql://root:123@localhost/intergrid_db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


STATIC = '/static/img/'
app.config['UPLOAD_FOLDER'] = os.path.realpath('.') + STATIC + 'blog/'

db = SQLAlchemy  (app) # flask-sqlalchemy
bc = Bcrypt      (app) # flask-bcrypt


import routes, models
