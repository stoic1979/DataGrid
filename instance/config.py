DEBUG = False      # Turns on debugging features in Flask
BCRYPT_LEVEL = 12  # Configuration for the Flask-Bcrypt extension
MAIL_FROM_EMAIL = "nika.rostia1@gmail.com"  # For use in application emails
SECRET_KEY = 'devKey##$$'


# MAIL SETTINGS
MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 465
MAIL_USE_SSL = True
MAIL_USERNAME = 'nika.rostia1@gmail.com'
MAIL_PASSWORD = 'gmailpassword123'

# MYSQL SETTINGS
# MY_SQL_USER = 'intertek'
MY_SQL_USER  = 'root'
MY_HOST = 'localhost'
MY_DBNAME = 'ingrid'
# MY_PASSWORD = 'Aptech3510$'
# MY_PASSWORD = 'password'
MY_PASSWORD = '123'

# MYSQL SETTINGS
# MY_DEV_SQL_USER = 'intertek'
MY_DEV_SQL_USER = 'root'
MY_DEV_HOST = 'localhost'
MY_DEV_DBNAME = 'ingrid'
# MY_DEV_PASSWORD = 'Aptech3510$'
# MY_DEV_PASSWORD = 'password'
MY_DEV_PASSWORD = '123'

# ANALYTICS SETTINGS
ANALYTICS = 'GOOGLE_CLASSIC_ANALYTICS'
ACCOUNT = 'UA-46342606-3'

# ADMINISTRATOR
ADMINS = ['martin.gascon@intertek.com']

SQLALCHEMY_TRACK_MODIFICATIONS = False
# SQLALCHEMY_DATABASE_URI         = "mysql+pymysql://intertek:Aptech3510$@localhost/intergrid_db"
# SQLALCHEMY_DATABASE_URI         = "mysql+pymysql://root:password@localhost/ingrid"
SQLALCHEMY_DATABASE_URI = "mysql://root:123@localhost/ingrid"
