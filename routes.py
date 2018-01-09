# IMPORTS #################################################
from flask import render_template, \
    request,  flash,  session,  \
    abort,  url_for,  redirect,  \
    g,  json,  jsonify,  send_from_directory
from flask_login import login_user,  logout_user,  \
    current_user,  login_required
from forms import ContactForm,  BenchmarkForm,  \
    LoginForm,  RegisterForm,  \
    ForgotPasswordForm,  ResetForm,  \
    PlantForm,  AddBlogForm
from flask_mail import Message,  Mail
import pymysql as mdb

from werkzeug.utils import secure_filename
import os

from scipy import spatial
import pandas as pd
import numpy as np
import math
import difflib
import decimal
import datetime

import sys
reload(sys)
sys.setdefaultencoding('utf8')

import socket,  re,  random,  string
from flask_login import LoginManager
from models import User,  user_assets,  Blogs
from init import app,  db,  bc
from util import *

from sqlalchemy import create_engine
from sqlalchemy import desc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

app.config.from_pyfile('config.py')


##################################### SUPPORT FUCNTIONS #################################################
# human readable:  function to reduce large MWh numbers to smaller numbers and larger units
abv = [' MWh', ' GWh', ' TWh', ' PWh', ' EWh', ' ZWh']
def hr(n):
    n = float(n)
    mdx = max(0, min(len(abv)-1,  int(math.floor(0 if n == 0
                                                 else math.log10(abs(n))/3))))
    return '{:.0f}{}'.format(n / 10**(3 * mdx),  abv[mdx])


# function to calculate statistics from last year (for positive increase)
def calc_stat(a, b):
    if b!=0:
        c = int((a-b)/b*100)
        d = "asc"
        e = "green"
        if (a-b<0):
            c=-c
            d = "desc"
            e = "red"
    else:
        c="NA"
        d=""
        e=""
    return (int(a), c, d, e)


# function to calculate statistics from last year (for negative increase)
def calc_statn(a, b):
    if b!=0:
        c = int((a-b)/b*100)
        d = "asc"
        e = "red"
        if (a-b<0):
            c=-c
            d = "desc"
            e = "green"
    else:
        c="NA"
        d=""
        e=""
    return (int(a), c, d, e)


# Calculate the difference in percentage (for positive increase)
def rel_diff(a, b):
    if b!=0:
        c=int(abs(a-b)/((a+b)/2)*100)
        d="asc" 
        e = "green"
        if (a-b<0):
            d = "desc"
            e="red"
    else:
        c="NA"
        d=""
        e=""
    return (c, d, e)

# Calculate the difference in percentage (for negative increase)
def rel_diffn(a, b):
    if b!=0:
        c=int(abs(a-b)/((a+b)/2)*100)
        d="asc" 
        e = "red"
        if (a-b<0):
            d = "desc"
            e="green"
    else:
        c="NA"
        d=""
        e=""
    return (c, d, e)

##################################### FLASK EMAIL #################################################
mail = Mail()
app.secret_key = app.config["SECRET_KEY"]
mail.init_app(app)

##################################### FLASK LOGIN #################################################
login_manager = LoginManager()
login_manager.init_app(app)

###################################### EMAIL HANDLER #################################################

if not app.debug:
    import logging
    from logging.handlers import SMTPHandler
    mail_handler = SMTPHandler('127.0.0.1', 'server-error@example.com',
                               app.config["ADMINS"],
                               'YourApplication Failed')
    mail_handler.setLevel(logging.ERROR)
    app.logger.addHandler(mail_handler)


###################################### MYSQL CONFIGURATION #################################################
my_user = app.config["MY_SQL_USER"]
my_host = app.config["MY_HOST"]
my_dbname = app.config["MY_DBNAME"]
my_password = app.config["MY_PASSWORD"]

my_dev_user      = app.config["MY_DEV_SQL_USER"]
my_dev_host      = app.config["MY_DEV_HOST"]
my_dev_dbname    = app.config["MY_DEV_DBNAME"]
my_dev_password  = app.config["MY_DEV_PASSWORD"]


# Connect to the Database
from sys import platform
if platform == "linux" or platform == "linux2":
    if socket.gethostbyname(socket.gethostname())=="10.195.224.126":
        my_host="10.195.224.126"
    else:
        my_host = "localhost"
    db = mdb.connect(user=my_user,  host=my_host,  db=my_dbname,
                     password=my_password,  charset='utf8',
                     unix_socket="/var/run/mysqld/mysqld.sock")
    
elif platform == "darwin":
    my_host = "127.0.0.1"
    db = mdb.connect(user=my_user,  host=my_host,
                     db=my_dbname,   password=my_password)

elif platform == "win32":
    my_host = "127.0.0.1"
    db = mdb.connect( user=my_dev_user, 
                      host=my_dev_host, 
                      db=my_dev_dbname, 
                      password=my_dev_password)


################## FUNCTIONS TO QUERY THE DATABASE
def askDB(query,  db):
    
    with db:
        cur = db.cursor()
        db.ping(True)
        try:
            if cur.execute(query) > 0:
                return cur.fetchall()
            else:
                return None
        except:
            print "Unable to make this query."
            cur.close()
    
    return None

            
def create_db_session():

    engine = None

    # an Engine,  which the Session will use for connection resources
    if platform == "win32":
        engine = create_engine("mysql+pymysql://"+my_dev_user+":"
                               +my_dev_password+"@"+my_dev_host+"/"+my_dbname)
    else:
        engine = create_engine("mysql+pymysql://"+my_user+":"
                               +my_password+"@"+my_host+"/"+my_dbname)

    # create a configured "Session" class
    Session  = sessionmaker( bind=engine )

    # create a Session
    return Session()

################################################# AUTHENTICATION #################################################

# provide login manager with load_user callback


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# map login to login


@app.route('/logout',  methods=['GET',  'POST'])
def logout():

    if current_user.is_authenticated:
        logout_user()
        return redirect(url_for('index'))
    else:
        return 'User not authenticated,  go to <a href="/">index</a>'

    if current_user.is_authenticated:
        logout_user()
        return redirect(url_for('index'))
    else:
        return 'User not authenticated,  go to <a href="/">index</a>'

    if current_user.is_authenticated:
        print "current_user.is_authenticated -> True"
    else:
        print "current_user.is_authenticated -> False"

    username = request.form.get('username',  '',  type=str)
    password = request.form.get('password',  '',  type=str)

    print 'u=' + username + ' p='+password

    # filter User out of database through username
    user = User.query.filter_by(user=username).first()

    if user == None:
        return "Username does not exist. Please try again"
    elif bc.check_password_hash(user.password,  password):

        login_user(user)

        if current_user.is_authenticated:
            return "current_user.is_authenticated -> True"
        else:
            return "current_user.is_authenticated -> False"

    else:
        return "Wrong password. Please try again. " \
               "'\n' Warning: You can try up to three times. " \
               "After 5 attempts your account will be blocked. " \
               "If you have tried three times,  please use the Forgot " \
               "Username/Password link to receive a temporary password. " \
               "<a href='/login'>LOGIN</a> "


# map register to register
@app.route('/register_c',  methods=['GET'])
def register_c():

    email = request.args.get('email')
    token = request.args.get('token')

    # return 'email = ' + email + ' | token=' + token

    if not email or not token:
        return 'ERR: invalid input on r' \
               'egistration confirmation'

    user = g_user_by_email( email )

    if not user:
        return 'ERR: invalid email used for registration confirmation'

    if g_check_register_token( user,  token):

        user.state = USER_STATE.ACTIVE

        user.commit()

        return 'Registration confirmation ok. ' \
               'You may <a href="/login">login</a>.'

    else:
        return 'ERR: invalid token used for ' \
               'registration confirmation'


# map register to register
@app.route('/register',  methods=['GET',  'POST'])
def register():

    err = None

    # declare the form here
    form = RegisterForm(request.form)

    # validate_on_submit() checks if both http method is POST and the form is valid
    # on submit
    if request.method == 'POST': # if form.validate(): #form.validate_on_submit():

        # get form data and assign it to variables
        email = request.form.get('email'    ,    '',     type=str)
        name = request.form.get('name'     ,    '',     type=str) # this is for info ONLY
        username = request.form.get('username' ,    '',     type=str) # this is the login name
        company = request.form.get('company'  ,    '',     type=str)
        password = request.form.get('password' ,    '',     type=str)
        cpassword = request.form.get('cpassword',    '',     type=str)
        terms = request.form.get('terms'    ,    'off',  type=str)

        # check data for empty values 
        if ((len(email) == 0) or
            (len(name) == 0) or
            (len(username) == 0) or
            (len(company) == 0) or
            (len(password) == 0) or
            (terms != 'on') or
            (len(cpassword) == 0)
            ) :

            err = 'Mandatory data missing.<br />Thanks to provide all requested information and agree the terms of service.'
            return render_template('usermanagement/register.html',  form=form,  err=err)

        # check user / email is already taken
        if username_registerred( username ):
            err = ' Username ' + username + ' already in use,  please choose another one or if you wish to access the existing account,  enter the email address in our password reset form in the <a href="/login">login</a> page. You will then receive an email with instructions on how to reset the password.'
            return render_template('usermanagement/register.html',  form=form,  err=err)
 
        if email_registerred( email ):
            err = ' Email ' + email + ' already in use,  please choose ' \
                                      'another one or if you wish to access ' \
                                      'the existing account,  enter the email' \
                                      ' address in our password reset ' \
                                      'form in the <a href="/login">' \
                                      'login</a> page. You will then ' \
                                      'receive an email with instructions ' \
                                      'on how to reset the password.'
            return render_template('usermanagement/register.html',
                                   form=form,  err=err)

        # regex to check for e-mail syntax
        if not re.match("(^.+@{1}.+\.{1}.+)",  str(email)):
            err = "Invalid e-mail. Please try again."
            return render_template('usermanagement/register.html',
                                   form=form,  err=err)

        # check if passwords match
        if password != cpassword:
            err = "Passwords do no match. Please try again."
            return render_template('usermanagement/register.html',
                                   form=form,  err=err)

        # Check password quality
        if weak_password( password ):

            err = "Password strength is low. Please choose another one."
            return render_template('usermanagement/register.html',
                                   form=form,  err=err)
            
        # hash the password here (bcrypt has salting included)
        pw_hash = bc.generate_password_hash(password)

        # if form is valid and all verification is complete
        # create User object and give the parameters in order
        user = User(username,  pw_hash,  name,  email,  company)

        # Send an email to the admin every time an account was open @ the ingrid server.
        if my_host=="10.195.224.126":
            msg = Message("A new user has signed up for INGRID",
                          sender='ingrid.intertek@gmail.com',
                          recipients=[user.email])
            msg.body = "Username: " + username + "\nName: " + \
                       name+ "\nEmail: " + email + \
                       "\nCompany: " + company
            mail.send(msg)
        
        # create as user by default ..
        user.set_user_role()

        ###############################################################
        # http://docs.sqlalchemy.org/en/latest/orm/session_basics.html
        ###############################################################

        # my_user      = app.config["MY_SQL_USER"]
        # my_host      = app.config["MY_HOST"]
        # dbname       = app.config["MY_DBNAME"]
        # my_password  = app.config["MY_PASSWORD"]

        engine = None

	    # an Engine,  which the Session will use for connection resources
        if platform == "win32":
            engine = create_engine("mysql+pymysql://"+my_dev_user+":"+
                                   my_dev_password+"@"+my_dev_host+"/"+my_dbname)
        else:
            engine = create_engine("mysql+pymysql://"+my_user+":"
                                   +my_password+"@"+my_host+"/"+my_dbname)

        # create a configured "Session" class
        Session  = sessionmaker( bind=engine )

	    # create a Session
        session = Session()

        # check if user name exists or not
        dbuser = User.query.filter_by(user=username).first()
        if dbuser != None:
            err = 'Username already exist,  Please choose different name.'
            return render_template('usermanagement/register.html',
                                   form=form,  err=err)

        # check if email exists or not
        dbuser = User.query.filter_by(email=email).first()
        if dbuser != None:
            err = 'email already exists,  If you forgot your user name ' \
                  'please go to login page and click on forgot username/password.' \
                  ' <a href="/login">login</a>'
            return render_template('usermanagement/register.html',
                                   form=form,  err=err)

        user.fraud  = 0
        user.state  = USER_STATE.NOT_INIT
        
        # add User object to database
        session.add ( user )

        # commit change
        session.commit ( )

        link = 'http://localhost:8000/register_c?email='+user.email+\
               '&token='+g_register_token( user )

        try:

            # send message to user with the temporary password
            msg = Message("Ingrid Account Registration - Validation Required",
                          sender='ingrid.intertek@gmail.com',
                          recipients=[ user.email])
            msg.body = 'Thank you for registering at Ingrid. ' \
                       'Please click ' + link + ' to validate your ' \
                                                'email address and gain ' \
                                                'access to the INGRID ' \
                                                'website.\n\nAny ' \
                                                'questions about your ' \
                                                'account?,  please email ' \
                                                'ingrid.intertek@gmail.com. ' \
                                                '\n\nWarm regards,  ' \
                                                '\nThe Ingrid Team. '
            mail.send(msg)

            err = 'Registration is pending.<br/> To complete ' \
                  'registration please check your email and ' \
                  'validate your account. Depending on your email ' \
                  'filters,  this correspondence may go into your ' \
                  'spam folder. Please ensure that you check your ' \
                  'spam/junk folder if you do not receive these ' \
                  'emails in your inbox. <br />After you may <a ' \
                  'href="/login">login</a>.'

        except:
            err = 'User is registerred but confirmation ' \
                  'email was not sent due a system error.<br/> ' \
                  'Contact support to activate the account!'

    # render the register template
    return render_template('usermanagement/register.html',  form=form,  err=err)

# map login to login


@app.route('/login',  methods=['GET',  'POST'])
def login():

    err = None

    # this case is handled in view ( template )
    # if current_user.is_authenticated:
    #    err = 'User allready authenticated !'        

    # define login form here
    form = LoginForm(request.form)

    # check if both http method is POST and form is valid on submit
    if request.method == 'POST':

        # assign form data to variables
        username = request.form.get('username',  '',  type=str)
        password = request.form.get('password',  '',  type=str)

        # filter User out of database through username
	    # print username
        user = User.query.filter_by(user=username).first()

        if user == None:
            err = 'Username does not exist! <br/> Please try again.'
        
        elif user.state == USER_STATE.NOT_INIT:

            err = 'Username inactive !<br/> Please check ' \
                  'you email to confirm the registration.'

        # fraud
        # elif user.state == USER_STATE.INACTIVE:
        #
        #    err = 'Username inactive !<br/> We detect a fraud on this accout. Please contact support.'
                
        elif bc.check_password_hash(user.password,  password):

            # if we have any wrong pwd attempts for this user then clean it
            dbuser = wrongpwdcnt.query.filter_by(user=username).first()
            if dbuser != None:
                wrongpwdcnt.delete(dbuser)
            
            login_user(user)
            flash('You were successfully logged in')
            #return "Login ok"
            return redirect(url_for('dashboard'))
  
        else:

            # to make an entry in the db for each wrong pwd attempt
            dbuser = wrongpwdcnt.query.filter_by(user=username).first()

            # if no user in wrongpwdcnt,  add 1 attempt
            if dbuser == None:
                wrong_attempt_cnt = 1
                user = wrongpwdcnt(username,  wrong_attempt_cnt)
                wrongpwdcnt.save ( user )

            # if there was an attempt,  add +1 attempt
            else:
                dbuser.wrong_attempt_cnt += 1
                dbuser.commit()
                wrongpwdcnt.commit(dbuser);

            # we count again the number of attempts
            dbuser = wrongpwdcnt.query.filter_by(user=username).first()

            # if there is more than 3 attempts
            if dbuser.wrong_attempt_cnt >3:

                 # if there is more than 5 attempts (I don't
                 # think we ever reach this point because we erase user in the wrongpwd after 3 attempts)
                if dbuser.wrong_attempt_cnt >= 5:

                    # We are missing here the actual block here right?

                    # To unlock the user,  you have to delete the
                    #  entry for that user from wrongpwdcnt table and ask them to click on forgot pwd link.
                    err = "Your user name is blocked. <br /> " \
                          "Please contact admin from Intertek." \
                          " <martin.gascon@intertek.com>"

                # generate temporary password
                tmp_pwd = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(9))

                # this puts the temporary password in the wrongpwdcnt database
                dbuser1 = User.query.filter_by(user=username).first()
                dbuser1.password = bc.generate_password_hash(tmp_pwd)
                dbuser1.commit()

                # send message to user with the temporary password
                msg = Message("Ingrid username and temporary password",
                              sender='ingrid.intertek@gmail.com',
                              recipients=[user.email])
                msg.body = "Please use these credentials to login:" \
                           " \nUsername: "+dbuser.user +"\nTemp pwd: "+tmp_pwd+ \
                           "\nPlease reset your password using this link:" \
                           " http://ingrid.intertek.com/reset"
                mail.send(msg)

                # Delete user from wrongpwdcnt (this should be only if they successfully reset their account right?)
                wrongpwdcnt.delete(dbuser)

                err = "Temporary password sent to your mail. <br /> " \
                      "Please check it and reset your password."

            else:

                # we have less than 3 attempts
                # flash('Wrong password! <br/> Please try again')
                err = 'Wrong password! <br/> Please try again.'

            ############End adding by Udayini.######################
    # render template
    return render_template('usermanagement/login.html',  form=form,  err=err)


############Start adding by Udayini.######################
# map reset to reset
@app.route('/reset',  methods=['GET',  'POST'])
def reset():

    # Define reset form here
    form = ResetForm(request.form)

    page_msg = None
    page_err = None

    # check if both http method is POST and form is valid on submit
    if request.method == 'POST':

        # assign form data to variables
        username = request.form.get('username', '',  type=str)
        old_pass = request.form.get('password', '',  type=str)
        new_pass = request.form.get('npassword', '',  type=str)
        new_pass_c = request.form.get('cpassword', '',  type=str)

        dbuser = User.query.filter_by(user=username).first()

        # user is registerred ?
        if dbuser == None:
            # return "User name doesn't exists"
            page_err = "User name doesn't exists"

        # check the provided password 
        elif bc.check_password_hash(dbuser.password,  old_pass):

            # check pass && confirmed pass to be identical
            if len(new_pass) == 0:
                # return "New password must match with the confirm password"
                page_err = "New password is empty."
            
            elif new_pass != new_pass_c:
                # return "New password must match with
                # the confirm password"
                page_err = "New password must match with " \
                           "the confirm password."

            # pass is week ?
            elif weak_password( new_pass ):
                # return "New password must match
                # with the confirm password"
                page_err = "Password strength is low. " \
                           "Please choose another one."

            # all ok,  update the pass in db
            else:

                # dbuser = User.query.filter_by(user=username).first()
                dbuser.password = bc.generate_password_hash(new_pass)
                # dbuser.commit()
                User.commit(dbuser)

                # return "*** Password updated ***"
                page_msg = 'Password successfully updated. Pls login.'

            # return redirect(url_for('index'))

        else:

            # To make an entry in the db for each wrong pwd attempt
            dbuser1 = wrongpwdcnt.query.filter_by(user=username).first()
            if dbuser1 == None:
                wrong_attempt_cnt = 1
                user = wrongpwdcnt(username,  wrong_attempt_cnt)
                wrongpwdcnt.save ( user )
            else:
                dbuser1.wrong_attempt_cnt  += 1
                # dbuser1.commit()
                wrongpwdcnt.commit(dbuser1);

            dbuser1 = wrongpwdcnt.query.filter_by(user=username).first()
            if dbuser1.wrong_attempt_cnt >=5:
                tmp_pwd = ''.join(
                    random.choice(string.ascii_uppercase +
                                  string.digits) for _ in range(9))
                print tmp_pwd
                # dbuser1 = User.query.filter_by(user=username).first()
                dbuser.password = bc.generate_password_hash(tmp_pwd)
                # dbuser.commit()
                User.commit(dbuser)
                
                # To unlock the user,  you have to delete
                # the entry for that user from wrongpwdcnt table and ask them to click on forgot pwd link.
                # return "Your user name is blocked. Please
                # email ingrid.intertek@gmail.com.."
                page_err = "Your user name is blocked." \
                           " Please email ingrid.intertek@gmail.com.."

            else:    
                # return "Old password is wrong"
                page_err = "Old password is wrong"

    # render template
    return render_template( 'usermanagement/reset.html',  
                            form=form, 
                            page_msg=page_msg, 
                            page_err=page_err)


# map ForgotPassword to ForgotPassword
@app.route('/ForgotPassword',  methods=['GET',  'POST'])
def ForgotPassword():

    form     = ForgotPasswordForm(request.form)
    page_msg = None 
    page_err = None

    # check if both http method is POST and form is valid on submit
    if request.method == 'POST':

        # assign form data to variables
        # username = request.form.get('username',  '',  type=str)
        email = request.form.get('email',  '',  type=str)

        dbuser = User.query.filter_by(email=email).first()
        # subject = "Password sent to the email"

        # html = render_template('email/recover.html', recover_url=recover_url)
        if dbuser == None:
            #return "Email doesn't exists"
            page_err = "Email doesn't exists"

        elif email == dbuser.email:

            tmp_pwd = ''.join(random.choice(string.ascii_uppercase
                                            + string.digits) for _ in range(9))
            print tmp_pwd

            dbuser.password = bc.generate_password_hash(tmp_pwd)
            #dbuser.commit()
            User.commit(dbuser)

            #print "Need to send username, temppwd and reset link to email"

            msg = Message("Reset your INGRID Password",
                          sender='ingrid.intertek@gmail.com',
                          recipients=[dbuser.email])
            # msg.body = "Username:"+dbuser.user +"\nTemp pwd:"
            # +tmp_pwd+ "\nPlease reset your password using below link \n"+url_for('reset')
            msg.body = "Don't worry,  we all forget sometimes." \
                       "\n\nHi "+dbuser.name+", \n\nYou've recently asked to reset the password for this INGRID account:\n\nUsername: " + dbuser.user +"\n\nTo update your password,  use the following temporary password: " + tmp_pwd + "\n\nUsing this link http://ingrid.intertek.com/reset\n\nWarm Regards\nThe INGRID Team. \n\n\n If you did not make this request,  or if you have questions,  please email ingrid.intertek@gmail.com."

            mail.send(msg)

            #
            # return redirect(url_for('reset'))
            #
            # return "Username and temp password sent to your
            # mail. Please check it and try to <a href='/login'>LOGIN</a> again."
            page_msg  = "Username and temp password sent to " \
                        "your mail. <br/> Please check it and reset your password."

        else:
            return redirect(url_for('index'))

    # render template
    return render_template( 'usermanagement/ForgotPassword.html',  
                            form=form, 
                            page_msg=page_msg, 
                            page_err=page_err)

############End adding by Udayini.######################


################################################# ROUTES #################################################
#

@app.route('/')
@app.route('/index')
def index():

    # Query the plant names in the database
    qry1 = "select distinct(pname) from egrid14_plt order by pname;"
    res1 = askDB(qry1,  db) 

    # Query the plant names in the database
    plants = []   # Every plant in the grid
    
    if res1: # askDB return None if query return empty set
    	for r in res1:
    		plants.append(dict(name=r[0]))

    return render_template("index.html",  plants=plants,  mh=my_host)

@app.route('/input')
def input():

    # Query the plant names in the database
    qry1 = "select distinct(pname) from egrid14_plt order by pname;"
    res1 = askDB(qry1,  db)
    plants = []   # Every plant in the grid
    
    if res1: # askDB return None if query return empty set

    	for r in res1:
    		plants.append(dict(name=r[0]))

    return render_template("index.html",  plants=plants,  mh=my_host)

@app.route('/settings')
@login_required
def settings():

    if current_user.role == USER_ROLES.USER:

        assets,  ocodes,  gcodes = [],  [],  []

        # Assets for this user
        qry1 = "select * from user_assets where user = '%s';" % current_user.user
        res1 = askDB(qry1,  db)
        
        if res1: # askDB return None if query return empty set
            for r in res1:
                ocodes.append(r[3])
                gcodes.append(r[6])
                assets.append(dict(plant_id=r[3], fname=r[4],
                                   unit_id=r[5],  unit_code=r[6]))

        return render_template( "usermanagement/settings_user.html",  
                                assets=assets, 
                                current_page = 'settings')

    elif current_user.role == USER_ROLES.ADMIN or \
                    current_user.role == USER_ROLES.GROUP_MANAGER:
        
        assets,  ocodes,  gcodes = [],  [],  []

        # Assets for this user
        qry1 = "select * from user_assets;" 
        res1 = askDB(qry1,  db)
        
        if res1: # askDB return None if query return empty set
            for r in res1:
                ocodes.append(r[3])
                gcodes.append(r[6])
                assets.append(dict(plant_id=r[3], fname=r[4],
                                   unit_id=r[5],  unit_code=r[6]))

        return render_template("usermanagement/settings_user.html",  
                               assets=assets, 
                               current_page = 'settings')

    
@app.route('/dashboard',  methods=['GET',  'POST'])
@login_required
def dashboard():
    # Variable declaration
    global db
    
    clat= 40
    clon= -99
    minLng= -124
    minLat = 24
    maxLng = -66
    maxLat = 55    
        
    if current_user.role == USER_ROLES.USER:
        
        stats  = []
        assets = []
        plants = []
        ocodes,  gcodes = [],  []
        oper,  oper_col = [], []  # Operations from LM

        # Assets for this user
        qry1 = "select * from user_assets where " \
               "user = '%s';" % current_user.user
        res1 = askDB(qry1,  db)
        
        if res1: # askDB return None if query return empty set
            for r in res1:
                ocodes.append(r[3])
                gcodes.append(r[6])
                assets.append(dict(plant_id=r[3], fname=r[4],
                                   unit_id=r[5],  unit_code=r[6]))
                    
           
            # SELECT ALL PLANTS for the map
            qry2 = "select * from egrid14_plt_ingrid where " \
                   "orispl in (" +",  ".join(str(x) for x in ocodes) + ");"
            #print qry2
            res2 = askDB(qry2,  db)

        
            # askDB return None if query return empty set
            if res2: 

                for r in res2:
                    plants.append(dict(lat=r[0], lon=r[1], na=r[2],
                                       oc=r[3],  op=r[4], ne=r[5],
                                       cn=r[6], nblr=r[7], ngen=r[8],
                                       fuel=r[9], npc=r[10]))
                lats = [x['lat'] for x in plants]
                longs = [y['lon'] for y in plants]
                if len(lats)!=0:
                    clat = (float(min(lats))+float(max(lats)))/2
                    clon = (float(min(longs))+float(max(longs)))/2
                    minLng = float(max(longs))*1.01
                    minLat = float(min(lats))*0.99
                    maxLng = float(min(longs))*0.99
                    maxLat = float(max(lats))*1.01
                if minLng > maxLng:
                    aux = minLng
                    minLng=maxLng
                    maxLng=aux            
            


                # Let's calculate some stats for the dashboard. ###########################################
                # Total net-gen,  Cycling (EHS),  Starts,  etc

                # variable declaration
                ng0, ng1, ng2, ng3, da0, da1, da2, da3, st0, st1, st2, \
                st3, lf0, lf1, lf2, lf3, od0, od1, od2, od3, hs0, ws0, cs0, \
                hs1, ws1, cs1, hs2, ws2, cs2, hs3, ws3, cs3 = 0, 0, 0, 0, 0,\
                                                              0, 0, 0, 0, 0, 0,\
                                                              0, 0, 0, 0, 0, 0,\
                                                              0, 0, 0, 0, 0,\
                                                              0, 0, 0, 0, 0,\
                                                              0, 0, 0, 0, 0
                
                
                ### MAIN DASHBOARD STATS'S BLOCK
                # query the generation for the past two years and calculate the variation
                qry3 = "select sum(genn),  sum(damage),  sum(nom_starts),  " \
                       "sum(lf),  AVG(nom_op_days)*24,  sum(hs),  sum(ws),  " \
                       "sum(cs),  AVG(profact) from int_ann_gen_oper where " \
                       "gcode in (" +",  ".join(str(x) for x in gcodes) + ") " \
                                                                          "and year=2017;"
                new = askDB(qry3,  db)
                
                qry3 = "select sum(genn),  sum(damage),  sum(nom_starts),  " \
                       "sum(lf),  AVG(nom_op_days)*24,  sum(hs),  sum(ws)," \
                       "  sum(cs) from int_ann_gen_oper where gcode in " \
                       " (" +",  ".join(str(x) for x in gcodes) + ") " \
                                                                  "and year=2016;"
                old = askDB(qry3,  db)
                
                # index 0 is the actual value,  1 is the variation,  2 is asc/desc (if var>0 or var<0),  3 is green/red (if var>0 or var<0)
                [ng0,  ng1,  ng2,  ng3] = calc_stat (new[0][0],
                                                     int(float(old[0][0])/
                                                         float(new[0][8])))
                [da0,  da1,  da2,  da3] = calc_statn(new[0][1],
                                                     int(float(old[0][1])/
                                                         float(new[0][8])))
                [st0,  st1,  st2,  st3] = calc_statn(new[0][2],
                                                     int(float(old[0][2])/
                                                         float(new[0][8])))
                [lf0,  lf1,  lf2,  lf3] = calc_statn(new[0][3],
                                                     int(float(old[0][3])/
                                                         float(new[0][8])))
                [od0,  od1,  od2,  od3] = calc_stat (new[0][4],
                                                     int(float(old[0][4])/
                                                         float(new[0][8])))
                [hs0,  hs1,  hs2,  hs3] = calc_statn(new[0][5],
                                                     int(float(old[0][5])/
                                                         float(new[0][8])))
                [ws0,  ws1,  ws2,  ws3] = calc_statn(new[0][6],
                                                     int(float(old[0][6])/
                                                         float(new[0][8])))
                [cs0,  cs1,  cs2,  cs3] = calc_statn(new[0][7],
                                                     int(float(old[0][7])/
                                                         float(new[0][8])))
                
                
                #  Convert the value tu human readable
                ng0=hr(ng0)
                
                stats.append(dict(ng0=ng0,  ng1=ng1,  ng2=ng2,  ng3=ng3,
                                  da0=da0,  da1=da1,  da2=da2,  da3=da3,
                                  st0=st0,  st1=st1,  st2=st2,  st3=st3,
                                  lf0=lf0,  lf1=lf1,  lf2=lf2,  lf3=lf3,
                                  od0=od0,  od1=od1,  od2=od2,  od3=od3,
                                  hs0=hs0,  ws0=ws0,  cs0=cs0,  hs1=hs1,
                                  ws1=ws1,  cs1=cs1,   hs2=hs2,  ws2=ws2,
                                  cs2=cs2,   hs3=hs3,  ws3=ws3,  cs3=cs3))

        # I am passing not passing values yet,  but I will need to. I am faking them into the dashboard. 
        return render_template("usermanagement/dashboard_user.html", 
                              assets=assets, 
                              plants=json.dumps(plants), 
                              clat=clat, 
                              clon=clon, 
                              minLng = minLng, 
                              minLat = minLat, 
                              maxLng = maxLng, 
                              maxLat = maxLat, 
                              stats = stats, 
                              mh=my_host, 
                              current_page = 'dashboard')

    elif current_user.role == USER_ROLES.ADMIN:

        return render_template("usermanagement/settings_user.html",
                               current_page = 'settings')

    elif current_user.role == USER_ROLES.GROUP_MANAGER:

        dbuser = User.query.all()
        dropdown_list = ['Choose User']
        for u in dbuser:
            dropdown_list.append(u.user)  
            
        
        users=[]
        user_assets=[]
        assets=[]
        
        #assets = assets.query_all()
        qry1 = "select * from user;"
        res1 = askDB(qry1,  db)
        
        if res1: # askDB return None if query return empty set

            for r in res1:
                users.append(dict(id=r[0], name=r[7],
                                  user=r[1], email=r[2], role=r[4]))
        
        qry1 = "select * from assets ORDER BY rn DESC;"
        res1 = askDB(qry1,  db)

        if res1: # askDB return None if query return empty set
            for r in res1:
                assets.append(dict(gcode=r[1], ocode=r[2],
                                   fname=r[4], state=r[3],
                                   uid=r[5], ppf=r[6], pfc=r[7]))
        
         
        qry1 = "select * from user_assets;"
        res1 = askDB(qry1,  db)
        
        if res1: # askDB return None if query return empty set
            for r in res1:
                user_assets.append(dict(rn=r[0], user_id=r[1],
                                        user=r[2], plant_id=r[3],
                                        fname=r[4],  unit_id=r[5],
                                        unit_code=r[6],  admin_user=r[7],
                                        valid_from=r[8],
                                        valid_until=r[9]))
            
            
        #PlantForm
        form = PlantForm(request.form)

        if request.method == 'POST':
            user            = request.form.get('user',  '',
                                               type=str)
            plant_id        = request.form.get('plant_id',  '',
                                               type=str)
            valid_until     = request.form.get('valid_until',  '',
                                               type=str)
            
            #insertDB("user",  "martingascon")  # I'am not able to record into the database.
            try: 
                qry1 = "INSERT INTO user_assets (user,   " \
                       "admin_user,  valid_until) values " \
                       "(%s,  %s,  %s );" % ("martin.gascon",
                                             "martingascon",  "2017-01-01")
                #print qry1
                res1 = askDB(qry1,  db)
#                #insert into user_assets (user,  admin_user,  valid_until) values ();
            except:
                return "Could not save in the database"
            #u = user_assets(user,  plant_id )
            #user_assets.save (u)
            
            
        return render_template("usermanagement/dashboard_manager.html",  
                               users=users, 
                               assets=assets, 
                               user_assets=user_assets, 
                               form=form,  
                               dropdown_list=dropdown_list
                              )

    else:
        return "You don't have permissions to access the" \
               " dashboard! Please,  return <a href='/home'>HOME</a>."


@app.route('/dashboard_plant_operations')
@login_required
def dashboard_plant_operations(gcode_args=None):

    # Requested variable to identify the plant
    gcode = request.args.get('gcode')

    if not gcode and not gcode_args:
        return 'invalid input: gcode=Null'

    if not gcode:
        gcode = gcode_args
        #return 'dashboard_plant_operations() for ' + ocode_args + ' (inner call )'

    #return 'dashboard_plant_operations() for ' + ocode + ' (from GET)'

    #try:

    # variable declaration
    global db
    ocodes,  gcodes = [0], [0] # OCODES,  GCODES
    plts,  owns,  blrs,  gens = [], [], [], []   # PLANTS/OWNERS/BLRS/GENS FROM EGRID
    ptlsh,  ownsh,  gnrsh,  blrsh,   =[], [], [], []   # Header for PLANTS/OWNERS/BLRS/GENS
    aplts,  ablrs,  agens,  agensb,  acodes,  agenplt,  \
    agengen = [], [], [], [], [0], [], []  # ALL FROM EIA
    afuels = []  # ALL FROM EIA
    eplts,  eblrs,  egens,  ecodes = [], [], [], [0]  #  PLANTS/BLRS/GENS/OCODES FROM EPA
    oper,  oper_col = [], []  # Operations from LM

    # FIRST SELECT THE OCODE CORRESPONDING TO THAT GCODE
    qry1 = "select ocode FROM assets where gcode=%s;" % gcode
    res1 = askDB(qry1,  db)
    if res1:
        ocode = res1[0][0]
    # print ocode     

    # Define the Queries (all plants with this ocode). Including headers
    qry1 = "select * FROM egrid14_plt where orispl=%s;" % ocode
    qry2 = "select LFIELD,  UFIELD,  DEFINITION FROM egrid14_plt_header;"
    qry3 = "select * FROM egrid14_own where orispl=%s;" % ocode
    qry4 = "select LFIELD,  UFIELD,  DEFINITION FROM egrid14_own_header;"

    # Query the database
    res1 = askDB(qry1,  db)
    res2 = askDB(qry2,  db)
    res3 = askDB(qry3,  db)
    res4 = askDB(qry4,  db)

    # askDB return None if query return empty set
    if res1:  
        s = [2, 1, 10, 21]
        for n in range(0, len(s)):
            ptlsh.append(dict(na=res2[s[n]][0], fi=res2[s[n]][2],
                              un=res2[s[n]][1]))

        for r in res1:
            ocodes.append(r[4])
            plts.append(dict(na=r[3], st=r[2], op=r[5], us=r[7],
                             ne=r[11], nb=r[20], ng=r[21], pf=r[22],
                             fc=r[23]))

    if res3: 
        s = [4, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21,
             23, 24, 26, 27, 29, 30, 32, 33, 35]
        for n in range(0, len(s)):
            if res3[0][s[n]+1]==0 or res3[0][s[n]+1]=="" or res3[0][s[n]+1] is None:
                continue
            else:
                ownsh.append(dict(na=res4[s[n]][0], fi=res4[s[n]][2],
                                  un=res4[s[n]][1],  na2=res3[0][s[n]+1]))

    ################ EGRID BOILERS (Removed for the moment)  #####
    #Create the queries
    qry1 = "select * from egrid14_blr where ORISPL=%s;"  % ocode
    qry2 = "select LFIELD,  UFIELD,  DEFINITION FROM egrid14_blr_header;"

    # Query the database
    res1 = askDB(qry1,  db)
    res2 = askDB(qry2,  db)

    # if not empty fill the variables
    if res1:
        s = [4, 6, 5, 11, 28]
        for n in range(0, len(s)):
            blrsh.append(dict(na=res2[s[n]][0], fi=res2[s[n]][2],
                              un=res2[s[n]][1]))
        for r in res1:
            blrs.append(dict(bid=r[5], pm=r[6], us=r[7], fu=r[12], yo=r[29]))

    ########### EGRID GENERATORS (Included all the generators for this plants) #####

    qry1 = "select * from egrid14_gnr where ORISPL=%s;"  % ocode
    qry2 = "select LFIELD,  UFIELD,  DEFINITION FROM egrid14_gnr_header;"

    res1 = askDB(qry1,  db)
    res2 = askDB(qry2,  db)

    if res1: # askDB return None if query return empty set
        s = [4, 6, 7, 8, 14]
        for n in range(0, len(s)): gnrsh.append(dict(na=res2[s[n]][0],
                                                     fi=res2[s[n]][2],
                                                     un=res2[s[n]][1]))
        for r in res1:
            gens.append(dict(gid=r[5], gs=r[7], pm=r[8],  fu=r[9], yo=r[15]))

    ##### EIA ANNUAL AND MONTHLY GENERATION #####
    qry1 = "select * from eia_mon_gen where plant_id=%s " \
           "and date<'2016-07-01';"  % ocode
    qry2 = "select distinct(gid) from eia_mon_gen where" \
           " plant_id=%s;"  % ocode
    qry3 = "select * from eia_ann_gen_plt where " \
           "plant_id=%s;"  % ocode
    qry4 = "select * from eia_ann_fuel_plt where " \
           "plant_id=%s;"  % ocode

    # Each individual query can be NONE
    res1 = askDB(qry1,  db)  
    res2 = askDB(qry2,  db)  
    res3 = askDB(qry3,  db)  
    res4 = askDB(qry4,  db)  

    colors=['#AA0000',  '#0000AA',  '#0AA000',   '#8C0B90', '#CF95D7',
            '#AD6D70', '#BC2500', '#F6CC1D',  '#C0E4FF',  '#2AB502',
            '#7C60A8',   '#37AB65',  '#3DF735', '#FF0000',  '#00FF00',
            '#0000FF',  '#8C0B90', '#CF95D7',  '#AD6D70', '#BC2500',
            '#F6CC1D',  '#C0E4FF',  '#2AB502',  '#7C60A8',   '#37AB65',
            '#3DF735', '#FF0000',  '#00FF00',  '#0000FF',  '#8C0B90',
            '#CF95D7',  '#AD6D70', '#BC2500', '#F6CC1D',  '#C0E4FF',
            '#2AB502',  '#7C60A8',   '#37AB65',  '#3DF735', '#FF0000',
            '#00FF00',  '#0000FF',  '#8C0B90', '#CF95D7',  '#AD6D70',
            '#BC2500', '#F6CC1D',  '#C0E4FF',  '#2AB502',  '#7C60A8',
            '#37AB65',  '#3DF735', '#FF0000',  '#00FF00',  '#0000FF',
            '#8C0B90', '#CF95D7',  '#AD6D70', '#BC2500', '#F6CC1D',
            '#C0E4FF',  '#2AB502',  '#7C60A8',   '#37AB65',  '#3DF735',
            '#FF0000',  '#00FF00',  '#0000FF',  '#8C0B90', '#CF95D7',
            '#AD6D70', '#BC2500', '#F6CC1D',  '#C0E4FF',  '#2AB502',
            '#7C60A8',   '#37AB65',  '#3DF735', '#FF0000',  '#00FF00',
            '#0000FF',  '#8C0B90', '#CF95D7',  '#AD6D70', '#BC2500',
            '#F6CC1D',  '#C0E4FF',  '#2AB502',  '#7C60A8',   '#37AB65',
            '#3DF735', '#FF0000',  '#00FF00',  '#0000FF',  '#8C0B90',
            '#CF95D7',  '#AD6D70', '#BC2500', '#F6CC1D',  '#C0E4FF',
            '#2AB502',  '#7C60A8',   '#37AB65',  '#3DF735', '#FF0000',
            '#00FF00',  '#0000FF',  '#8C0B90', '#CF95D7',  '#AD6D70',
            '#BC2500', '#F6CC1D',  '#C0E4FF',  '#2AB502',  '#7C60A8',
            '#37AB65',  '#3DF735']

    # check for Nulls 
    if res1:
        for a in res1:
            agens.append(dict(oc=a[0], gid=a[1], date=a[2], gen=a[3]))

    if res2:
        for idx, b in enumerate(res2):
            agensb.append(dict(gid=b[0], co=colors[idx]))

    if res3:   
        for a in res3:
            agenplt.append(dict(pid=a[0], na=a[1], year=a[2], gen=a[3]))

    if res4:        
        for a in res4:
            afuels.append(dict(pid=a[0],  na=a[1],  sn=a[2],  rf=a[3],
                               pu=a[4],  tfq=a[5],  efq=a[6],  tfm=a[7],  efm=a[8],
                               ng=a[9],  yr=a[10]))


    ##### INTERTEK OPERATIONS #################################################################

    # Create queries for a specific operation's plant & query the database
    qry1 = "select * from int_ann_gen_oper where gcode=%s;" % gcode
    res1 = askDB(qry1,  db)  

    if res1:
        # Fill the variables
        for a in res1:
            oper.append(dict(ui=a[20],  yr=a[1],  genn=a[13],
                             dam=a[14],  starts=a[7],  lf=a[11],
                             hs=a[8],  ws=a[9],  cs=a[10],  od=(a[6]/(a[3]-a[4])*100),
                             cf=a[23],  uf=a[24]))

    #  get max and min yr from oper and add it to unit info 
    qry1 = "select min(year), max(year) from int_ann_gen_oper where gcode=%s;" % gcode
    res1 = askDB(qry1,  db) 
    yrmin = res1[0][0]
    yrmax = res1[0][1]


    # Let's calculate some stats for the dashboard. ###########################################
    # Total net-gen,  Cycling (EHS),  Starts,  etc

    # variable declaration
    ng0, ng1, ng2, ng3, da0, da1, da2, da3, \
    st0, st1, st2, st3, lf0, lf1, lf2, lf3, od0, od1, \
    od2, od3, hs0, ws0, cs0, hs1, ws1, cs1, hs2, ws2, \
    cs2, hs3, ws3, cs3= 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,\
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                        0, 0, 0, 0, 0, 0, 0, 0, 0
    cf0, cf1, cf2, cf3, uf0, uf1, uf2, uf3 = 0, 0, 0, 0, \
                                             0, 0, 0, 0
    
    ### 1ST STATS'S BLOCK (just the report date),  2ND is Nom Days
    
    ### 3rd-12th STATS BLOCKs
    # query the generation for the past two years and calculate the variation
    qry1 = "select sum(genn),  sum(damage),  avg(CF),  " \
           "sum(nom_starts),  sum(lf),  AVG(nom_op_days)*24,  " \
           "avg(UF),  sum(hs),  sum(ws),  sum(cs),  AVG(profact) " \
           "from int_ann_gen_oper where gcode = %s and year=2017;"  % gcode 
    new = askDB(qry1,  db)
    
    qry2 = "select sum(genn),  sum(damage),  avg(CF),  " \
           "sum(nom_starts),  sum(lf),  AVG(nom_op_days)*24,  " \
           "avg(UF),  sum(hs),  sum(ws),  sum(cs) from int_ann_gen_oper" \
           " where gcode = %s and year=2016;"  % gcode 
    old = askDB(qry2,  db)
    
    
    # index 0 is the actual value,  1 is the variation,  2 is asc/desc (if var>0 or var<0),  3 is green/red (if var>0 or var<0)
    [ng0,  ng1,  ng2,  ng3] = calc_stat (new[0][0], 
                                      int(float(old[0][0])/float(new[0][10])))
    [da0,  da1,  da2,  da3] = calc_statn(new[0][1],  
                                      int(float(old[0][1])/float(new[0][10])))
    [cf0,  cf1,  cf2,  cf3] = calc_statn(new[0][2],  
                                      int(float(old[0][2])/float(new[0][10])))  
    [st0,  st1,  st2,  st3] = calc_statn(new[0][3],  
                                      int(float(old[0][3])/float(new[0][10])))
    [lf0,  lf1,  lf2,  lf3] = calc_statn(new[0][4],  
                                      int(float(old[0][4])/float(new[0][10])))
    [od0,  od1,  od2,  od3] = calc_stat (new[0][5],  
                                      int(float(old[0][5])/float(new[0][10])))
    [uf0,  uf1,  uf2,  uf3] = calc_stat (new[0][6],  
                                      int(float(old[0][6])/float(new[0][10])))
    [hs0,  hs1,  hs2,  hs3] = calc_statn(new[0][7],  
                                      int(float(old[0][7])/float(new[0][10])))
    [ws0,  ws1,  ws2,  ws3] = calc_statn(new[0][8],  
                                      int(float(old[0][8])/float(new[0][10])))
    [cs0,  cs1,  cs2,  cs3] = calc_statn(new[0][9],  
                                      int(float(old[0][9])/float(new[0][10])))
       
        
    #  Convert the value tu human readable
    ng0=hr(ng0)

    qry1 =  "select updated,  nom_days - miss_days" \
            " from int_ann_gen_oper where gcode = %s and year=2017;"  % gcode
    report = askDB(qry1,  db)
    up = report[0][0] 
    ndays= report[0][1]
 
    stats = []

    stats.append(dict(ng0=ng0,  ng1=ng1,  ng2=ng2,  ng3=ng3,  
                      da0=da0,  da1=da1,  da2=da2,  da3=da3,  st0=st0,  
                      st1=st1,  st2=st2,  st3=st3,  lf0=lf0,  
                      lf1=lf1,  lf2=lf2,  lf3=lf3,  od0=od0,  
                      od1=od1,  od2=od2,  od3=od3,  hs0=hs0,  
                      ws0=ws0,  cs0=cs0,  hs1=hs1,  ws1=ws1,  
                      cs1=cs1,   hs2=hs2,  ws2=ws2,  cs2=cs2,   
                      hs3=hs3,  ws3=ws3,  cs3=cs3,  cf0=cf0,  
                      cf1=cf1,  cf2=cf2,  cf3=cf3,  uf0=uf0,  uf1=uf1, 
                      uf2=uf2,  uf3=uf3,  up=up,  ndays=ndays))

            #####################################################################


    # Select unit_info from my assets and query DB
    qry1 = "select * from assets where gcode=%s;" % gcode
    res1 = askDB(qry1,  db) 

    # Load info for this asset
    unit_info=[]

    if res1:
        for a in res1:
            unit_info.append(dict(gcode=a[1],  ocode=a[2],  
                                  pname=a[4],  uid=a[5],  prmvr=a[6],  fuel
                                  =a[7],  
                                  untyronl=a[8],  npc=a[9],  yrmin=yrmin,  
                                  yrmax=yrmax))

        # take prmvr and fuel to subset
        prmvr = res1[0][6]
        fuel = res1[0][7]

        # Our reference point (age and capacity of this unit)
        ref = [res1[0][8], res1[0][9]]

        # Select all the units,  yronl and npc to compare with same prmvr and fuel & query the database
        qry2 = "select gcode,  untyronl,  npc from assets w" \
               "here prmvr='%s' and fuel='%s' and gcode<99999;" % \
               (prmvr, fuel)
        res2 = askDB(qry2,  db)

        list = []

        # Number of points or units to compare with (let's get a sense of how many do we need)
        N = 10

        if res2:
            for r in res2:
                list.append(r)

            A = np.array(list)
            B = A[:, 1:3] 

            # find 10 nearest points
            selection = B[spatial.KDTree(B).query(ref, k=N)[1]]
            #print(B[spatial.KDTree(B).query(pt, k=10)[1]])

            # calculate the distances and the indexes
            distance, index = spatial.KDTree(B).query(ref, k=N)

            # Use those codes from the selection (+ transform to int)
            selected_gcodes = A[index, 0:1].astype(int)

            # Convert from numpy to vector
            selected_gcodes = selected_gcodes.flatten()

            # Max and Min values of year
            yrx,  npcx = selection.max(axis=0).astype(int)
            yrm,  npcm = selection.min(axis=0).astype(int)

            # Infor for the comparison text
            comp_text = []
            comp_text.append(dict(n=N,  fuel=fuel,  prmvr=prmvr,  
                                  yrx=yrx,  npcx=npcx, yrm=yrm, npcm=npcm))

            # Create queries for operations of selected units & query the database
            qry3 = "select * from int_ann_gen_oper " \
                   "where gcode in (" +",  ".join(str(x) 
                                                 for x in selected_gcodes) + ");"
            res3 = askDB(qry3,  db)  
            #print selected_gcodes
            # Load here the operations with these N plants
            oper_comp =[]
            
            lookup = {}
            
            # Look up table to hide gcodes (let's numerate them.)
            for idx, a in enumerate(selected_gcodes):
                lookup[str(a)]=idx+1
    
            if res3:
                # Fill the variables (divide by N to normalize by number of units)
                for idx, a in enumerate(res3):
                    if (a[3]-a[4])!=0:
                        oper_comp.append(dict(ui=a[0],  yr=a[1],  genn=a[13],  
                                              dam=a[14],  starts=a[15],  lf=a[19],  
                                              hs=a[16],  ws=a[17],  cs=a[18],  
                                              od=(a[6]/(a[3]-a[4])*100), 
                                              cf=a[23],  uf=a[24],  ut="Unit %s, "
                                                                     " Year: %s " %
                                                                     (lookup[str
                                                                     (a[0])], 
                                                                      a[1]))) 
                    else:
                        oper_comp.append(dict(ui=a[0],  yr=a[1],  genn=a[13],  
                                              dam=a[14],  starts=a[15],  lf=a[19], 
                                              hs=a[16],  ws=a[17],  cs=a[18],  od=0,   
                                              cf=a[23],  uf=a[24],  ut="Unit %s,  "
                                                                     "Year: %s " % (
                                lookup[str(a[0])],  
                                a[1])))
              
            # Now we have to pass the averages and relative changes for the summary plot
            oper_data = []

            
             # Let's define variables
            hs1, ws1, cs1, da1, st1, lf1, od1, ge1, cf1, uf1 = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            hs2, ws2, cs2, da2, st2, lf2, od2, ge2, cf2, uf2 = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            hsv, wsv, csv, dav, stv, lfv, odv, gev, cfv, ufv = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            rda, rhs, rws, rcs, rst, rlf, rod, rge, rcf, ruf = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            das="desc"
            dac="green"
            sts="desc"
            stc="green"
            hss="desc"
            hsc="green"
            wss="desc"
            wsc="green"
            css="desc"
            csc="green" 
            lfs="desc"
            lfc="green"
            ods="desc"
            odc="green"          
            cfs="desc"
            cfc="green"              
            ufs="desc"
            ufc="green"  
            
            qry3 = "select AVG(hs),  AVG(ws),  AVG(cs),  AVG(damage), " \
                   " AVG(starts),  AVG(lf),  AVG(nom_op_days/nom_days)*100,  " \
                   "AVG(gen),  avg(CF),  avg(UF) from int_ann_gen_oper where " \
                   "gcode= %s;" % gcode
            r = askDB(qry3,  db)
            
            # for my unit
            hs1=round(float(r[0][0]), 1)
            ws1=round(float(r[0][1]), 1)
            cs1=round(float(r[0][2]), 1)
            da1=round(float(r[0][3]), 1)
            st1=round(float(r[0][4]), 1)
            lf1=round(float(r[0][5]), 1)
            od1=round(float(r[0][6]), 1)
            ge1=round(float(r[0][7]), 1)
            cf1=round(float(r[0][8]), 1)
            uf1=round(float(r[0][9]), 1)

            
            
            
            qry3 = "select AVG(hs),  AVG(ws),  AVG(cs),  AVG(damage),  AVG(starts),  " \
                   "AVG(lf),  AVG(nom_op_days/nom_days)*100,  AVG(gen),  avg(CF),  " \
                   "avg(UF) from int_ann_gen_oper where gcode in" \
                   " (" +",  ".join(str(x) for x in selected_gcodes) + ");"
            r = askDB(qry3,  db)

            # for the comparison units
            hs2=round(float(r[0][0]), 1)
            ws2=round(float(r[0][1]), 1)
            cs2=round(float(r[0][2]), 1)
            da2=round(float(r[0][3]), 1)
            st2=round(float(r[0][4]), 1)
            lf2=round(float(r[0][5]), 1)
            od2=round(float(r[0][6]), 1)
            ge2=round(float(r[0][7]), 1)
            cf2=round(float(r[0][8]), 1)
            uf2=round(float(r[0][9]), 1)

            [dav, das, dac] = rel_diffn(da1, da2)
            [stv, sts, stc] = rel_diffn(st1, st2)
            [hsv, hss, hsc] = rel_diffn(hs1, hs2)
            [wsv, wss, wsc] = rel_diffn(ws1, ws2)               
            [csv, css, csc] = rel_diffn(cs1, cs2)     
            [lfv, lfs, lfc] = rel_diffn(lf1, lf2)               
            [gev, ges, gec] = rel_diff(ge1, ge2)        
            [cfv, cfs, cfc] = rel_diff(cf1, cf2)               
            [ufv, ufs, ufc] = rel_diff(uf1, uf2)       
            
        
            if da1 and da2:
                if da2!=0:
                    rda=int(da1/da2*100)
            if st1 and st2:
                if st2!=0:
                    rst=int(st1/st2*100)
            if hs1 and hs2:
                if hs2!=0:
                    rhs=int(hs1/hs2*100)
            if ws1 and ws2:
                if ws2!=0:
                    rws=int(ws1/ws2*100)
            if cs1 and cs2:
                if cs2!=0:
                    rcs=int(cs1/cs2*100)
            if lf1 and lf2:
                if lf2!=0:
                    rlf=int(lf1/lf2*100)   
            if od1 and od2:
                if od2!=0:
                    rod=int(od1/od2*100)
            if ge1 and ge2:
                if ge2!=0:
                    rge=int(ge1/ge2*100)  
            if cf1 and cf2:
                if cf2!=0:
                    rcf=int(cf1/cf2*100)
            if uf1 and uf2:
                if uf2!=0:
                    ruf=int(uf1/uf2*100)  
                
            selected_gcodes = np.append(selected_gcodes,  gcode)
            
            qry3 = "select gcode,  AVG(damage) as dam " \
                   "from int_ann_gen_oper where gcode in " \
                   "(" +",  ".join(str(x) for x in selected_gcodes) \
                   + ") group by gcode order by dam;"
            res3 = askDB(qry3,  db)
 
            # Let's do the ranking by damage
            ranking = []
            if res3:
                for idx,  r in enumerate(res3):
                    if (str(r[0])==str(gcode)):
                        ranking.append(dict(rank=int(idx+1),  
                                            unit="Your Unit",   dam=r[1]))
                    else:
                        ranking.append(dict(rank=int(idx+1),  
                                            unit="Your Peers",   dam=r[1]))


            # put all the values in a dictionary
            oper_data.append(dict(da1=da1,  st1=st1,  hs1=hs1,  ws1=ws1,  cs1=cs1,  
                                  lf1=lf1,  od1=od1,  ge1=hr(ge1), cf1=cf1,  
                                  uf1=uf1,   
                                  da2=da2,  st2=st2,  hs2=hs2,  ws2=ws2,  cs2=cs2, 
                                  lf2=lf2,  od2=od2,  ge2=hr(ge2), cf2=cf2,  uf2=uf2, 
                                  dav=dav,  stv=stv,  hsv=hsv,  wsv=wsv,  
                                  csv=csv,  lfv=lfv,  odv=odv,  gev=gev,  
                                  cfv=cfv,  ufv=ufv, 
                                  das=das,  dac=dac,  sts=sts,  stc=stc,  
                                  hss=hss,  hsc=hsc,  wss=wss,  wsc=wsc,  
                                  css=css,  csc=csc,  
                                  lfs=lfs, lfc=lfc,  ods=ods,  odc=odc,   
                                  ges=ges,  gec=gec,  cfs=cfs,  cfc=cfc,  
                                  ufs=ufs,  ufc=ufc,  
                                  rda=rda,  rst=rst,  rhs=rhs,  rws=rws,  
                                  rcs=rcs,  rlf=rlf,  rod=rod,  rge=rge,  
                                  rcf=rcf,  ruf=ruf))            


    return render_template("usermanagement/dashboard_plant_operations.html", 
            current_page = 'plant_operations', 
            plts=  plts, 
            ptlsh= ptlsh, 
            owns = owns, 
            ownsh= ownsh, 
            blrs=  blrs, 
            blrsh= blrsh, 
            gens=  gens, 
            gnrsh= gnrsh, 
            aplts= aplts, 
            agens= agens, 
            agensb= agensb, 
            agengen = agengen, 
            agenplt = agenplt, 
            afuels = afuels, 
            ablrs= ablrs, 
            eplts= eplts, 
            oper = oper, 
            oper_comp= oper_comp, 
            oper_col= oper_col, 
            unit_info = unit_info, 
            comp_text = comp_text, 
            oper_data=oper_data, 
            ranking=ranking, 
            stats=stats, 
            mh=my_host)
    #except:
     #   return ' Error processing dashboard plant operations,  code = ' + str(ocode)   

# ajax entry point
@app.route('/api',  methods=['POST'])
def ajax_router():

    section     = request.form[ 'section'   ] # useless ?!
    action      = request.form[ 'action'    ] # ajax action
    data        = request.form[ 'data'      ] # data to be used
    data2       = request.form[ 'data2'     ] # data to be used

    update_ts   = time.time()

    # some validation ?!

    status      = STATUS.OK
    status_info = 'NA'

    # update name for user
    if COMMON.OPER_UPDATE_NAME == action:

        user_id = int(data)

        if STATUS.OK == set_name(user_id,  data2 ) :

            # update status ..
            status = STATUS.OK
            status_info = 'Name updated successfully'

        else:
            status = STATUS.ERR
            status_info = 'Error updating name'

        return jsonify( section=section , 
                        action=action   , 
                        status=status   , 
                        status_info=status_info )

    # update username for user
    elif COMMON.OPER_UPDATE_USERNAME == action: # used in login

        user_id = int(data)

        if STATUS.OK == set_username(user_id,  data2 ) :

            # update status ..
            status = STATUS.OK
            status_info = 'Username updated successfully'

        else:
            status = STATUS.ERR
            status_info = 'Error updating username'

        return jsonify( section=section , 
                        action=action   , 
                        status=status   , 
                        status_info=status_info )

    # update company for user
    elif COMMON.OPER_UPDATE_COMPANY == action: # used in login

        user_id = int(data)

        if STATUS.OK == set_company(user_id,  data2 ) :

            # update status ..
            status = STATUS.OK
            status_info = 'Company updated successfully'

        else:
            status = STATUS.ERR
            status_info = 'Error updating company'

        return jsonify( section=section , 
                        action=action   , 
                        status=status   , 
                        status_info=status_info )
    
    
    # update pass for user
    elif COMMON.OPER_UPDATE_PASS == action: # used in login

        user_id  = int(data)
        new_pass = data2 

        user = g_user_by_id( user_id )

        if not user:

            status = STATUS.ERR
            status_info = 'Error updating passwd ( user not found = '+data+' in database ).'
         
        elif weak_password( new_pass ):

            status = STATUS.ERR
            status_info = 'Error updating passwd ( passwd too weak ).'

        else:

            # set update ts     
            user.lastupdate     = update_ts
            user.lastupdate_pwd = update_ts

            user.password = bc.generate_password_hash( new_pass )

            # commit changes  
            user.commit()

            # update status ..
            status = STATUS.OK
            status_info = 'Passwd updated successfully'

        return jsonify( section=section , 
                        action=action   , 
                        status=status   , 
                        status_info=status_info )

    # update username for user
    elif COMMON.OPER_UPDATE_EMAIL == action: 

        # read input data ..
        user_id   = int(data)
        new_email = data2

        # do some checks
        user     = g_user_by_id( user_id )
        tmp_user = g_user_by_email( new_email )

        # dummy .. case
        if user.email == new_email:

            status = STATUS.ERR
            status_info = 'Error updating email (same as old one)'

        # new email already used by another user
        elif tmp_user and ( tmp_user.id != user ):

            status = STATUS.ERR
            status_info = 'Error updating email (eMail already used by another user)'

        # new email is valid ?!
        elif not is_valid_email( new_email ):

            status = STATUS.ERR
            status_info = 'Error updating email (not a valid eMail address)'

        # all ok ..
        else:

            user.email = new_email

            # set update ts     
            user.lastupdate = update_ts
            
            user.commit()

            status = STATUS.OK   
            status_info = 'Email updated successfully'

        return jsonify( section=section , 
                        action=action   , 
                        status=status   , 
                        status_info=status_info )

    elif COMMON.OPER_DASHBOARD_PLANT_OPERATIONS == action:

        return jsonify( section=section , 
                        action=action , 
                        status=status , 
                        status_info=status_info, 
                        response=dashboard_plant_operations( data ) )

    else:

        return jsonify( section=section , 
                        action=action, 
                        status=STATUS.ERR , 
                        status_info='Unknown action ..' )


@app.route('/map_search')
def map_search():

    global db
    # SELECT ALL PLANTS
    qry1 = "select * from egrid14_plt_ingrid;"
    res1 = askDB(qry1,  db)
    plants = []   # positions of every plant in the grid
    clat= 40
    clon= -99
    minLng= -124
    minLat = 24
    maxLng = -66
    maxLat = 55

    if res1:

    	for r in res1:
    		plants.append(dict(lat=r[0],  lon=r[1],  na=r[2],  oc=r[3],  op=r[4],  
                               ne=r[5],  cn=r[6],  nblr=r[7],  
                               ngen=r[8],  fuel=r[9],  npc=r[10]))
        lats = [x['lat'] for x in plants]
        longs = [y['lon'] for y in plants]
        if len(lats)!=0:
            clat = (float(min(lats))+float(max(lats)))/2
            clon = (float(min(longs))+float(max(longs)))/2
            minLng = float(max(longs))*1.01
            minLat = float(min(lats))*0.99
            maxLng = float(min(longs))*0.99
            maxLat = float(max(lats))*1.01
        if minLng > maxLng:
            aux = minLng
            minLng=maxLng
            maxLng=aux

    return render_template("map_search.html", 
                           plants=json.dumps(plants), 
                           clat=clat, 
                           clon=clon, 
                           minLng = minLng, 
                           minLat = minLat, 
                           maxLng = maxLng, 
                           maxLat = maxLat, 
                           mh=my_host)


# Advanced search form
@app.route('/adv_search')
def adv_search():

    # Select all the plant names to show in the form
    qry1 = "select distinct(pname) from egrid14_plt order by pname;"
    res1 = askDB(qry1,  db)

    # Select all the operators to show in the form
    qry2 = "select distinct(oprname) from egrid14_plt order by oprname;"
    res2 = askDB(qry2,  db)

    # Select all the utility service territory names to show in the form
    qry3 = "select distinct(utlsrvnm) from egrid14_plt order by utlsrvnm;"
    res3 = askDB(qry3,  db)

    # variables to use
    plants,  opers,  userv = [], [], []   # plants,  operators UServices

    # if they are not empty,  fill the variables
    if res1:
    	for r in res1:
    		plants.append(dict(name=r[0]))

    if res2:
    	for r in res2:
    		opers.append(dict(op=r[0]))

    if res3:
    	for r in res3:
    		userv.append(dict(us=r[0]))

    return render_template("adv_search.html",   plants=plants,  
                           opers=opers,  userv = userv,  mh=my_host)



# Output of the quick search button on the nav-bar 
@app.route('/output')
def output():

    # Let's define some variables.
    
    NERC_regions = ["ASCC",  "SERC",  "WECC",  "RFC",  "NPCC",  
                    "FRCC",  "HICC",  "MRO",  "TRE"]
    
    FUELS = ["BIOMASS",  "COAL",  "GAS",  "GEOTHERMAL",  "HYDRO",  "NUCLEAR",  
             "OFSL",  "OIL",  "OTHF",  "SOLAR",  "WIND"]
    
    STATES = ["AK",  "ALASKA",  "AL",  "ALABAMA",  "AR",  "ARKANSAS",  "AZ",  
              "ARIZONA",  "CA",  "CALIFORNIA",  "CO",  "COLORADO",  "CT",  
              "CONNECTICUT",  "DC",  "DISTRICT OF COLUMBIA",  "DE",  "DELAWARE", 
              "FL",  "FLORIDA",  "GA",  "GEORGIA",  "HI",  "HAWAII",  "IA",  
              "IOWA",  "ID",  "IDAHO",  "IL",  "ILLINOIS",  "IN",  "INDIANA",  
              "KS",  "KANSAS",  "KY",  "KENTUCKY",  "LA",  "LOUISIANA",  "MA",  
              "MASSACHUSETTS",  "MD",  "MARYLAND",  "ME",  "MAINE",  "MI",  "MICHIGAN",  
              "MN",  "MINNESOTA",  "MO",  "MISSOURI",  "MS",  "MISSISSIPPI",  "MT",  
              "MONTANA",  "NC",  "NORTH CAROLINA",  "ND",  "NORTH DAKOTA",  "NE",  
              "NEBRASKA",  "NH",  "NEW HAMPSHIRE",  "NJ",  "NEW JERSEY",  "NM",  
              "NEW MEXICO",  "NV",  "NEVADA",  "NY",  "NEW YORK",  "OH",  "OHIO",  
              "OK",  "OKLAHOMA",  "OR",  "OREGON",  "PA",  "PENNSYLVANIA",  "PR",  
              "PUERTO RICO",  "RI",  "RHODE ISLAND",  "SC",  "SOUTH CAROLINA",  "SD",  
              "SOUTH DAKOTA",  "TN",  "TENNESSEE",  "TX",  "TEXAS",  "UT",  "UTAH",  "VA",  
              "VIRGINIA",  "VT",  "VERMONT",  "WA",  "WASHINGTON",  "WI",  "WISCONSIN",  
              "WV",  "WEST VIRGINIA",  "WY",  "WYOMING"]
    
    # variable declaration
    global db
    ocodes= [0] # OCODES
    plts,  ptlsh = [],  []   # PLANTS/ HEADERS

    # Request the plant name or other things state,  oris,  NERC or operator
    key = request.args.get('plant')
    #print key.isdigit()
    
    if key.isdigit():
        #query by ORISPL number
        qry1 = "select * FROM egrid14_plt " \
               "where ORISPL= %s limit 100;" % int(key)

    elif key.upper() in NERC_regions:
        #query by NERC region
        qry1 = "select * FROM egrid14_plt where nerc " \
               "like '%%%s%%' limit 500;" % key.upper()
        
    elif key.upper() in FUELS:
        # query by fuel category
        qry1 = "select * FROM egrid14_plt where " \
               "plfuelct like '%%%s%%';" % key
        
    elif key.upper() in STATES:
        # query by state
        qry1 = "select * FROM egrid14_plt where " \
               "state like '%%%s%%' limit 500;" % key
    else: 
        # query all the names in the database and the header
        qry1 = "select * FROM egrid14_plt where " \
               "PNAME like '%%%s%%' limit 500;" % key
    
    # Query the Database
    res1 = askDB(qry1,  db)
   
    # If we haven't found results,  let's check the operators
    if res1==None:
        qry1 = "select * FROM egrid14_plt where " \
               "oprname like '%%%s%%' limit 500;" % key 
        res1 = askDB(qry1,  db)   
        

    
    # If we still haven't found anything,  let's check the county
    if res1==None:
        qry1 = "select * FROM egrid14_plt where " \
               "cntyname like '%%%s%%' limit 500;" % key 
        res1 = askDB(qry1,  db)   
    
    
    # Read the header for egrid14_plt
    qry2 = "select LFIELD,  DEFINITION FROM egrid14_plt_header;"
    res2 = askDB(qry2,  db)
    
    netgen = []
    message = []
    links = {} 
    
    # if not empty fill the variables
    if res1:
        
        s = [2,  1,  4,  10,  19,  20,  22]
        for n in range(0, len(s)): ptlsh.append(dict(id=n,  na=res2[s[n]][0],  
                                                    fi=res2[s[n]][1]))
        for r in res1:
            plts.append(dict(na=r[3],  st=r[2],  oc=r[4],  op=r[5],  
                             ne=r[11],  nb=r[20],  ng=r[21],  fc=r[23]))
            ocodes.append(int(r[4]))
            
         # Let's get the generation for all these units   
        qry3 = "select year,  sum(netgen),  count(*) as plants from eia_ann_gen_plt where plant_id in (" +",  ".join(str(x) for x in ocodes) + ") group by year;"     
        # Query the database
        res3 = askDB(qry3,  db)

        if res3:
            for r in res3:
                netgen.append(dict(year=r[0],  netgen=int(r[1]),  
                                   plants="Number of plants %s " % r[2])) 
  
    else:  # We haven't found anything. 
        
        # Let' make a list of possible results
        clist = []
        
        qry4 = "select pname,  orispl FROM egrid14_plt;"
        res4 = askDB(qry4,  db)
        if res4:
            for r in res4:
                # Include all the plant names
                clist.append(r[0])  
                links[r[0]]=int(r[1])
                 
            # Let's get the 3 closest matches in the list
            if len(clist)>0: 
                res = difflib.get_close_matches(key.upper().
                                                capitalize(),  clist,  8,  0.4)
               
            
            if res:
                for x in res:
                    message.append(dict(plant=str(x),  pcode=links[str(x)] ))
            else:
                message = None
            
    return render_template("output.html", 
 			  plts=  plts, 
              ptlsh= ptlsh, 
              netgen=netgen, 
              message=message, 
              mh=my_host)


# Output table coming from the advanced search page.
@app.route('/output_adv')
def output_adv():

    # variable declaration
    global db
    ocodes= [0] # OCODES
    plts,  ptlsh = [], []  # PLANTS/headers

    # Requested variables
    plt = request.args.get('plant')
    sta = request.args.get('state')
    oper = request.args.get('oper')
    util = request.args.get('util')
    nerc = request.args.get('nerc')
    county = request.args.get('county')
    npcmin = str(request.args.get('npcmin'))
    npcmax = str(request.args.get('npcmax'))
    fcat = request.args.get('fcat')
    spq = request.args.get('spq')
    
    search = []
    # Building the advanced search
    qry1 = "select * FROM egrid14_plt WHERE 1=1"

    if plt!="ALL":
        qry1 = qry1 + " AND PNAME like '%%%s%%'"  % plt
        search.append(plt)
        
    if sta!="ALL":
        qry1 = qry1 + " AND state like '%%%s%%'" % sta    
        search.append(sta)
        
    if oper!="ALL":
        qry1 = qry1 + " AND oprname like '%%%s%%'" % oper
        search.append(oper)
        
    if util!="ALL":
        qry1 = qry1 + " AND utlsrvnm like '%%%s%%'" % util
        search.append(util)  
        
    if nerc!="ALL":
        qry1 = qry1 + " AND nerc like '%%%s%%'" % nerc
        search.append(nerc)
            
    if county!="ALL":
        qry1 = qry1 + " AND cntyname like '%%%s%%'" % county
        search.append(county)
        
    if npcmin!="0":
        qry1 = qry1 + " AND namepcap >= %s" % npcmin
        search.append(">%s MW" % npcmin)
        
    if npcmax!="10000":
        qry1 = qry1 + " AND namepcap < %s"  % npcmax
        search.append("<%s MW" % npcmax)
        
    if fcat!="ALL":
        qry1 = qry1 + " AND plfuelct like '%%%s%%'" % fcat
        search.append(fcat)
        
    qry1 = qry1 + ";"

    # Select the headers for the tables
    qry2 = "select LFIELD,  DEFINITION FROM egrid14_plt_header;"

    # Query the database
    res1 = askDB(qry1,  db)
    res2 = askDB(qry2,  db)

    
    # remove empty spaces
    while '' in search:
        search.remove('')
    
    # Let's make a string
    if len(search)==0:
        search2 = "[ All plants in the U.S ]"
    else:
        search2 = "[ " + ",  ".join(str(x) for x in search) + " ]"

    
    # if they are not empty,  fill the variables
    if res1 and res2:
        s = [2,  1,  4,  10,  19,  20,  22]
        for n in range(0, len(s)): ptlsh.append(dict(id=n,  na=res2[s[n]][0],  fi=res2[s[n]][1]))
        for r in res1:
            plts.append(dict(na=r[3],  st=r[2],  oc=r[4],  op=r[5],  
                             ne=r[11],  nb=r[20],  ng=r[21],  fc=r[23]))
            ocodes.append(r[4])
    
    
    
    # Let's get the generation for all these units   
    qry3 = "select year,  sum(netgen),  count(*) as plants " \
           "from eia_ann_gen_plt where plant_id in (" +",  ".join(
        str(x) for x in ocodes) + ") group by year;"     
    # Query the database
    res3 = askDB(qry3,  db)
   
    netgen = []
    
    if res3:
        for r in res3:
    		netgen.append(dict(year=r[0],  netgen=int(r[1]),  
                               plants="Number of plants %s " % r[2]))
  
  
    #print search

    return render_template("output.html", 
 			  plts=  plts, 
              ptlsh= ptlsh, 
              netgen=netgen, 
              search=search2, 
              mh=my_host)


# if the Query is done in the map
@app.route('/map_adv')
def map_adv():


    # variable declaration
    global db
    ocodes= [0] # OCODES
    plts,  ptlsh = [], []  # PLANTS/headers

    plt = request.args.get('plant')
    sta = request.args.get('state')
    oper = request.args.get('oper')
    util = request.args.get('util')
    nerc = request.args.get('nerc')
    county = request.args.get('county')
    npcmin = str(request.args.get('npcmin'))
    npcmax = str(request.args.get('npcmax'))
    fcat = request.args.get('fcat')


    # Building the advanced search
    qry1 = "select * FROM egrid14_plt WHERE 1=1"

    if plt!="ALL":
        qry1 = qry1 + " AND PNAME like '%%%s%%'"  % plt

    if sta!="ALL":
        qry1 = qry1 + " AND state like '%%%s%%'" % sta

    if oper!="ALL":
        qry1 = qry1 + " AND oprname like '%%%s%%'" % oper

    if util!="ALL":
        qry1 = qry1 + " AND utlsrvnm like '%%%s%%'" % util

    if nerc!="ALL":
        qry1 = qry1 + " AND nerc like '%%%s%%'" % nerc

    if county!="ALL":
        qry1 = qry1 + " AND cntyname like '%%%s%%'" % county

    if npcmin!="0":
        qry1 = qry1 + " AND namepcap >= %s" % npcmin

    if npcmax!="10000":
        qry1 = qry1 + " AND namepcap < %s"  % npcmax

    if fcat!="ALL":
        qry1 = qry1 + " AND plfuelct like '%%%s%%'" % fcat

    # Only plants with defined Lat,  Lon
    qry1 = qry1 + " AND lat is not null and lon is not null;"

    # Select the headers for the tables
    qry2 = "select LFIELD,  DEFINITION FROM egrid14_plt_header;"

    # Query the Database
    res1 = askDB(qry1,  db)
    res2 = askDB(qry2,  db)

    # Center the map to see all the points
    clat= 40
    clon= -99
    minLng= -124
    minLat = 24
    maxLng = -66
    maxLat = 55

    # if they are not empty,  fill the variables
    if res1 and res2:
        s = [2,  1,  4,  10,  19,  18,  20,  22,  25]
        for n in range(0, len(s)): ptlsh.append(dict(id=n,  na=res2[s[n]][0],  
                                                    fi=res2[s[n]][1]))
        for r in res1:
            plts.append(dict(na=r[3],  st=r[2],  oc=r[4],  op=r[5],  
                             ne=r[11],  nblr=r[20],  ngen=r[21],  
                             fuel=r[23],  cn=r[17],  lat=r[18], 
                             lon=r[19],  npc=r[26]))
            ocodes.append(r[4])
        lats = [x['lat'] for x in plts]
        longs = [y['lon'] for y in plts]

        # show 1% more of the map en each side
        if len(lats)!=0:
            clat = (float(min(lats))+float(max(lats)))/2
            clon = (float(min(longs))+float(max(longs)))/2
            minLng = float(max(longs))*1.01
            minLat = float(min(lats))*0.99
            maxLng = float(min(longs))*0.99
            maxLat = float(max(lats))*1.01

        # Invert Long if min>max
        if minLng > maxLng:
            aux = minLng
            minLng=maxLng
            maxLng=aux


    return render_template("map_search.html", 
              plants=json.dumps(plts), 
              clat=clat, 
              clon=clon, 
              minLng = minLng, 
              minLat = minLat, 
              maxLng = maxLng, 
              maxLat = maxLat, 
              ptlsh= ptlsh, 
              mh=my_host)


# Show the plant level information
@app.route('/output_plant_level')
def output_plant_level():

    # variable declaration
    global db
    ocodes= [0] # OCODES
    plts,  owns,  blrs,  gens = [],  [],  [],  []   # PLANTS/OWNERS/BLRS/GENS FROM EGRID
    ptlsh,  ownsh,  gnrsh,  blrsh,   =[],  [],  [],  []   # Header for PLANTS/OWNERS/BLRS/GENS
    aplts,  ablrs,  agens,  agensb,  acodes,  agenplt,  \
    agengen = [],  [],  [],  [],  [0],  [],  []   # ALL FROM EIA
    afuels = []  # ALL FROM EIA
    eplts,  eblrs,  egens,  ecodes = [], [], [], [0]  #  PLANTS/BLRS/GENS/OCODES FROM EPA
    oper,  oper_col = [], []  # Operations from LM

    # Requested variable to identify the plant
    ocode = request.args.get('ocode')

    # Define the Queries (all plants with this ocode). Including headers
    qry1 = "select * FROM egrid14_plt where orispl=%s;" % ocode
    qry2 = "select LFIELD,  UFIELD,  DEFINITION FROM egrid14_plt_header;"
    qry3 = "select * FROM egrid14_own where orispl=%s;" % ocode
    qry4 = "select LFIELD,  UFIELD,  DEFINITION FROM egrid14_own_header;"

    # Query the database
    res1 = askDB(qry1,  db)
    res2 = askDB(qry2,  db)
    res3 = askDB(qry3,  db)
    res4 = askDB(qry4,  db)

    if current_user.is_authenticated:
        if res1:
            s = [3,  2,  1,  16,  6,  8,  10,  11,  17,  18,  19,  20,  
                 21,  24,  25]
            for n in range(0, len(s)): 
                plts.append(dict(na=res2[s[n]][0],  fi=res2[s[n]][2],  
                                 un=res2[s[n]][1],  na2=res1[0][s[n]+1]))

            
        if (res3!=''):
            s = [4,  5,  6,  8,  9,  11,  12,  14,  15,  17,  18,  20,  
                 21,  23,  24,  26,  27,  29,  30,  32,  33,  35]
            for n in range(0, len(s)): 
                if res3[0][s[n]+1]==0 or res3[0][s[n]+1]=="" or res3[0][s[n]+1] is None:
                    continue
                else:
                    ownsh.append(dict(na=res4[s[n]][0],  fi=res4[s[n]][2],  
                                      un=res4[s[n]][1],  na2=res3[0][s[n]+1]))

    else:
        # If not empty,  fill the variables
        if res1 and res2:
            s = [2, 1, 10, 21]
            for n in range(0, len(s)):
                ptlsh.append(dict(na=res2[s[n]][0],  
                                  fi=res2[s[n]][2],  un=res2[s[n]][1]))

            for r in res1:
                ocodes.append(r[4])
                plts.append(dict(na=r[3],  st=r[2],  op=r[5],  us=r[7],  
                                 ne=r[11],  nb=r[20],  ng=r[21],  pf=r[22],  
                                 fc=r[23]))

        if res3 and res4:
            s = [4,  5,  6,  8,  9,  11,  12,  14,  15,  17,  18,  20,  21,  23,  
                 24,  26,  27,  29,  30,  32,  33,  35]
            for n in range(0, len(s)):
                if res3[0][s[n]+1]==0 or res3[0][s[n]+1]=="" or res3[0][s[n]+1] is None:
                    continue
                else:
                    ownsh.append(dict(na=res4[s[n]][0],  fi=res4[s[n]][2],  
                                      un=res4[s[n]][1],  na2=res3[0][s[n]+1]))
    ################ EGRID BOILERS (Removed for the moment)  #####
    #Create the queries
    qry1 = "select * from egrid14_blr where ORISPL=%s;"  % ocode
    qry2 = "select LFIELD,  UFIELD,  DEFINITION FROM egrid14_blr_header;"

    #Query the database
    res1 = askDB(qry1,  db)
    res2 = askDB(qry2,  db)

    #if not empty fill the variables
    if res1 and res2:
        s = [4, 6, 5, 11, 28]
        for n in range(0, len(s)):
            blrsh.append(dict(na=res2[s[n]][0],  fi=res2[s[n]][2],  
                              un=res2[s[n]][1]))
        for r in res1:
            blrs.append(dict(bid=r[5],  pm=r[6],  us=r[7],  
                             fu=r[12],  yo=r[29]))

    ########### EGRID GENERATORS (Included all the generators for this plants) #####

    if current_user.is_authenticated:
        qry1 = "select * from egrid14_gnr where ORISPL=%s;"  % ocode
        qry2 = "select LFIELD,  UFIELD,  DEFINITION FROM egrid14_gnr_header;"

        res1 = askDB(qry1,  db)
        res2 = askDB(qry2,  db)

        if res1 and res2:
            s = [4, 6, 7, 8, 9, 14]
            for n in range(0, len(s)): gnrsh.append(dict(na=res2[s[n]][0], 
                                                        fi=res2[s[n]][2],  
                                                        un=res2[s[n]][1]))
            for r in res1:
                gens.append(dict(gid=r[5], gs=r[7], pm=r[8],  
                                 fu=r[9],  npc=r[10],  yo=r[15]))
                
    
    else:
        qry1 = "select * from egrid14_gnr where ORISPL=%s;"  % ocode
        qry2 = "select LFIELD,  UFIELD,  DEFINITION FROM egrid14_gnr_header;"

        res1 = askDB(qry1,  db)
        res2 = askDB(qry2,  db)

        if res1 and res2:
            s = [4, 6, 7, 8, 14]
            for n in range(0, len(s)): gnrsh.append(dict(na=res2[s[n]][0], fi=res2[s[n]][2], un=res2[s[n]][1]))
            for r in res1:
                gens.append(dict(gid=r[5], gs=r[7], pm=r[8],  fu=r[9], yo=r[15]))
                
    ##### EIA ANNUAL AND MONTHLY GENERATION #####
    qry1 = "select * from eia_mon_gen where plant_id=%s and date<'2016-07-01';"  % ocode
    qry2 = "select distinct(gid) from eia_mon_gen where plant_id=%s;"  % ocode
    qry3 = "select * from eia_ann_gen_plt where plant_id=%s;"  % ocode
    qry4 = "select * from eia_ann_fuel_plt where plant_id=%s;"  % ocode

    res1 = askDB(qry1,  db)
    res2 = askDB(qry2,  db)
    res3 = askDB(qry3,  db)
    res4 = askDB(qry4,  db)
    
    colors=['#AA0000',  '#0000AA',  '#0AA000',  '#8C0B90',  '#CF95D7',  '#AD6D70', 
            '#BC2500',  '#F6CC1D',  '#C0E4FF',  '#2AB502',  '#7C60A8',   '#37AB65', 
            '#3DF735',  '#FF0000',  '#00FF00',  '#0000FF',  '#8C0B90',  '#CF95D7', 
            '#AD6D70',  '#BC2500',  '#F6CC1D',  '#C0E4FF',  '#2AB502',  '#7C60A8', 
            '#37AB65',  '#3DF735',  '#FF0000',  '#00FF00',  '#0000FF',  '#8C0B90', 
            '#CF95D7',  '#AD6D70',  '#BC2500',  '#F6CC1D',  '#C0E4FF',  '#2AB502', 
            '#7C60A8',   '#37AB65',  '#3DF735',  '#FF0000',  '#00FF00',  '#0000FF',  '#8C0B90', '#CF95D7',  '#AD6D70', '#BC2500', '#F6CC1D',  '#C0E4FF',  '#2AB502',  '#7C60A8',   '#37AB65',  '#3DF735', '#FF0000',  '#00FF00',  '#0000FF',  '#8C0B90', '#CF95D7',  '#AD6D70', '#BC2500', '#F6CC1D',  '#C0E4FF',  '#2AB502',  '#7C60A8',   '#37AB65',  '#3DF735', '#FF0000',  '#00FF00',  '#0000FF',  '#8C0B90', '#CF95D7',  '#AD6D70', '#BC2500', '#F6CC1D',  '#C0E4FF',  '#2AB502',  '#7C60A8',   '#37AB65',  '#3DF735', '#FF0000',  '#00FF00',  '#0000FF',  '#8C0B90', '#CF95D7',  '#AD6D70', '#BC2500', '#F6CC1D',  '#C0E4FF',  '#2AB502',  '#7C60A8',   '#37AB65',  '#3DF735', '#FF0000',  '#00FF00',  '#0000FF',  '#8C0B90', '#CF95D7',  '#AD6D70', '#BC2500', '#F6CC1D',  '#C0E4FF',  '#2AB502',  '#7C60A8',   '#37AB65',  '#3DF735', '#FF0000',  '#00FF00',  '#0000FF',  '#8C0B90', '#CF95D7',  '#AD6D70', '#BC2500', '#F6CC1D',  '#C0E4FF',  '#2AB502',  '#7C60A8',   '#37AB65',  '#3DF735']
        
    if res1:
        for a in res1:
            agens.append(dict(oc=a[0],  gid=a[1],  date=a[2],  gen=a[3]))
          
    if res2:  
        for idx,  b in enumerate(res2):
            agensb.append(dict(gid=b[0],  co=colors[idx]))
            
    if res3:    
        for a in res3:
            agenplt.append(dict(pid=a[0],  na=a[1],  year=a[2],  gen=a[3]))
        
    if res4:      
        for a in res4:
            afuels.append(dict(pid=a[0],  na=a[1],  sn=a[2],  rf=a[3],  pu=a[4], 
                               tfq=a[5],  efq=a[6],  tfm=a[7],  efm=a[8], 
                               ng=a[9],  yr=a[10]))

    ##### INTERTEK OPERATIONS #####

    # Create queries for a generic operation's plant
    qry1 = "select * from int_ann_gen_oper where ocode=259 and uid=3;"
    qry2 = "select distinct(uid) from int_ann_gen_oper where ocode=259 and uid=3;"

    # Query the database
    res1 = askDB(qry1,  db)
    res2 = askDB(qry2,  db)

    if res1 and res2:

        # Fill the variables
        for a in res1:
            oper.append(dict(ui=a[21],  yr=a[1],  genn=a[13], 
                             dam=a[14],  starts=a[15],  lf=a[19], 
                             hs=a[16],  ws=a[17],  cs=a[18], 
                             od=(a[6]/(a[3]-a[4])*100)))
        for idx,  b in enumerate(res2):
            oper_col.append(dict(ui=b[0],  co=colors[idx]))

    return render_template("output_plant_level.html", 
 			  plts=plts, 
              ptlsh=ptlsh, 
              owns=owns, 
              ownsh=ownsh, 
              blrs=blrs, 
              blrsh=blrsh, 
              gens=gens, 
              gnrsh=gnrsh, 
			  aplts=aplts, 
              agens=agens, 
              agensb=agensb, 
              agengen=agengen, 
              agenplt=agenplt, 
              afuels=afuels, 
              ablrs=ablrs, 
			  eplts=eplts, 
              oper=oper, 
              oper_col=oper_col, 
              mh=my_host)


##################################### Other pages ############################################


##################################### First navigation-bar ###################################


# Related products and services
@app.route('/overview')
def overview():

    return render_template("overview.html",  mh=my_host)


# Learn more about Windlife
@app.route('/windlife')
def windlife():
    return render_template("windlife.html",  mh=my_host)


##################################### Second / Main navigation-bar ###################################


# Operational Benchmark
@app.route('/bypo')
def bypo():
    
    # qry1 = "select untyronl,  npc,  prmvr  from assets where fuel='Natural gas';"
    # Query the database
    # res1 = askDB(qry1,  db)

    # coords = []
    
    # if res1:
        # Fill the variables
        # for a in res1:
            # coords.append(dict(yo=(2017-int(a[0])), npc=a[1],  pm=a[2]))
    # print coords

    return render_template("bypo.html", 
                           # coords=coords, 
                           mh=my_host)


# Signature Data Benchmark
@app.route('/bypo2')
def bypo2():

    return render_template("bypo2.html", mh=my_host)


# Benchmark form
@app.route('/benchmark',  methods=['GET',  'POST'])
def benchmark():

    # Variable declaration
    global db
    plants,  units = [],  []   # every plant/unit in the EPA

    # Upload the form from forms.py
    form = BenchmarkForm(request.form)

    # If filled,  send us an email from ingrid.intertek
    if request.method == 'POST':
        if form.validate() == False:
            flash('Please,  fill required fields')
            return render_template('benchmark.html',  mh=my_host,  form=form)
        else:
            msg = Message(form.subject.data, 
                          sender='ingrid.intertek@gmail.com', 
                          recipients=['aimengineering.sales@intertek.com', 
                                      'martin.gascon@gmail.com'])
            msg.body = """
            From: {0}
            Company: {1}
            Email: {2}
            Plant: {3}
            Plant: {4}
            Subject: {5}

            Message:
            {6}
            """.format(form.name.data,  form.company.data, 
                       form.email.data,  form.plant.data,  form.unit.data, 
                       form.subject.data,  form.message.data)
            mail.send(msg)
            return render_template('benchmark.html', 
                                   mh=my_host,  form=form,  success=True)

    # If the form is not filled yet ...
    elif request.method == 'GET':

        # Put all the plant names that we could
        # have operations sorted by name
        qry1 = "select fname from epa_plt where plpfgnct in " \
               "('GAS', 'COAL', 'OIL') order by fname;"
        res1 = askDB(qry1,  db)

        # Once the plant is selected,  we have to select
        # the unit we want to benchmark
        qry2 = "select fname, uid from epa_gnr where plpfgnct " \
               "in ('GAS', 'COAL', 'OIL') order by fname;"
        res2 = askDB(qry2,  db)

        # if the results are not empty,  fill the variables
        if res1:
            for r in res1:
                plants.append(dict(name=r[0]))

        if res2:
            for r in res2:
                units.append(dict(na=r[0], uid=r[1]))

        return render_template('benchmark.html',  plants=plants, 
                               units=units,  mh=my_host,  form=form)


# Pricing
@app.route('/pricing')
def pricing():

    return render_template("pricing.html",  mh=my_host)


# Blog
@app.route('/blog')
def blog():

    return render_template("blog.html",  mh=my_host)


# People
@app.route('/team')
def team():

    return render_template("team.html",  mh=my_host)


# Contact us
@app.route('/contactus',  methods=['GET',  'POST'])
def contactus():
    form = ContactForm(request.form)

    # If the form has been filled,  send us an email
    if request.method == 'POST':

        if form.validate() == False:
            flash('Please,  fill required fields')
            return render_template('contactus.html',  mh=my_host,  form=form)

        else:

            msg = Message(form.subject.data, 
                          sender='ingrid.intertek@gmail.com', 
                          recipients=['aimengineering.sales@intertek.com', 
                                      'martin.gascon@intertek.com'])
            msg.body = """
            From: {0}
            Company: {1}
            Email: <{2}>
            Subject: {3}

            Message:
            {4}
            """.format(form.name.data,  form.company.data, 
                       form.email.data,  form.subject.data,  form.message.data)
            mail.send(msg)

            return render_template('contactus.html',  mh=my_host, 
                                   form=form,  success=True)

    # If the form hasn't been filled yet ...
    elif request.method == 'GET':

        return render_template('contactus.html',  mh=my_host,  form=form)


@app.route('/blogs_old')
def blogs_old():
    blog_list = Blogs.query.order_by("blog_date").all()
    blogs = [blog.to_dict() for blog in blog_list]

    return render_template('blogs_old.html',  blogs=blogs)


@app.route('/blogs/<int:page>')
def blogs(page):

    blogs = ''
    blogs_per_page = 6
    print "++++++++++++++++++++++++++++++++++++++++++"
    if page == 1:
        blog_list = Blogs.query.order_by("blog_date").limit(6)
        print "++++_____________+++++++++++++++++++-----------------"
        blogs = [blog.to_dict() for blog in blog_list]
    else:
        i = page-1
        blog_list = Blogs.query.order_by("blog_date").limit(3)[i*3:]
        blogs = [blog.to_dict() for blog in blog_list]
    query = Blogs.query.order_by(desc(Blogs.blog_view_count)).limit(4).all()
    popular = [blog.to_dict() for blog in query]
    # new = "SELECT * FROM blogs ORDER BY blog_date DESC LIMIT 2"

    new_data = Blogs.query.order_by(desc(Blogs.blog_date)).limit(3).all()
    new_time_data = [blog.to_dict() for blog in new_data]
    new_latest_data = Blogs.query.order_by(desc(Blogs.blog_date)).\
        limit(1).all()
    latest_data = [blog.to_dict() for blog in new_latest_data]

    return render_template('blogs.html',  blogs=blogs, 
                           popular=popular,  time_data=new_time_data, 
                           latest_data=latest_data)


# @app.route('/blogs/<int:blog_id>')
# def singleBlog(blog_id):
#     single_blog = Blogs.query.filter_by(blog_id=blog_id).all()
#     blogs = [blog.to_dict() for blog in single_blog]
#     return render_template('single-blog.html',  blogs=blogs)


ALLOWED_EXTENSIONS = set(['png',  'jpg',  'jpeg',  'gif'])


def allow_file(filename):
    return '.' in filename and filename.rsplit('.',  1)
    [1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload',  methods=['GET',  'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file.filename == '':
            flash("Please select a valid file")
            return redirect(request.url)
        if file and allow_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'],  filename))
            return redirect(url_for('upload',  filename=filename))
    return render_template('uploads.html')


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],  filename)


@app.errorhandler(404)
def page_not_found(error):
    return render_template('page_not_found.html'),  404


@app.errorhandler(401)
def page_not_found(error):
    return render_template('page_not_found.html'),  401


@app.route('/viewMyBlogs',  methods=['GET',  'POST'])
@login_required
def viewMyBlogs():
    assets,  user_id = [],  []
    query = "SELECT * FROM blogs WHERE blog_user_id='%s';" % current_user
    blog = askDB(query,  db)
    if blog:
        for blog_query in blog:
            assets.append(dict(title=blog_query[1], 
                               description=blog_query[2],  image=blog_query[3], 
                               author=blog_query[4],  status=blog_query[5]))
    return render_template('usermanagement/viewMyBlogs.html', 
                           assets=assets,  user=user_id)


@app.route('/addBlog',  methods=['GET',  'POST'])
@login_required
def addBlog():
    form = AddBlogForm(request.form)
    # import pdb; pdb.set_trace()
    if current_user.role == USER_ROLES.USER:
        return redirect(url_for('viewMyBlogs'))
    else:
        if request.method == 'POST':
            file = request.files['file']
            filename = secure_filename(file.filename)
            if filename:
                file.save(os.path.join(app.config['UPLOAD_FOLDER'],  filename))
            title = form.title.data
            description = form.description.data
            image = filename
            author = current_user
            blog = Blogs(blog_title=title,  blog_description=description, 
                         blog_image=image,  blog_user_id=author)

            try:
                query = "INSERT INTO blogs(blog_title,  blog_description,  " \
                        "blog_image,  blog_user_id,  blog_status,  blog_date) " \
                        "VALUES ('%s',  '%s',  '%s',  '%s',  '%d',  '%s');" % \
                        (title,  description,  image,  author,  0, 
                         str(datetime.datetime.now().date()))
                askDB(query,  db)
            except:
                return "Sorry,  we found some technical " \
                       "issues,  please contact to admin!"
        assets,  user_id = [],  []
        query = "SELECT * FROM blogs WHERE blog_user_id='%s';" % current_user
        blog = askDB(query,  db)
        if blog:
            for blog_query in blog:
                assets.append(dict(title=blog_query[1], 
                                   description=blog_query[2], 
                                   image=blog_query[3], 
                                   author=blog_query[4],  status=blog_query[5]))
    return render_template('usermanagement/addBlog.html',  assets=assets)


@app.route('/editBlog/<blog_id>')
@login_required
def editBlog(blog_id):
    error = None
    form = AddBlogForm(request.form)
    assets,  title,  description,  image,  author = [],  [],  [],  [],  []
    if current_user.role == USER_ROLES.USER:
        if request.method == 'POST':
            file = request.files['file']
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'],  filename))
            title = request.form.get('blogTitle',  '',  type=str)
            description = request.form.get('blogDescription',  '',  type=str)
            image = filename
            author = request.form.get('blogAuthor',  '',  type=str)

            try:
                sendData = "UPDATE blogs WHERE blog_id=blog_id(" \
                           "blog_title,  blog_description,  blog_image,  " \
                           "blog_user_id) VALUES  (%s,  %s,  %s,  %s)" % \
                           (title,  description,  image,  author)
                query = askDB(sendData,  db)
            except:
                return "Sorry,  Database doesn't seems to be working"
        else:
            assets,  user_id = [],  []
            query = "SELECT user_id FROM user_assets WHERE " \
                    "user = '%s';" % current_user.user
            user_query = askDB(query,  db)
            user_id = user_query[1]

            query = "SELECT * FROM blogs WHERE blog_user_id='%s';" % user_id
            # query = "SELECT * FROM blogs"
            blog = askDB(query,  db)
            if blog:
                for blog_query in blog:
                    assets.append(dict(title=blog_query[1], 
                                       description=blog_query[2], 
                                       image=blog_query[3], 
                                       author=blog_query[4], 
                                       status=blog_query[5]))
            return render_template('usermanagement/addBlog.html', 
                                   assets=assets)
