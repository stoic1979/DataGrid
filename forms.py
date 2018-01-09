from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, \
    BooleanField, Form, TextField, \
    TextAreaField, SubmitField, validators, \
    ValidationError
from wtforms.validators import InputRequired, Email, \
    Length, DataRequired


class ContactForm(FlaskForm):
    name = TextField("Name",  [validators.Required("Please enter your name.")])
    company = TextField("Company")
    email = TextField("Email",  [validators.Required("Please enter your email "
                                                     "address."),
                                 validators.Email("Please enter your "
                                                  "email address.")])
    subject = TextField("Subject",  [validators.Required("Please "
                                                         "enter a subject.")])
    message = TextAreaField("Message",  [validators.Required("Please "
                                                             "enter a message.")
                                         ])
    submit = SubmitField('Send Message')   
 

class BenchmarkForm(FlaskForm):
    name = TextField("Name",  [validators.Required("Please "
                                                   "enter your name.")])
    company = TextField("Company", [validators.Required(
        "Please enter your Company name.")])
    email = TextField("Email",  [validators.Required(
        "Please enter your email address."),
        validators.Email("Please enter your email address.")])
    plant = TextField("Plant", [validators.Required(
        "Please select your Plant Name.")])
    unit = TextField("Unit",
                     [validators.Required("Please select a unit ID.")])
    subject = TextField("CHOOSE YOUR BENCHMARK LEVEL",
                        [validators.Required("Please enter a subject.")])
    message = TextAreaField("Use this box for clarifications",
                            [validators.Required("Please enter a message.")])
    submit = SubmitField('Send Message') 


class LoginForm(FlaskForm):
    username = StringField("username",
                           validators=[InputRequired(
                               "Please enter your username."),
                               Length(min=4, max=15)])
    password = PasswordField("password",
                             validators=[InputRequired(
                                 "Please enter your password."),
                                 Length(min=8, max=80)])
    remember = BooleanField("remember me")
    submit = SubmitField('Send Message')


class RegisterForm(FlaskForm):
    email = StringField(u'E-mail adress', validators=[InputRequired()])
    name = StringField(u'Name', validators=[InputRequired()])
    company = StringField(u'Company', validators=[InputRequired()])
    username = StringField(u'Username', validators=[InputRequired()])
    password = PasswordField(u'Password', validators=[InputRequired()])
    cpassword = PasswordField(u'Confirm password', validators=[InputRequired()
                                                               ])


class ForgotPasswordForm(Form):
    email = StringField(u'E-mail adress', validators=[InputRequired()])


class ResetForm(Form):
    username = StringField(u'Username', validators=[InputRequired()])
    password = PasswordField(u'Old Passowrd', validators=[InputRequired()])
    npassword = PasswordField(u'New Password', validators=[InputRequired()])
    cpassword = PasswordField(u'Confirm Password', validators=[InputRequired()
                                                               ])


class PlantForm(Form):
    user = StringField(u'User', validators=[InputRequired()])
    plant_id = StringField(u'Plant ID', validators=[InputRequired()])
    valid_until = StringField(u'Valid until', validators=[InputRequired()])


class AddBlogForm(Form):
    title = StringField('title', validators == [DataRequired()])
    description = StringField('description', validators == [DataRequired()])
    image = StringField('image')
    author = StringField('author')
    submit = SubmitField('AddBlog')
