from common import *
from models import *
import re
from app import db
import hashlib


def weak_password(password):

    special_chars = '!@#$%^&*()-+_'

    if not password or len(password) < 6:
        return True

    if not re.search(r'[A-Z]', password):
        return True

    if not re.search(r'[a-z]', password):
        return True

    if not re.search(r'[0-9]', password):
        return True

    for c in password:
        if c in special_chars:
            return False

    return True


def is_valid_email(email):

    if not re.match("(^.+@{1}.+\.{1}.+)", str(email)):
        return False
    else:
        return True


def list_users():
    return User.query.all()


# check if whatever username is already taken
def username_registerred(user):

    if User.query.filter_by(user=user).first():
        return True

    return False


# check if whatever email is already taken
def email_registerred(email):

    if User.query.filter_by(email=email).first():
        return True

    return False


# locate user using eMail as input
def g_user_by_email(email):

    user = User.query.filter_by(email=email).first()
    if user:
        return user

    return None


# locate user using eMail as input
def g_user_by_id(user_id):

    user = User.query.filter_by(id=user_id).first()
    if user:
        return user

    return None


def get_user_roles():

    data = {}
    for user in User.query.all():

        data[user.id] = user.role

    return data


def print_user_roles():

    for id, role in get_user_roles().iteritems():
        print ' *** (user_id=' + str(id) + ') -> ' + str(role)


def set_role(user_id, role):

    user = User.query.filter_by(id=user_id).first()
    if user:

        user.role = role

        # commit changes
        db.session().commit()

        return STATUS.OK

    else:
        return STATUS.UNKNOWN_USER


def make_admin(user_id):

    return set_role(user_id, USER_ROLES.ADMIN)


def make_user(user_id):

    return set_role(user_id, USER_ROLES.USER)


def set_name(user_id, data):

    user = User.query.filter_by(id=user_id).first()
    if user:

        user.name = data

        # commit changes
        db.session().commit()

        return STATUS.OK

    else:
        return STATUS.UNKNOWN_USER


def activate_user(user_id):

    user = User.query.filter_by(id=user_id).first()
    if user:

        user.state = USER_STATE.ACTIVE

        # commit changes
        db.session().commit()

        return STATUS.OK

    else:
        return STATUS.UNKNOWN_USER


def set_username(user_id, data):

    user = User.query.filter_by(id=user_id).first()
    if user:

        user.user = data

        # commit changes
        db.session().commit()

        return STATUS.OK

    else:
        return STATUS.UNKNOWN_USER


def set_company(user_id, data):

    user = User.query.filter_by(id=user_id).first()
    if user:

        user.company = data

        # commit changes
        db.session().commit()

        return STATUS.OK

    else:
        return STATUS.UNKNOWN_USER


def set_email(user_id, data):

    user = User.query.filter_by(id=user_id).first()
    if user:

        user.email = data

        # commit changes
        db.session().commit()

        return STATUS.OK

    else:
        return STATUS.UNKNOWN_USER


# return one item
def g_asset(id):

    obj = Object.query.get(id)

    if not obj:
        return None

    if obj.key1 == COMMON.TYPE_ASSET:

        return Asset().copy(obj)

    # this point shoudl not be hit ..
    return None


# Get all items for limit < 0
def g_all_assets(limit=10):

    retValues = []

    if limit > 0:

        for obj in Object.query.filter_by(
                key1=COMMON.TYPE_ASSET).order_by("id").limit(limit):

            retValues.append(Asset().copy(obj))
    else:

        for obj in Object.query.filter_by(
                key1=COMMON.TYPE_ASSET).order_by("id"):

            retValues.append(Asset().copy(obj))

    return retValues


def g_object_last_id():

    try:
        return Object.query.order_by(
            'id desc').limit(1)[0].id
    except:
        return -1


def g_object_next_id():

    try:
        return Object.query.order_by(
            'id desc').limit(1)[0].id + 1
    except:
        return -1


# generate a payment token
def g_register_token(user):

    if not user:
        return None

    return hashlib.md5(str(user.id) + user.email).hexdigest()


# check if token exist for assignment
def g_check_register_token(user, token):

    if token == g_register_token(user):
        return True
    else:
        return False
