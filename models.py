# -*- encoding: utf-8 -*-
"""
Python Aplication Template
Licence: GPLv3
"""

from init import db
from flask_login import UserMixin
import time
import datetime

# from   common        import *


class USER_ROLES:

    USER = 1  # normal user
    ADMIN = 2  # admin
    GROUP_MANAGER = 3  # group manag


class User(UserMixin, db.Model):

    id = db.Column(db.Integer,     primary_key=True)
    user = db.Column(db.String(64),  unique=True)
    email = db.Column(db.String(120), unique=True)
    company = db.Column(db.String(64))
    group_id = db.Column(db.Integer)
    role = db.Column(db.Integer)
    password = db.Column(db.String(500))
    password_q = db.Column(db.Integer)
    name = db.Column(db.String(500))
    state = db.Column(db.Integer)
    fraud = db.Column(db.Integer)
    lastupdate = db.Column(db.Integer)
    lastupdate_pwd = db.Column(db.Integer)

    def __init__(self, user, password, name, email, company):
        self.user = user
        self.password = password
        self.name = name
        self.email = email
        self.company = company
        self.group_id = None
        self.role = None

        self.state = 0
        self.fraud = 0
        self.lastupdate = time.time()
        self.lastupdate_pwd = time.time()

    def __repr__(self):
        return '%r' % (self.id)

    def set_user_role(self):
        self.role = USER_ROLES.USER

    def get_role(self):

        if self.role == USER_ROLES.ADMIN:
            return 'ADMIN'
        elif self.role == USER_ROLES.GROUP_MANAGER:
            return 'GROUP_MANAGER'
        else:
            return 'USER'

    def save(self):

        # inject self into db session
        db.session.add(self)

        # commit change and save the object
        db.session.commit()

        return self

    def commit(self):

        # commit change (needed for wrongpwdcount)
        db.session.commit()


class Object(db.Model):

    # only if you want to have another table name mapped over this model
    # __tablename__ = "Object"

    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer)

    idx1 = db.Column(db.Integer)  # to be used for indexing
    idx2 = db.Column(db.Integer)  # to be used for indexing
    idx3 = db.Column(db.Integer)  # to be used for indexing
    idx4 = db.Column(db.Integer)  # to be used for indexing
    idx5 = db.Column(db.Integer)  # to be used for indexing

    idx6 = db.Column(db.Float)  # to be used for indexing
    idx7 = db.Column(db.Float)  # to be used for indexing
    idx8 = db.Column(db.Float)  # to be used for indexing

    key1 = db.Column(db.String(100))  # search key
    key2 = db.Column(db.String(100))  # search key
    key3 = db.Column(db.String(100))  # search key
    key4 = db.Column(db.String(100))  # search key
    key5 = db.Column(db.String(100))  # search key
    key6 = db.Column(db.String(100))  # search key
    key7 = db.Column(db.String(100))  # search key
    key8 = db.Column(db.String(100))  # search key
    key9 = db.Column(db.String(100))  # search key
    key10 = db.Column(db.String(100))  # search key

    data1 = db.Column(db.String(1000))  # data holder
    data2 = db.Column(db.String(1000))  # data holder
    data3 = db.Column(db.String(1000))  # data holder
    data4 = db.Column(db.String(1000))  # data holder
    data5 = db.Column(db.String(1000))  # data holder
    data6 = db.Column(db.String(1000))  # data holder
    data7 = db.Column(db.String(1000))  # data holder
    data8 = db.Column(db.String(1000))  # data holder
    data9 = db.Column(db.String(1000))  # data holder
    data10 = db.Column(db.String(1000))  # data holder

    rawdata = db.Column(db.String(1000))  # data holder 5k

    counter = db.Column(db.Integer)  # counts the loading
    expiry = db.Column(db.Integer)  # signal expiration
    lastupdate = db.Column(db.Integer)  # signal last update

    def __init__(self):

        # primary key
        self.id = None

        # user id
        self.userid = -1

        # indexing
        self.idx1 = -1
        self.idx2 = -1
        self.idx3 = -1
        self.idx4 = -1
        self.idx5 = -1

        # search keys
        self.key1 = None
        self.key2 = None
        self.key3 = None
        self.key4 = None
        self.key5 = None
        self.key6 = None
        self.key7 = None
        self.key8 = None
        self.key9 = None
        self.key10 = None

        # data holders
        self.data1 = None
        self.data2 = None
        self.data3 = None
        self.data4 = None
        self.data5 = None
        self.data6 = None
        self.data7 = None
        self.data8 = None
        self.data9 = None
        self.data10 = None
        self.rawdata = None

        # context
        self.count = 0
        self.expiry = 0
        self.lastupdate = -1

    def type(self):
        return self.key1

# Class to count the number of attempts to login.


class wrongpwdcnt(UserMixin, db.Model):

    user = db.Column(db.String(64),  primary_key=True)
    wrong_attempt_cnt = db.Column(db.Integer)

    def __init__(self, user, wrong_attempt_cnt):
        self.user = user
        self.wrong_attempt_cnt = wrong_attempt_cnt

    def save(self):

        # inject self into db session
        db.session.add(self)

        # commit change and save the object
        db.session.commit()

        return self

    def commit(self):
        db.session.commit()

    def delete(self):

        db.session.delete(self)
        db.session.commit()


class user_assets(UserMixin, db.Model):

    rn = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    user = db.Column(db.String(64))
    plant_id = db.Column(db.Integer)
    fname = db.Column(db.String(120))
    admin_user = db.Column(db.String(64))
    date_created = db.Column(db.Date)
    valid_until = db.Column(db.Date)

    def __init__(self, user_id, user, plant_id, fname, admin_user,
                 date_created, valid_until):
        self.user_id = user_id
        self.user = user
        self.plant_id = plant_id
        self.fname = fname
        self.admin_user = admin_user
        self.date_created = date_created
        self.valid_until = valid_until

    def __repr__(self):

        return '<User %r>' % (self.user)

    def save(self):

        # inject self into db session
        db.session.add(self)

        # commit change and save the object
        db.session.commit()

        return self

    def commit(self):

        # commit change (needed for wrongpwdcount)
        db.session.commit()


class BlogStatus:
    SHOWN = 0
    PENDING = 1
    DELETED = 2


class Blogs(db.Model):

    # __tablename__ = 'egridBlogs'

    blog_id = db.Column(db.Integer, primary_key=True)
    blog_title = db.Column(db.String(128), nullable=False)
    blog_description = db.Column(db.Text)
    blog_image = db.Column(db.String(128), nullable=False)
    blog_user_id = db.Column(db.Integer)
    blog_status = db.Column(db.Integer, default=BlogStatus.PENDING, index=True)
    blog_date = db.Column(db.DateTime, nullable=False, default=datetime)
    blog_view_count = db.Column(db.Integer)

    def to_dict(self):
        return dict(
            id=self.blog_id,
            title=self.blog_title,
            description=self.blog_description,
            image=self.blog_image,
            status=self.blog_status,
            published=self.blog_date,
            view_count=self.blog_view_count
        )
