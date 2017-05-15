# project/models.py
"""

"""

import datetime
from datetime import timedelta, datetime
from flask import current_app
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask.ext.bcrypt import Bcrypt
from flask.ext.sqlalchemy import SQLAlchemy

bcrypt = Bcrypt(current_app)
db = SQLAlchemy(current_app)

class User(db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    usertype = db.Column(db.Integer, nullable=False, default=0)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    lastpaidon = db.Column(db.DateTime, nullable=True, default = (datetime.now() - timedelta(5000)))
    name = db.Column(db.String, default="")
    phoneno = db.Column(db.String, default="")
    city = db.Column(db.String, default="")
    country = db.Column(db.String, default="")
    profile = db.Column(db.String, default="")
    page = db.Column(db.String, default="")
    account_holdername = db.Column(db.String, default="")
    bank_name = db.Column(db.String, default="")
    account_number = db.Column(db.String, default="")
    swift_code = db.Column(db.String, default="")
    iban_number = db.Column(db.String, default="")
    ifsc_code = db.Column(db.String, default="")
    branch_address = db.Column(db.String, default="")
    def __init__(self, email, password, confirmed,
                 admin=False,usertype=0, confirmed_on=None, name="",phoneno="",  city="", country='' ,profile='', page='', account_holdername='', bank_name='', account_number='', swift_code='', iban_number='', ifsc_code='', branch_address=''):
        self.email = email
        self.password = bcrypt.generate_password_hash(password)
        self.registered_on = datetime.now()
        self.admin = admin
        self.usertype = usertype
        self.confirmed = confirmed
        self.confirmed_on = confirmed_on
        self.name = name
	self.phoneno = phoneno
        self.city = city
        self.country = country
        self.profile = profile
        self.page = page
        self.account_holdername = account_holdername
        self.bank_name = bank_name
        self.account_number = account_number
        self.swift_code = swift_code
        self.iban_number = iban_number
        self.ifsc_code = ifsc_code
        self.branch_address = branch_address

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def __repr__(self):
        return '<email {}'.format(self.email)

    def get_token(self, expiration=1800):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'user': self.id}).decode('utf-8')

    @staticmethod
    def verify_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return None
        id = data.get('user')
        if id:
            return User.query.get(id)
        return None

class Tracking(db.Model):

    __tablename__ = "tracking"

    id = db.Column(db.Integer, primary_key=True)
    created_on = db.Column(db.DateTime, server_default=db.func.now())
    post_ID = db.Column(db.Integer, nullable=False)
    user_ID = db.Column(db.Integer, nullable=False)
    ip = db.Column(db.String, nullable=False)
    
    def __init__(self, post_ID, user_ID, ip):
        self.post_ID = post_ID
        self.ip = ip
        self.user_ID = user_ID
        
    def get_id(self):
        return self.id


class Points(db.Model):
    __tablename__ = "points"

    id = db.Column(db.Integer, primary_key=True)
    created_on = db.Column(db.DateTime, server_default=db.func.now())
    updated_on = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    user_ID = db.Column(db.Integer, nullable=False)
    post_ID = db.Column(db.Integer, nullable=False)
    earned_points = db.Column(db.Integer, default = 0)
    
    def __init__(self, user_ID, post_ID, earned_points):
        self.user_ID = user_ID
        self.post_ID = post_ID
        self.earned_points = earned_points
        
        
    def get_id(self):
        return self.id

class Posts(db.Model):
    __tablename__ = "posts"

    id = db.Column(db.Integer, primary_key=True)
    created_on = db.Column(db.DateTime, server_default=db.func.now())
    post_topheading= db.Column(db.String)
    post_title = db.Column(db.String) 
    post_link = db.Column(db.String, unique=True, nullable=False)
    post_image = db.Column(db.String, default='')
    post_description = db.Column(db.String,default='')
    post_code = db.Column(db.String, unique=True, nullable=False)
    post_category = db.Column(db.String,default='')
    post_type = db.Column(db.String,default='article')
    

    def __init__(self, post_title,post_topheading, post_link, post_image, post_description, post_category, post_code):
        self.post_title = post_title
        self.post_topheading = post_topheading
        self.post_link = post_link
        self.post_image = post_image
        self.post_description = post_description
        self.post_category = post_category
        self.post_code = post_code
        
    def get_id(self):
        return self.id



class Transaction(db.Model):
    __tablename__ = "transaction"

    id = db.Column(db.Integer, primary_key=True)
    created_on = db.Column(db.DateTime, server_default=db.func.now())
    amount = db.Column(db.Integer, nullable=False) 
    user_ID = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.String, default='')
    

    def __init__(self, amount, user_ID, comment=''):
        self.amount = amount
        self.user_ID = user_ID
        self.comment = comment
    def get_id(self):
        return self.id

