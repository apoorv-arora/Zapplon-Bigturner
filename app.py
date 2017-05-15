#################
#### imports ####
#################

import os

from flask import Flask, render_template
from flask.ext.login import LoginManager
from flask.ext.bcrypt import Bcrypt
from flask_mail import Mail
from flask.ext.debugtoolbar import DebugToolbarExtension
from flask.ext.sqlalchemy import SQLAlchemy


################
#### config ####
################

application = Flask(__name__)
application.config.from_object('config.ProductionConfig')

####################
#### extensions ####
####################

login_manager = LoginManager()
login_manager.init_app(application)
bcrypt = Bcrypt(application)
mail = Mail(application)
toolbar = DebugToolbarExtension(application)
db = SQLAlchemy(application)


####################
#### blueprints ####
####################
with application.app_context():
	from main.views import main_blueprint
	from user.views import user_blueprint
	application.register_blueprint(main_blueprint)
	application.register_blueprint(user_blueprint)


####################
#### flask-login ####
####################

from models import User

login_manager.login_view = "user.login"
login_manager.login_message_category = "danger"


@login_manager.user_loader
def load_user(user_id):
	return User.query.filter(User.id == int(user_id)).first()


########################
#### error handlers ####
########################

@application.errorhandler(403)
def forbidden_page(error):
	return render_template("errors/403.html"), 403


@application.errorhandler(404)
def page_not_found(error):
	return render_template("errors/404.html"), 404


@application.errorhandler(500)
def server_error_page(error):
	return render_template("errors/500.html"), 500

if __name__ == "__main__":
	application.config['SESSION_TYPE'] = 'filesystem'
	application.run(host='0.0.0.0')
