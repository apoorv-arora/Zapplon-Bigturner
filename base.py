from flask.ext.testing import TestCase


from app import application, db
from models import User


class Base(TestCase):

    def setUp(self):
	    self.app_context = application.app_context()
	    self.app_context.push()

	def tearDown(self):
    	self.app_context.pop()