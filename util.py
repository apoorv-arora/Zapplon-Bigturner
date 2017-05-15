# project/util.py


from flask.ext.testing import TestCase
from models import User
from app import application, db


class BaseTestCase(TestCase):

    def create_app(self):

        application.config.from_object('project.config.TestingConfig')
        return application

    @classmethod
    def setUpClass(self):
        db.create_all()
        user = User(
            email="test@user.com",
            password="just_a_test_user",
            confirmed=False
        )
        db.session.add(user)
        db.session.commit()
        

    @classmethod
    def tearDownClass(self):
        db.drop_all()