# project/email.py

from flask.ext.mail import Message
from app import application, mail

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=application.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)
