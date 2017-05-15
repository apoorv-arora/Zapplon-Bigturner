# project/user/views.py


#################
#### imports ####
#################

import datetime

from flask import render_template, Blueprint, url_for, \
    redirect, flash, request
from flask.ext.login import login_user, logout_user, \
    login_required, current_user
from models import User
from tokenizer import generate_confirmation_token, confirm_token
from decorators import check_confirmed
from .forms import LoginForm, RegisterForm, ChangePasswordForm,ResetPassword, \
    ExistingUser,ResetPasswordSubmit
import threading

threads=[]

################
#### config ####
################

user_blueprint = Blueprint('user', __name__,)
from mailer import send_email
from app import db, bcrypt
################
#### routes ####
################

@user_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect('/')
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        user = User(
            email=form.email.data,
            password=form.password.data,
            confirmed=False
        )

        db.session.add(user)
        db.session.commit()

        token = generate_confirmation_token(user.email)
        confirm_url = url_for('user.confirm_email', token=token, _external=True)
        html = render_template('user/activate.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        send_email(user.email, subject, html)

        login_user(user)
        flash('A confirmation email has been sent via email.', 'success')
        return redirect(url_for("user.unconfirmed"))

    return render_template('user/register.html', form=form)


@user_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/')
    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(
                user.password, request.form['password']):
            login_user(user)
            flash('Welcome.', 'success')
            return redirect(url_for('main.home'))
        else:
            flash('Invalid email and/or password.', 'danger')
            return render_template('user/login.html', form=form)
    return render_template('user/login.html', form=form)


@user_blueprint.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You were logged out.', 'success')
    return redirect(url_for('user.login'))


@user_blueprint.route('/profile', methods=['GET', 'POST'])
@login_required
@check_confirmed
def profile():
    form = ChangePasswordForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(email=current_user.email).first()
        if user:
            user.password = bcrypt.generate_password_hash(form.password.data)
            db.session.commit()
            flash('Password successfully changed.', 'success')
            return redirect(url_for('user.profile'))
        else:
            flash('Password change was unsuccessful.', 'danger')
            return redirect(url_for('user.profile'))
    return render_template('user/profile.html', form=form)


@user_blueprint.route('/confirm/<token>')
@login_required
def confirm_email(token):
    if current_user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
        return redirect(url_for('main.home'))
    email = confirm_token(token)
    user = User.query.filter_by(email=current_user.email).first_or_404()
    if user.email == email:
        user.confirmed = True
        user.confirmed_on = datetime.datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    else:
        flash('The confirmation link is invalid or has expired.', 'danger')
    return redirect(url_for('main.home'))


@user_blueprint.route('/reset/<token>',methods=['GET', 'POST'])
def reset_password(token):
    form = ChangePasswordForm(request.form) 
    email = confirm_token(token)
    if form.validate_on_submit():
        password = bcrypt.generate_password_hash(form.password.data)
        db.session.query(User).filter_by(email=email).update({"password": password})
        db.session.commit()
        db.session.close()
        flash('Password changed successfully','success')
        return redirect(url_for("user.login"))


    return render_template('user/changepassword.html',form=form)
def worker(email,form):
    password = bcrypt.generate_password_hash(form.password.data)
    db.session.query(User).filter_by(email=email).update({"password": password})
    db.session.commit()
@user_blueprint.route('/unconfirmed')
@login_required
def unconfirmed():
    if current_user.confirmed:
        return redirect(url_for('main.home'))
    flash('Please confirm your account!', 'warning')
    return render_template('user/unconfirmed.html')


@user_blueprint.route('/resend')
@login_required
def resend_confirmation():
    token = generate_confirmation_token(current_user.email)
    confirm_url = url_for('user.confirm_email', token=token, _external=True)
    html = render_template('user/activate.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(current_user.email, subject, html)
    flash('A new confirmation email has been sent.', 'success')
    return redirect(url_for('user.unconfirmed'))

@user_blueprint.route('/reset-password', methods=('GET', 'POST',))
def forgot_password():
    token = request.args.get('token',None)
    form = ResetPassword(request.form) #form
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_confirmation_token(user.email)
            confirm_url = url_for('user.reset_password', token=token, _external=True)
            html = render_template('user/forgetPw.html', confirm_url=confirm_url)
            subject = "Change Password"
            send_email(user.email, subject, html)
            flash('A mail to change Password has been sent.', 'success')
    return render_template('user/reset.html', form=form)
