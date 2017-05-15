# project/main/views.py


#################
#### imports ####
#################

from flask.ext.login import login_user, logout_user, \
	login_required, current_user
from flask import render_template, Blueprint, request
from flask.ext.login import login_required
import threading
from models import User
################
#### config ####
################

main_blueprint = Blueprint('main', __name__,)
threads = []

################
#### routes ####
################http://stackoverflow.com/questions/23744171/flask-get-all-products-from-table-and-iterate-over-them

@main_blueprint.route('/')
#@login_required
def home():
	if current_user.is_authenticated:
		return render_template('main/index.html')
	else:
		return render_template('main/landing.html')

@main_blueprint.route('/user/<id>')
def singleuser(id):
	singleuser = User.query.filter_by(id=id).first_or_404()
	return render_template('main/alluser.html', singleuser=singleuser)


from werkzeug.security import generate_password_hash, check_password_hash
from models import Posts, Tracking, Points, Transaction
from flask_wtf import Form
from wtforms import validators
from wtforms import TextField, StringField, SelectField
from wtforms.validators import required
from flask import redirect, url_for, request, flash
from hashids import Hashids
from flask import current_app
from flask.ext.sqlalchemy import SQLAlchemy

hashids = Hashids()

db = SQLAlchemy(current_app)
db.create_all()



@main_blueprint.route('/tracking')
@login_required
def tracking():
	if not current_user.admin:
		return redirect('/')
	tracking = Tracking.query.all()
	return render_template('main/alluser.html', tracking = tracking)

@main_blueprint.route('/points')
@login_required
def points():
	if not current_user.admin:
		return redirect('/')
	points = Points.query.order_by(Points.earned_points.desc()).all()
	return render_template('main/alluser.html', points = points)


class changeratevalidator(Form):
	rate = TextField('cpm',validators=[required()])

@main_blueprint.route('/showusers', methods=['GET', 'POST','delete'])
@login_required
def showusers():
	if not current_user.admin:
		return redirect('/')
	
	deleteuserbyid = request.args.get('deleteuserbyid')
	if deleteuserbyid > 0:
		User.query.filter(User.id == deleteuserbyid).delete()
		db.session.commit()
		db.session.close()
		

	
	form = changeratevalidator()
	user = User.query.filter(User.id == current_user.id).first()
	#flash(user.usertype, "warning")
	if form.validate_on_submit():
		user.usertype = form.rate.data
		db.session.query(User).filter_by(id = current_user.id).update({"usertype": form.rate.data})
		db.session.commit()
		

	if current_user.usertype > 1:
		flash("yes you are affiliated", "warning")
		
	toggle = request.args.get('toggle')
	if toggle > 0:
		usertobetoggled = User.query.filter_by(id = toggle).first()
		
		if usertobetoggled.usertype is 0:
			usertobetoggled.usertype = 1
			
		elif usertobetoggled.usertype is 1:
			usertobetoggled.usertype = 2
			
		# elif usertobetoggled.usertype is 2:
			# usertobetoggled.usertype = 3
		elif usertobetoggled.usertype is 2:
			usertobetoggled.usertype = 0
			
		db.session.query(User).filter_by(id = toggle).update({"usertype": usertobetoggled.usertype})
		db.session.commit()
		db.session.close()
		return redirect(url_for('main.showusers'))
	users = User.query.order_by(User.id.desc()).all()
	db.session.close()
	return render_template("main/Users.html", users=users, rate = user.usertype, form = form)


from sqlalchemy import func
from datetime import datetime, timedelta
@main_blueprint.route('/showposts', methods=['GET'])
@login_required
def showposts():
	deletepostbyid = request.args.get('deletepostbyid')
	if current_user.admin:
		if deletepostbyid > 0:
			postToDelete = Posts.query.filter(Posts.id == deletepostbyid).first()
			current_db_sessions = db.session.object_session(postToDelete)
			current_db_sessions.delete(postToDelete)		
			current_db_sessions.commit()
			
	rate = User.query.filter(User.id == 1).first()
	
	posts = Posts.query.order_by(Posts.id.desc()).all()
	showpoints = request.args.get('showpoints')
	
	
	if showpoints > 0 and current_user.usertype > 0:

		posts = Posts.query.join(Points, Posts.id == Points.post_ID) \
		.add_columns(Points.earned_points,Posts.post_topheading, Posts.post_title, Posts.id, Posts.post_link, Posts.post_image, Posts.post_code, Posts.post_description).filter_by(user_ID = current_user.id).order_by(Points.earned_points.desc()).all()
		# pointsofpast = Tracking.query.filter_by(user_ID = current_user.id).filter_by(Tracking.created_on >= (datetime.utcnow() - timedelta(3600 * 24 * 15)).sum()
		
		pointsofpast = Tracking.query.filter(Tracking.user_ID == current_user.id).filter(Tracking.created_on >= (datetime.now() - timedelta(15))).count()
		pointsofyesterday = Tracking.query.filter(Tracking.user_ID == current_user.id).filter(Tracking.created_on >= (datetime.now() - timedelta(1))).count()

		flash(datetime.now(), "warning")
		# flash(datetime.now()-timedelta(15), "warning")
		return render_template("main/Posts.html", title="all posts", posts = posts, ref = hashids.encode(current_user.id), pointsofpast = pointsofpast, pointsofyesterday=pointsofyesterday, rate = rate.usertype, showpoints = 10)
	if current_user.usertype < 1:
		flash("Get affiliated to access earnings!", "warning")
	db.session.close()
	return render_template("main/Posts.html", title="all posts", posts = posts, ref = hashids.encode(current_user.id), rate = rate.usertype)	# posts = Posts.query.join(Posts.id = Points.post_ID).order_by(desc(Points.earned_points)).all()
	# posts = Posts.query.all()
	# points = Points.query.all()





@main_blueprint.route('/pages', methods=['GET'])
@login_required
def pages():
	category = request.args.get('category')
	limitpage = 6
	showearning = request.args.get('showearning')
	if showearning > 0 and current_user.usertype > 0: 
		posts = Posts.query.join(Points, Posts.id == Points.post_ID) \
		.add_columns(Points.earned_points, Posts.post_topheading, Posts.post_title, Posts.id, Posts.post_link, Posts.post_image, Posts.post_code, Posts.post_description).filter_by(user_ID = current_user.id).order_by(Points.earned_points.desc()).all()
		return render_template("main/alluser.html", title="all posts", posts = posts, ref = hashids.encode(current_user.id))

	pagerequested = request.args.get('page')
	# pagerequested = int(pagerequested)
	pageno = 1
	if pagerequested > 1:
		pageno = int(pagerequested)
		# flash(int(pagerequested), "warning")
	if pageno > limitpage:
		pageno = 1
	if category=='all':
		toplinkpage = Posts.query.order_by(Posts.id.desc()).paginate(pageno, 6, False)
	else:
		toplinkpage = Posts.query.filter_by(post_category=category).order_by(Posts.id.desc()).paginate(pageno, 6, False)

		
	post = ['entertainment', 'relationships', 'wtf', 'all']
	
	return render_template("main/toplinks.html",title="pages",post=post,category=category, apage = toplinkpage, ref = hashids.encode(current_user.id), currentpageno = pageno, limitpage = limitpage)


@main_blueprint.route('/showpost/<code>', methods=['GET'])
def showpost(code):
	singlepost = Posts.query.filter_by(post_code=code).first_or_404()
	flash(singlepost.id, "warning")
	user_code = request.args.get('ref')
	remote_addr = request.remote_addr

    	db.session.expire_on_commit = False	
    	singlepost = Posts.query.filter_by(post_code=code).first_or_404()

    	if(user_code):
     		tup = hashids.decode(user_code)
		try:
			user_code = float(tup[0])
		except:
			user_code = -1;

    	if( Tracking.query.filter(Tracking.post_ID == singlepost.id).filter( Tracking.ip == remote_addr).filter(Tracking.user_ID == user_code).scalar() is None):
        	newtrack = Tracking(singlepost.id, user_code , remote_addr)
        	db.session.add(newtrack)

      		if( Points.query.filter(Points.post_ID == singlepost.id).filter(Points.user_ID == user_code).scalar() is None):
        		newpoint = Points(user_code, singlepost.id, 1)
            		db.session.add(newpoint)

        	else:
            		element = Points.query.filter(Points.post_ID == singlepost.id).filter(Points.user_ID == user_code).first()
            		element.earned_points += 1
        	try: 	
			db.session.commit()
		except:
			db.session.rollback()
		finally:
			db.session.close()     

	return render_template("main/single.html", title="post", singlepost = singlepost)


# adding post to database

class addpostvalidator(Form):
	post_topheading = TextField('post_bottom-title',validators=[required()])
	post_title = TextField('post_top-heading',validators=[required()])
	post_link = TextField('post_link',validators=[required()])
	post_image = TextField('post_image',validators=[required()])
	post_description = TextField('post_description',validators=[required()])
	post_category = SelectField('post_type', choices = [('entertainment','entertainment'), ('fashion', 'fashion'), ('food', 'food'), ('relationships', 'relationships'), ('wtf', 'wtf'), ('travel', 'travel'), ('sports', 'sports'), ('other', 'other')], validators=[required()])



#http://stackoverflow.com/questions/20837209/flask-wtform-save-form-to-db
@main_blueprint.route('/addpost/',methods=['GET','POST'])
@login_required
def addpost():
	if current_user.usertype < 2:
		if not current_user.admin:
			return redirect('/')

	form = addpostvalidator()
	if form.validate_on_submit():
	
		new_post = Posts(
			form.post_topheading.data,
			form.post_title.data,
			form.post_link.data,
			form.post_image.data,
			form.post_description.data,
			form.post_category.data,
			generate_password_hash(form.post_title.data)
			)
		db.session.add(new_post)
		db.session.commit()
		db.session.close()
		return redirect('/')
	db.session.close()
	return render_template('main/addpost.html', form=form)


class detailsvalidator(Form):

	name = TextField('name',validators=[required()])
	phoneno = TextField('phoneno',validators=[required()])
	city = TextField('city',validators=[required()])
	country = TextField('country',validators=[required()])
	profile = TextField('profile',validators=[required()])
	page = TextField('page',validators=[required()])
	account_holdername = TextField('account_holdername')
	bank_name = TextField('bank_name')
	account_number = TextField('account_number')
	swift_code = TextField('swift_code')
	iban_number = TextField('iban_number')
	ifsc_code = TextField('ifsc_code')
	branch_address = TextField('branch_address')



@main_blueprint.route('/userdetails/',methods=['GET','POST'])
@login_required
def userdetails():
	paid = 0
	unpaid = 0
	ID = 0
	userid = request.args.get('userid')
	if current_user.admin and userid and int(userid) > 0:
		ID = int(userid)
	else:
		ID = current_user.id
	user = User.query.filter(User.id == ID).first_or_404()
	form = detailsvalidator()
	if form.validate_on_submit():
	
		
		user.name = 	form.name.data
		user.phoneno = form.phoneno.data
		user.city	=form.city.data
		user.country=	form.country.data
		user.profile=	form.profile.data
		user.page=	form.page.data
		user.account_holdername=	form.account_holdername.data
		user.bank_name=	form.bank_name.data
		user.account_number	=form.account_number.data
		user.swift_code	=form.swift_code.data
		user.iban_number	=form.iban_number.data
		user.ifsc_code	=form.ifsc_code.data
		user.branch_address=	form.branch_address.data
		
		
		db.session.commit()
		db.session.close()
		return redirect('/')
	
	if ID:
		user = User.query.filter(User.id == ID).first_or_404()
		
		# unpaid = User.query.outerjoin(Tracking, User.id == Tracking.user_ID).filter(Tracking.created_on > User.lastpaidon).add_columns(User.id, User.lastpaidon,User.email, User.name, func.count(Tracking.id).label('trackingcount')).group_by(User.id).filter(User.id == userid)
		unpaid = Tracking.query.filter(Tracking.created_on > user.lastpaidon).filter(Tracking.user_ID == ID).count()

		paidtothisuser = Transaction.query.filter(Transaction.user_ID == ID).all()
		if paidtothisuser:
			paid = sum([item.amount for item in paidtothisuser])

	rate = User.query.filter(User.id == 1).first()
	total = (float(rate.usertype)/1000)*float(unpaid) + float(paid)
	db.session.close()
	return render_template('main/userdetails.html', form=form, user = user, rate=rate.usertype, paidtilldate=paid, unpaidtilldate = unpaid, total = total)


class paymentvalidator(Form):
	amount = TextField('amount',validators=[required()])
	comment = TextField('comment',validators=[])

#9534862741

@main_blueprint.route('/payment', methods=(['GET', 'POST']))
@login_required
def payment():
	form = paymentvalidator()
	unpaidpoints = 0
	totalamount = 0
	listofpayments = Transaction.query.filter(Transaction.user_ID == current_user.id).order_by(Transaction.created_on.desc())
	userid = request.args.get('userid')
	payfor = request.args.get('payfor')
	
	if current_user.admin and userid and int(userid) > 0:
		if Transaction.query.filter(Transaction.user_ID == int(userid)).count() > 0:
			listofpayments = Transaction.query.filter(Transaction.user_ID == int(userid)).order_by(Transaction.created_on.desc())
			flash("last payment made on: {}".format(listofpayments[0].created_on), "warning")
			# lastpaymentdate = lastpayment.created_on;
			unpaidpoints = Tracking.query.filter(Tracking.user_ID == userid).filter(Tracking.created_on > listofpayments[0].created_on).count()
			rate = User.query.filter(User.id == 1).first()
			flash("unpaidpoints :%d, %d"%(unpaidpoints, rate.usertype*unpaidpoints), "warning")
			totalamount = sum([item.amount for item in listofpayments])

	elif current_user.admin:
		if Transaction.query.order_by(Transaction.created_on.desc()).count() > 0:
			listofpayments = Transaction.query.order_by(Transaction.created_on.desc()).all()
			# listofpayments = Transaction.query.all()
			flash("showing all payments", "warning")
			totalamount = sum([item.amount for item in listofpayments])
	else:
		flash("last payment made on: {}".format(listofpayments[0].created_on), "warning")
		unpaidpoints = Tracking.query.filter(Tracking.user_ID == current_user.id).filter(Tracking.created_on > listofpayments[0].created_on).count()
		rate = User.query.filter(User.id == 1).first()
		flash("unpaidpoints :%d, %d"%(unpaidpoints, rate.usertype*unpaidpoints), "warning")
		totalamount = sum([item.amount for item in listofpayments])
	
		
			

	if payfor and int(payfor) > 0 and current_user.admin and int(userid) > 0:
		if form.validate_on_submit():
			new_payment = Transaction(
			form.amount.data,
			userid,
			form.comment.data,
			)
			db.session.add(new_payment)
			db.session.commit()


			use = User.query.filter(User.id == payfor).first()
			use.lastpaidon = datetime.now()
			db.session.commit()
			db.session.close()
			return redirect(url_for('main.payment'))
	db.session.close()
	return render_template("main/payment.html", payments = listofpayments, payfor = payfor, form = form, unpaidpoints = unpaidpoints, totalamount = totalamount)

from sqlalchemy import func
@main_blueprint.route('/payuser', methods=(['GET']))
@login_required
def payuser():
	if not current_user.admin:
		redirect('/')
	paid = 0
	# elements = User.query.outerjoin(Transaction, User.id == Transaction.user_ID).add_columns(User.id,User.name, func.sum(Transaction.amount)).group_by(User.id)
	# paid = User.query.outerjoin(Transaction, User.id == Transaction.user_ID).add_columns(User.id,User.lastpaidon, User.email, func.sum(Transaction.amount).label('summ')).group_by(User.id)
	# unpaid = User.query.outerjoin(Tracking, User.id == Tracking.user_ID).filter(Tracking.created_on > User.lastpaidon).add_columns(User.id, func.count(Tracking.id).label('trackingcount')).group_by(User.id).filter(User.id == current_user.id)
	# unpaid = User.query.outerjoin(Tracking, User.id == Tracking.user_ID).filter(Tracking.created_on > User.lastpaidon).add_columns(User.id, User.lastpaidon,User.email, User.name, func.count(Tracking.id).label('trackingcount')).group_by(User.id).filter(User.id == userid)
	userid = 0
	userid =  request.args.get('userid')
	if userid:
		user = User.query.filter(User.id == userid).first_or_404()
		
		# unpaid = User.query.outerjoin(Tracking, User.id == Tracking.user_ID).filter(Tracking.created_on > User.lastpaidon).add_columns(User.id, User.lastpaidon,User.email, User.name, func.count(Tracking.id).label('trackingcount')).group_by(User.id).filter(User.id == userid)
		unpaid = Tracking.query.filter(Tracking.created_on > user.lastpaidon).filter(Tracking.user_ID == userid).count()

		paidtothisuser = Transaction.query.filter(Transaction.user_ID == int(userid)).all()
		if paidtothisuser:
			paid = sum([item.amount for item in paidtothisuser])

	rate = User.query.filter(User.id == 1).first()
	
	
		
	return render_template("main/payuser.html", unpaid = unpaid, rate = rate.usertype, paid = paid)

