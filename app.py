from mimetypes import init
from flask import Flask, redirect, render_template,redirect,url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
#from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
# from werkzeug.urls import url_quote, url_decode, url_encode
# from werkzeug.http import parse_options_header
# from werkzeug.utils import cached_property
# from werkzeug.routing import parse_rule

app = Flask(__name__)
#adding the secret key
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///database.db' 
Bootstrap(app)
db=SQLAlchemy(app)
# login_manager = LoginManager()
# login_manager.init_app(app)
# login_manager.login_view = 'login'


class User(db.Model): 
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(12),unique=True,nullable=False)
    email=db.Column(db.String(50),unique=True,nullable=False)
    password=db.Column(db.String(80),nullable=False)

# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))

class LoginForm(FlaskForm):

    username=StringField('username',validators=[InputRequired(),Length(min=4,max=12)])
    
    password=PasswordField('password',validators=[InputRequired(),Length(min=7,max=15)])

    remember=BooleanField('remember me')

class RegisterForm(FlaskForm):
    email=StringField('email',validators=[InputRequired(),Email(message='Incorrect EmailID'),Length(max=50)])

    username=StringField('username',validators=[InputRequired(),Length(min=4,max=12)])
    
    password=PasswordField('password',validators=[InputRequired(),Length(min=7,max=15)])


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login',methods=['Get','Post'])
def login():
    form=LoginForm()

    if form.validate_on_submit():
        # return '<h1>' +form.username.data+' '+form.password.data +'</h1>'
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password,form.password.data):
                #login_user(user,remember=form.remember.data)
                return redirect(url_for('dashboard'))
        return '<h1> Invalid Username or password'
    return render_template('login.html', form=form)

@app.route('/signup',methods=['Get','Post'])
def signup():
    form=RegisterForm()

    if form.validate_on_submit():
        hashed_password=generate_password_hash(form.password.data,method='sha256')
        new_user=User(username=form.username.data,email=form.email.data,password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return "<h1> New User has been created </h1>"
        #return '<h1>' + form.username.data +' '+form.email.data+' '+form.password.data +'</h1>'
    return render_template('signup.html',form=form)

@app.route('/dashboard')
# @login_required
# def logout():
#     logout_user()
#     return redirect(url_for('index'))

def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)