from flask import Flask ,render_template,redirect,url_for,session
from flask_sqlalchemy import SQLAlchemy,request
from datetime import datetime
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt,bcrypt
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import InputRequired,Length,ValidationError





app=Flask(__name__)

#database connect
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///main.db'
app.config['SECRET_KEY']='thisisasecretkey'

#init
db=SQLAlchemy(app)
migrate=Migrate(app,db,render_as_batch=True)
bcrypt=Bcrypt(app)


login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"


@login_manager.user_loader
def load_user(user_id):
    return Student.query.get(int(user_id))


with app.app_context():
    db.create_all()


class Friends(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(50),nullable=False)
    date_created=db.Column(db.DateTime,default=datetime.utcnow)
    usn=db.Column(db.String(30))
    email=db.Column(db.String(30))


    def __repr__(self):
        return '<Name %r>' % self.id

        



class Student(db.Model,UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    stu_name=db.Column(db.String(50),nullable=False ,unique=True)
    stu_password=db.Column(db.String(100),nullable=False)


#forms

class RegisterForm(FlaskForm):
    stu_name=StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Username"})
    stu_password=PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Password"})

    submit=SubmitField("Register")
    
    def validate_username(self,stu_name):
        existing_user_username=Student.query.filter_by(stu_name=stu_name.data).first()
        if existing_user_username:
            raise ValidationError(
                "tHAT USERNAME EXIST"
            )


class LoginForm(FlaskForm):
    stu_name=StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Username"})
    stu_password=PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Password"})

    submit=SubmitField("Login")




#head 



#home

@app.route('/',methods=['POST','GET'])
def home():
    return render_template('index.html')


#form
@app.route('/form',methods=['POST','GET'])
def myform():
    if request.method=="POST":
        x_name=request.form['name']
        x_email=request.form['email']
        x_usn=request.form['usn']
        f_name=Friends(name=x_name,usn=x_usn,email=x_email)
        #push to db
        try:
            db.session.add(f_name)
            db.session.commit()
            return redirect('/')
        except:
            return 'eroorrrr'
    else:
        fk=Friends.query.order_by(Friends.date_created).all()
        return render_template("form.html",fk=fk)



#dash
@app.route('/dashboard', methods=['GET','POST'] )
def dashboard(): 
    stu_name=session['stu_name']
    return render_template('dashboard.html',stu_name=stu_name)




#stu_login
@app.route('/login', methods=['GET','POST'])
def login():
    form= LoginForm()
    if form.validate_on_submit():
        user=Student.query.filter_by(stu_name=form.stu_name.data).first()
        if user:
            if bcrypt.check_password_hash(user.stu_password,form.stu_password.data):
                login_user(user)
                session['stu_name']=request.form['stu_name']
                return redirect(url_for('dashboard'))
    

    return render_template('login.html',form=form)



#stu_register
@app.route('/register' ,methods=['GET','POST'])
def register():
    form=RegisterForm()
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.stu_password.data)
        new_user=Student(stu_name=form.stu_name.data,stu_password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html',form=form)


@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user
    return redirect(url_for('login'))

@login_required
@app.route('/sportsclub')
def sportsclub():
    event_info=Event.query
    list=[]
    for i in event_info:
        if i.club_name=='Sports':
            list.append(i)

    return render_template('sportsclub.html',list=list)


#head 




class Head(db.Model,UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    h_name=db.Column(db.String(50),nullable=False ,unique=True)
    h_password=db.Column(db.String(100),nullable=False)


    def __repr__(self):
        return '<Name %r>' % self.id

class Head_RegisterForm(FlaskForm):
    h_name=StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Username"})
    h_password=PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Password"})

    submit=SubmitField("Register")
    
    def validate_username(self,h_name):
        existing_user_username=Head.query.filter_by(h_name=h_name.data).first()
        if existing_user_username:
            raise ValidationError(
                "tHAT USERNAME EXIST"
            )


class head_LoginForm(FlaskForm):
    h_name=StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Username"})
    h_password=PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Password"})

    submit=SubmitField("Login")
    



@app.route('/headlogin', methods=['GET','POST'])
def headlogin():
    form= head_LoginForm()
    if form.validate_on_submit():
        head_user=Head.query.filter_by(h_name=form.h_name.data).first()
        if head_user:
            if bcrypt.check_password_hash(head_user.h_password,form.h_password.data):
                login_user(head_user)
                session['h_name']=request.form['h_name']
                return redirect(url_for('headdashboard'))
    

    return render_template('headlogin.html',form=form)




@app.route('/headregister' ,methods=['GET','POST'])
def headregister():
    form=Head_RegisterForm()
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.h_password.data)
        new_user=Head(h_name=form.h_name.data,h_password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('headlogin'))

    return render_template('headregister.html',form=form)


@app.route('/headlogout',methods=['GET','POST'])
@login_required
def headlogout():
    logout_user
    return redirect(url_for('headlogin'))


@app.route('/headdashboard', methods=['GET','POST'] )
def headdashboard(): 
    event_info=Event.query
    h_name=session['h_name']
    return render_template('headdashboard.html',h_name=h_name,event_info=event_info)






#event

class Event(db.Model,UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    event_name=db.Column(db.String(50),nullable=False ,unique=True)
    date_created=db.Column(db.String(100))
    event_id=db.Column(db.String(100),nullable=False)
    club_name=db.Column(db.String(100),nullable=False)

    def __repr__(self):
        return '<Name %r>' % self.id



class EventForm(FlaskForm):
    event_name=StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Username"})
    date_created=StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Date"})
    club_name=StringField(validators=[InputRequired(),Length(min=1,max=20)],render_kw={"placeholder":"Club"})
    event_id=StringField(validators=[InputRequired(),Length(min=1,max=20)],render_kw={"placeholder":"id"})
    submit=SubmitField("Submit")
    
    def validate_event(self,event_name):
        existing_user_username=Event.query.filter_by(event_name=event_name.data).first()
        if existing_user_username:
            raise ValidationError(
                "tHAT Event EXIST"
            )
@login_required
@app.route('/eventform',methods=['GET','POST'])
def eventform():
    form=EventForm()
    if form.validate_on_submit() or  request.method=="POST":
        new_event=Event(event_name=form.event_name.data, date_created=form.date_created.data,club_name=form.club_name.data,event_id=form.event_id.data)
        db.session.add(new_event)
        db.session.commit()
        return  redirect(url_for('headdashboard'))

    return render_template('eventform.html',form=form)

if __name__ == '__main__':
    app.run(debug=True)