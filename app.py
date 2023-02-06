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





#dash
@app.route('/dashboard', methods=['GET','POST'] )
def dashboard(): 
    stu_name=session['stu_name']
    result=Result.query.limit(5)
    return render_template('dashboard.html',stu_name=stu_name,result=result)


@app.route('/results')
def resultevent():
        result=Result.query.limit(5)
        return render_template('resultview.html',result=result)



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



#sports club
@login_required
@app.route('/sportsclub')
def sportsclub():
    event_info=Event.query
    list=[]
    for i in event_info:
        if i.club_name=='Sports':
            list.append(i)
    
        
    return render_template('sportsclub.html',list=list)
#dance club


@login_required
@app.route('/danceclub')
def danceclub():
    event_info=Event.query
    list=[]
    for i in event_info:
        if i.club_name=='Dance':
            list.append(i)
    
        
    return render_template('danceclub.html',list=list)
#ML club
@login_required
@app.route('/techclub')
def techclub():
    event_info=Event.query
    list=[]
    for i in event_info:
        if i.club_name=='Tech':
            list.append(i)
    
        
    return render_template('Mlclub.html',list=list)

#music club
@login_required
@app.route('/musicclub')
def musicclub():
    event_info=Event.query
    list=[]
    for i in event_info:
        if i.club_name=='Music':
            list.append(i)
    
        
    return render_template('musicclub.html',list=list)

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

@login_required
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
    club_name=db.Column(db.String(100),nullable=False)

    def __repr__(self):
        return '<Name %r>' % self.id



class EventForm(FlaskForm):
    event_name=StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"eventname"})
    date_created=StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Date"})
    club_name=StringField(validators=[InputRequired(),Length(min=1,max=20)],render_kw={"placeholder":"Club"})
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
        new_event=Event(event_name=form.event_name.data, date_created=form.date_created.data,club_name=form.club_name.data)
        db.session.add(new_event)
        db.session.commit()
        return  redirect(url_for('headdashboard'))

    return render_template('eventform.html',form=form)

@login_required
@app.route('/update/<int:id>',methods = ['GET','POST'])
def update(id):
    form=EventForm()
    eve_id=Event.query.get_or_404(id)
    if request.method=="POST":
        if eve_id:
            db.session.delete(eve_id)
            db.session.commit()
     
              
            new_event=Event(event_name=form.event_name.data, date_created=form.date_created.data,club_name=form.club_name.data)

            db.session.add(new_event)
            db.session.commit()
            return redirect(url_for('headdashboard'))

    return render_template('update.html',eve_id=eve_id,form=form)


@login_required
@app.route('/delete/<int:id>',methods = ['GET','POST'])
def delete(id):
    eve_id=Event.query.get_or_404(id)
    if request.method=="POST":
        if eve_id:
            db.session.delete(eve_id)
            db.session.commit()
     
              
            
            return redirect(url_for('headdashboard'))

    return render_template('delete.html',eve_id=eve_id)



#participant

class Participant(db.Model,UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    email=db.Column(db.String(50),nullable=False)
    participant_name=db.Column(db.String(50),nullable=False)
    date_created=db.Column(db.String(100))
    event_name=db.Column(db.String(100),nullable=False)
    club_name=db.Column(db.String(100),nullable=False)

    def __repr__(self):
        return '<Name %r>' % self.id

  

@login_required
@app.route('/participant/<string:event_name>',methods=['GET','POST'])
def participant(event_name):
    
    eve_name=Event.query.filter(Event.event_name==event_name).first()
    if request.method=="POST":
        event_name=request.form['event_name']
        date_created=request.form['date_created']
        club_name=request.form['club_name']
        email_id=request.form['email_id']
        participant_name=request.form['participant_name']
        new_participant=Participant(event_name=event_name, date_created=date_created,club_name=club_name,email=email_id,participant_name=participant_name)
        db.session.add(new_participant)
        db.session.commit()
        return  redirect(url_for('sportsclub'))

    return render_template('par_register.html',eve_name=eve_name)

@login_required
@app.route('/participant_info',methods=['GET','POST'])
def participant_info():
    info=Participant.query
    return render_template("participant_info.html",info=info)


#club

class Club(db.Model,UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    email=db.Column(db.String(50),nullable=False ,unique=True)
    user_name=db.Column(db.String(50),nullable=False ,unique=True)
    date_joined=db.Column(db.String(100))
    club_name=db.Column(db.String(100),nullable=False)

    def __repr__(self):
        return '<Name %r>' % self.id



@login_required
@app.route('/join_a_club/<string:username>',methods=['GET','POST'])
def join_a_club(username):
    username=Student.query.filter(Student.stu_name==username).first()
    if request.method=="POST":
        user_name=request.form['user_name']
        date_joined=request.form['date_joined']
        club_name=request.form['club_name']
        email_id=request.form['email_id']
        new_member=Club(user_name=user_name, date_joined=date_joined,club_name=club_name,email=email_id)
        db.session.add(new_member)
        db.session.commit()
        return  redirect(url_for('dashboard'))
    return render_template('join_a_club.html',username=username)




@login_required
@app.route('/user_info/<string:name>')
def user_info(name):
    event=Participant.query.filter(Participant.participant_name==name).all()
    info=Club.query.filter(Club.user_name==name).first()
    return render_template('user_info.html',info=info,event=event)


#result

class Result(db.Model,UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    rank_one_name=db.Column(db.String(50),nullable=False )
    rank_two_name=db.Column(db.String(50),nullable=False )
    rank_three_name=db.Column(db.String(50),nullable=False )
    event_name=db.Column(db.String(50),nullable=False )

    def __repr__(self):
        return '<Name %r>' % self.id


@login_required
@app.route('/result/<int:id>',methods=['GET','POST'])
def result(id):
    name=Event.query.filter(Event.id==id).first()
    if request.method=="POST":
        rank_one_name= request.form['rank_one_name']
        rank_two_name= request.form['rank_two_name']
        rank_three_name= request.form['rank_three_name']
        event_name=request.form['event_name']
        ranking=Result(rank_one_name=rank_one_name,rank_two_name=rank_two_name,rank_three_name=rank_three_name,event_name=event_name)
        db.session.add(ranking)
        db.session.commit()
        return redirect(url_for('headdashboard'))
    return render_template('result.html',name=name)





#run

if __name__ == '__main__':
    app.run(debug=True)