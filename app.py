from flask import Flask ,render_template,redirect


from flask_sqlalchemy import SQLAlchemy,request
from datetime import datetime
from flask_migrate import Migrate
app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///friends.db'


#init
db=SQLAlchemy(app)
migrate=Migrate(app,db)



class Friends(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(50),nullable=False)
    date_created=db.Column(db.DateTime,default=datetime.utcnow)
    usn=db.Column(db.String(30))
    email=db.Column(db.String(30))

#create func to return string
    def __repr__(self):
        return '<Name %r>' % self.id
with app.app_context():
    db.create_all()


@app.route('/',methods=['POST','GET'])
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
        fk=Friends.query.order_by(Friends.date_created)
        return render_template("index.html",fk=fk)




if __name__ == '__main__':
    app.run(debug=True)
