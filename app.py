from flask import redirect,jsonify
from flask_mail import Mail,Message
import random
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename
from sqlalchemy.exc import SQLAlchemyError 
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_httpauth import HTTPBasicAuth
from flask import render_template, url_for,session,flash,get_flashed_messages
from flask import Flask,request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os,secrets
from PIL import Image

basedir=os.path.abspath(os.path.dirname(__file__))
app=Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'arindamrk3@gmail.com'  # replace with your Gmail
app.config['MAIL_PASSWORD'] = 'nmysrwcdlhefqwuh'     # use App Password, not Gmail password
app.config['MAIL_DEFAULT_SENDER'] = 'arindamrk3@gmail.com'
mail = Mail(app)
UPLOAD_FOLDER='/tmp/uploads'##os.path.join('/var', 'uploads')
os.makedirs(UPLOAD_FOLDER,exist_ok=True)
app.config['UPLOAD_FOLDER']=os.path.join('static','uploads')
app.config['ALLOWED_EXTENSIONS']={'png','jpg','jpeg','gif','mp4','mov','avi'}


app.secret_key="arindam@1234"
serializer = URLSafeTimedSerializer(app.secret_key)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:////tmp/database.db'##+os.path.join(basedir,'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(50),nullable=False)
    city=db.Column(db.String(40),nullable=False)
    email=db.Column(db.String(30),unique=True,nullable=False)
    is_verified=db.Column(db.Boolean,default=False)
    password_hash=db.Column(db.String(1228))
    media=db.relationship('Media',backref='user',lazy=True)
    profile_pic=db.Column(db.String(255),default='default.jpg')
    def set_password(self,password):
        self.password_hash=generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def to_dict(self):
        return {
            'id':self.id,
            'username':self.username,
            'city':self.city
        }
class Note(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    title=db.Column(db.String(100),nullable=False)
    content=db.Column(db.Text,nullable=False)
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    user=db.relationship('User',backref=db.backref('notes', lazy=True))

class Media(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    filename=db.Column(db.String(255),nullable=False)
    filetype=db.Column(db.String(20))
    caption=db.Column(db.String(255))
    upload_time=db.Column(db.DateTime,default=datetime.utcnow)
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'))
class Like(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'))
    media_id=db.Column(db.Integer,db.ForeignKey('media.id'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
def save_profile_pics(file):
    random_hex=secrets.token_hex(8)
    _, f_text=os.path.splitext(file.filename)
    picture_name=random_hex + f_text
    picture_path=os.path.join(app.root_path,'static/profile_pics',picture_name)
    output_size=(300,300)
    img=Image.open(file)
    img.thumbnail(output_size)
    img.save(picture_path)
    return picture_name
auth=HTTPBasicAuth()
@auth.verify_password
def verify_pass(username, password):
    user=User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        return user

@app.route("/register",methods=['POST','GET'])
def register():
    if request.method=="POST":
        username=request.form.get("username")
        city=request.form.get("city")
        password=request.form.get("password")
        email=request.form['email']
        if not username or not password:
            return render_template("register.html",error="all fields are required")
        existing_user=User.query.filter_by(username=username).first()
        if existing_user:
            print("user exist")
            return render_template("register.html",error="user already exist")
        new_user=User(username=username,city=city,email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        token=serializer.dumps(email,salt='email-confirmation')
        verify_link=url_for('verify_email',token=token,_external=True)############
        msg=Message("verify your Email",recipients=[email])
        msg.body=f"Hi {username},\n\n CLick the link below to verify your Email:\n{verify_link}\n\n Link will expire within 10 minutes."
        mail.send(msg)
        print("registration succesful verify link from email")
        flash("Registration successful! Please check your email to verify your account.", "info")
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route("/verify_email/<token>")
def verify_email(token):
    try:
        email=serializer.loads(token,salt='email-confirmation',max_age=600)
    except:
        flash("verification link expired!","danger")
        return redirect(url_for('login'))
    user=User.query.filter_by(email=email).first()
    if user:
        user.is_verified=True
        db.session.commit()
        print("Email verified")
        flash("Email verified successfully! You can login","success")
    else:
        flash("user not found","danger")
    return redirect(url_for('login'))


@app.route("/",methods=['POST','GET'])
def login():
    if 'user_id' in session:
        return redirect(url_for('homepage'))
    
    if request.method=='POST':
        username=request.form['username']
        password=request.form['password']
        user=User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if not user.is_verified:
                flash("please verify email before login","danger")
                return redirect(url_for('login'))
            session['user_id']=user.id
            session['username']=user.username
            flash("Login successful!", "success")
            print("login successfull")
            return redirect(url_for('homepage'))####dashboard
        else:
            flash('Invalid password or username','danger')
            print("incorrEct password or username")
            return redirect(url_for('login'))
    return render_template('login.html')



@app.route("/forget_password",methods=['POST', 'GET'])
def forget_password():
    print("forget password")
    if request.method=='POST':
        email=request.form['email']
        user=User.query.filter_by(email=email).first()#
        if user:
            otp=str(random.randint(100000, 999999))
            session['reset_email']=email
            session['otp']=otp
            msg=Message('RESET PASSWORD',recipients=[email])
            msg.body=f'Your OTP for password reset is {otp}' 
            mail.send(msg)
            flash('OTP sent successfully','info')
            print("OTP sent successfully")
            return redirect(url_for('verify_otp'))
        else:
            flash('No user found with this email.', 'danger')
    return render_template('forget_password.html')
        
    

@app.route("/verify_otp",methods=['GET','POST'])
def verify_otp():
    # if 'otp_created_at' in session:
    #     if datetime.utcnow().timestamp() - session['otp_created_at'] > 600:  # 10 minutes
    #         session.pop('otp', None)
    #         session.pop('reset_user_id', None)
    #         session.pop('otp_created_at', None)
    #         flash("OTP has expired. Please request a new one.", "danger")
    #         return redirect(url_for('forget_password'))

    if request.method=='POST':
        entered_otp=request.form['otp'].strip()
        if 'otp' in session and str(session['otp'])==entered_otp:
            flash("OTP verified you can reset password","success")
            return redirect(url_for('reset_password'))
        else:
            flash("Incorrect OTP","danger")
            return redirect(url_for('verify_otp'))
    return render_template("verify_otp.html")

@app.route("/reset_password",methods=['GET','POST'])
def reset_password():
    if request.method=='POST':
        new_password=request.form['password']
        reset_email=session.get('reset_email')
        if reset_email:
            user=User.query.filter_by(email=reset_email).first()
            if user:
                    user.set_password(new_password)
                    db.session.commit()
                    flash("Password reset successfully! Please login.", "success")
                    print("password changed successfully")
                    session.pop('otp',None)
                    session.pop('reset_user_id',None)
                    
                    return redirect(url_for('login'))
            else:
                flash('No account found for this Email','danger')
                return redirect(url_for('forget_password'))
        else:
            flash("Session expired. Try again.", "danger")
            return redirect(url_for('forget_password'))
    return render_template("reset_password.html")

@app.route("/upload",methods=['GET','POST'])
def upload():
    if 'user_id' not in session :
        flash("please log in first","danger")
        return redirect(url_for('login'))
    if request.method=='POST':
        file=request.files.get('file')
        caption=request.form.get('caption','').strip()
        user_id=session['user_id']
        if file and allowed_file(file.filename):  
            filename=secure_filename(file.filename)
            filepath=os.path.join(app.config['UPLOAD_FOLDER'],filename)
            file.save(filepath)
            print("file saved at:",filepath)
            filetype='video' if filename.split('.')[-1].lower() in ['mp4', 'mov', 'avi'] else 'image'
            new_media=Media(filename=filename,filetype=filetype,caption=caption,user_id=user_id)
            db.session.add(new_media)
            db.session.commit()
            flash("File uploaded successfully!","success")
            return redirect(url_for('profile'))
        else:
            flash("Invalid file type or no file","danger")
            return redirect(url_for('upload'))
    return render_template('upload.html')   


@app.route("/delete_media/<int:media_id>",methods=['POST'])
def delete_media(media_id):
    if 'user_id' not in session:
        flash("please login ")
        return redirect(url_for("login"))
    media=Media.query.get(media_id)
    User_id=session['user_id']
    if not media:
        flash("media not found")
        return redirect(url_for('profile'))
    if media.user_id!=User_id:
        flash("can not deletee this media")
        return redirect(url_for('profile'))
    Like.query.filter_by(media_id=media_id).delete()    ##delete all likes for the media

    filepath=os.path.join(app.config['UPLOAD_FOLDER'],media.filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    db.session.delete(media)
    db.session.commit()
    flash("media deleted successfully","success")
    return redirect(url_for('profile'))

 
@app.route("/my_media")
def my_media():
    if "user_id" not in session:
        flash("please login first","danger")
        return redirect(url_for('login'))
    user_id=session['user_id']
    media_files=Media.query.filter_by(user_id=user_id).order_by(Media.upload_time.desc()).all()
    return render_template('mygallary.html',media_files=media_files)


@app.route("/homepage")
def homepage():
    if 'user_id' not in session:
        flash("login please")
        return redirect(url_for('login'))
    ##user=db.session.get(User,session['user_id'])
    media_files=Media.query.order_by(Media.upload_time.desc()).all()
    likes={m.id:Like.query.filter_by(media_id=m.id).count() for m in media_files}
    user_likes={l.media_id for l in Like.query.filter_by(user_id=session.get('user_id')).all()}
    return render_template("homepage.html",media_files=media_files,likes=likes,user_likes=user_likes)

@app.route("/like/<int:media_id>",methods=['POST'])
def like(media_id):
    if 'user_id' not in session:
         return jsonify({"error":"not logged in"}),401 #redirect(url_for('login'))
    user_id=session['user_id']
    existing_like=Like.query.filter_by(user_id=user_id,media_id=media_id).first()
    if existing_like:
        db.session.delete(existing_like)
        db.session.commit()
        return jsonify({"status": "unliked"})
    else:
        new_like=Like(user_id=user_id,media_id=media_id)
        db.session.add(new_like)
        db.session.commit()
        return jsonify({"status": "liked"})

@app.route("/dashboard",methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user=db.session.get(User,session['user_id'])
    if user is None:
        session.clear()
        flash("session expired or user not found login or register again","danger")
        return redirect(url_for('login'))
    print("user enter to the dashboard")
    
    if request.method=='POST':
        note_con=request.form.get('content','').strip()
        note_title=request.form.get('title','').strip()
        if note_con:
            new_note=Note(title=note_title,content=note_con,user_id=user.id)
            db.session.add(new_note)
            db.session.commit()

            print("note added")
            
            flash("note added","success")
        else:
            flash('Note is empty')
        return redirect(url_for('dashboard'))
    notes=Note.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html',user=user,notes=notes)

@app.route("/delete_account",methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user=db.session.get(User,session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    password=request.form.get('password')
    if not password:
        flash("enter the password")
        return redirect(url_for('profile'))
    if not user.check_password(password):   
        flash("incorrect password")
        return redirect(url_for('profile'))
    try:
        
        notes=Note.query.filter_by(user_id=user.id).all()
        for n in notes:
            db.session.delete(n)    #delete note of specific user one by one not other user
        db.session.delete(user)     #delete the user
        db.session.commit()
        session.clear() #log out the user immediately after deleting account
        print("acccount deleted successfully")
        flash("acccount deleted successfully","success")
        return render_template("login.html")###############
    except SQLAlchemyError as e:
        print(e)
        db.session.rollback()
        flash("something went wrong wrong. Account not deleted!")
        return render_template("profile.html",user=user)


@app.route("/edit_note/<int:note_id>",methods=['POST','GET'])
def edit_note(note_id):
    note=Note.query.get_or_404(note_id)
    if 'user_id' not in session or note.user_id != session['user_id']:
        print("you are not allowed to edit this note!!")
        flash("you are not allowed to edit this note!!")
        return redirect(url_for('dashboard'))
    if request.method=="POST":
        note.title=request.form['title']
        note.content=request.form['content']
        db.session.commit()
        print("note updaated")
        flash("note updaated","success")
        return redirect(url_for('dashboard'))
    return render_template('edit_note.html',note=note)


@app.route("/delete_note/<int:note_id>")
def delete_note(note_id):
    note=Note.query.get_or_404(note_id)
    if 'user_id' not in session or note.user_id!=session['user_id']:
        print("you can not delete")
        flash("you can not delete")
        return redirect(url_for('dashboard'))
    db.session.delete(note)
    db.session.commit()
    flash("note deleted successfully","info")
    print("note deleted successfully")
    return redirect(url_for('dashboard'))






@app.route("/profile")
def profile():
    if 'user_id' not in session:
        flash("login please")
        return redirect(url_for('login'))
    user=db.session.get(User,session['user_id'])
    media_files=Media.query.filter_by(user_id=user.id).order_by(Media.upload_time.desc()).all()
    total_uploads=len(media_files)
    if not user:
        session.clear()
        print("user profile")
        return redirect(url_for('login'))
    return render_template('profile.html',user=user,media_files=media_files,total_uploads=total_uploads)


@app.route("/edit_profile", methods=['GET', 'POST'])
def edit_profile():
    
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user=db.session.get(User,session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    if request.method=="POST":
        new_username=request.form.get("username","").strip()
        new_city=request.form.get("city","").strip()
        new_pass=request.form.get("password","").strip()
        
        
        if not new_username or not new_city:
            flash("username or city can not be empty")
            return redirect(url_for('edit_profile'))
        
        if new_username!=user.username:
            conflict=User.query.filter_by(username=new_username).first()
            if conflict:
                print("conflict")
                flash("the username is already exist")
                return redirect(url_for('edit_profile'))
        if "profile_pic" in request.files:
            pic=request.files["profile_pic"]
            if pic and pic.filename !="":
                new_filename= save_profile_pics(pic)
                user.profile_pic=new_filename
        user.username=new_username
        user.city=new_city
        
        if new_pass:
            user.set_password(new_pass)
        db.session.commit()
        session['username']=user.username
        flash("Profile updated successfully.", "success")
        print("profile updated successfully")
        return redirect(url_for('profile'))
    return render_template("edit_profile.html",user=user)


@app.route('/logout')
def logout():
    session.clear()
    print("logged out")
    return redirect(url_for('login'))


if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)