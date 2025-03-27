import os
import secrets
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, current_user,
    logout_user, login_required
)
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

app.config['SECRET_KEY'] = 'your_secret_key_here'  # Replace with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///civicconnect.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -----------------------
# Database Models
# -----------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


class Issue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_file = db.Column(db.String(200), nullable=True)
    reported_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def __repr__(self):
        return f"Issue('{self.title}', '{self.category}')"


# -----------------------
# Routes
# -----------------------
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        # Check if user already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists. Please try again.', 'danger')
            return redirect(url_for('register'))
        new_user = User(username=username, email=email, password=hashed_pw)
        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('register'))
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


@app.route('/report-issue', methods=['GET','POST'])
@login_required
def report_issue():
    if request.method == 'POST':
        title = request.form.get('title')
        category = request.form.get('category')
        location = request.form.get('location')
        description = request.form.get('description')
        image_file = None
        if 'image' in request.files:
            image = request.files['image']
            if image and image.filename != '':
                random_hex = secrets.token_hex(8)
                _, f_ext = os.path.splitext(secure_filename(image.filename))
                image_filename = random_hex + f_ext
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
                image.save(save_path)
                image_file = image_filename
        new_issue = Issue(
            title=title,
            category=category,
            location=location,
            description=description,
            image_file=image_file,
            reported_by=current_user.id
        )
        db.session.add(new_issue)
        db.session.commit()
        flash('Issue reported successfully!', 'success')
        return redirect(url_for('view_issues'))
    return render_template('report_issue.html')


@app.route('/issues')
def view_issues():
    all_issues = Issue.query.all()
    return render_template('view_issues.html', issues=all_issues)


# -----------------------
# Database Initialization and Test User Creation
# -----------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
        
        # Create a predefined test user if not already in the database
        test_user = User.query.filter_by(username='testuser').first()
        if not test_user:
            hashed_pw = bcrypt.generate_password_hash('testpass').decode('utf-8')
            test_user = User(username='testuser', email='testuser@example.com', password=hashed_pw)
            db.session.add(test_user)
            db.session.commit()
            print("Test user created: username 'testuser', password 'testpass'")
        else:
            print("Test user already exists.")
            
    app.run(debug=True)
