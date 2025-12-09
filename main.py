from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change_this"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.Integer)
    password = db.Column(db.String(120), nullable=False)
    upi_id = db.Column(db.String(120), nullable=True)

class Items(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    cost = db.Column(db.Float, nullable=False)

class Products(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    cost = db.Column(db.Float, nullable=False)
    availability = db.Column(db.Boolean, default=True)

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('items.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    weight = db.Column(db.Float, nullable=False)
    time = db.Column(db.DateTime, default=datetime.utcnow)

def hash_password(plain_password: str) -> str:
    return generate_password_hash(plain_password, method='pbkdf2:sha256', salt_length=16)


@app.route('/')
def home():
    if 'user_id' not in session:
        return render_template("Home.html")
        
    user_name = session.get('user_name', 'Eco User')
    return render_template("Home.html", name=user_name)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))

    active_tab = 'signin'

    if request.method == 'POST':
        form_type = request.form.get('form_type')

        if form_type == 'signup':
            active_tab = 'signup'
            name = request.form.get('name')
            email = request.form.get('email')

            phone = request.form.get('phone') 
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            if password != confirm_password:
                flash('Passwords do not match!', 'error')
                return render_template('login.html', active_tab=active_tab)

            existing_user = Users.query.filter(
                (Users.email == email) | (Users.phone == phone)
            ).first()
            
            if existing_user:
                flash('A user with this email or phone number already exists.', 'error')
                return render_template('login.html', active_tab=active_tab)

            hashed_pw = hash_password(password) 
            new_user = Users(name=name, email=email, phone=phone, password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()

            flash('Sign up successful! Please sign in.', 'success')
            return redirect(url_for('login')) 

        elif form_type == 'login':
            active_tab = 'signin'
            credential = request.form.get('credential') 
            password = request.form.get('password')

            user = Users.query.filter(
                (Users.email == credential) | (Users.phone == credential)
            ).first()

            if user and check_password_hash(user.password, password):
                session['user_id'] = user.id
                session['user_name'] = user.name 
                return redirect(url_for('home'))
            else:
                flash('Invalid credentials. Please try again.', 'error')
                return render_template('login.html', active_tab=active_tab)

    return render_template('login.html', active_tab=active_tab)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/locations')
def locations():
    return render_template("locations.html")

@app.route('/services')
def services():
    return render_template("services.html")

@app.cli.command("create-db")
def create_db():
    db.create_all()
    print("Database created successfully.")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run( debug=True) 