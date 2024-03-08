from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['PROFILE_IMAGES'] = 'profile_images/'
db = SQLAlchemy(app)


# Define your models here using SQLAlchemy
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    profile_image = db.Column(db.String(100))  # File path or external link to profile image
    # Add more fields as needed


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    display = db.Column(db.Boolean, default=True)  # Whether the order should be displayed to other users
    # Add more fields as needed


# Define routes here
@app.route('/')
def index():
    users = None
    displayed_orders = None

    if 'user_id' in session:
        # Fetch list of users from the database
        users = User.query.all()

        # Fetch orders marked for display from all users
        displayed_orders = Order.query.filter_by(display=True).all()

    return render_template('index.html', users=users, displayed_orders=displayed_orders)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('You have been logged in successfully!', 'success')
            return redirect(url_for('orders'))  # Redirect to the orders page upon successful login
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check if the username is already taken
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
        # Create a new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('You have been registered successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('index'))


import os


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('You need to log in to access this page.', 'danger')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        # Update profile information
        # For simplicity, let's assume the user can only update the profile image
        if 'profile_image' in request.files:
            profile_image = request.files['profile_image']
            if profile_image.filename:  # Check if a file was uploaded
                # Generate a unique filename for the profile image
                filename = secure_filename(profile_image.filename)
                # Save the profile image to the folder specified in app.config['PROFILE_IMAGES']
                save_folder = app.config['PROFILE_IMAGES']
                os.makedirs(save_folder, exist_ok=True)  # Create the folder if it doesn't exist
                profile_image.save(f"static/{os.path.join(save_folder, filename)}")
                print(os.path.join(save_folder, filename))
                # Update the user's profile image path in the database
                user.profile_image = os.path.join(save_folder, filename)
                db.session.commit()
                flash('Profile updated successfully!', 'success')
            else:
                flash('No image selected.', 'warning')
            return redirect(url_for('profile'))
    return render_template('profile.html', user=user)


@app.route('/orders', methods=['GET', 'POST'])
def orders():
    if 'user_id' not in session:
        flash('You need to log in to access this page.', 'danger')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        message = request.form['message']
        display = request.form.get('display') == 'on'  # Check if the checkbox is checked
        new_order = Order(message=message, user_id=user.id, display=display)
        db.session.add(new_order)
        db.session.commit()
        flash('Order created successfully!', 'success')
        return redirect(url_for('orders'))
    orders = Order.query.filter_by(user_id=user.id).all()
    return render_template('orders.html', user=user, orders=orders)


@app.route('/cancel_order/<int:order_id>', methods=['POST'])
def cancel_order(order_id):
    if 'user_id' not in session:
        flash('You need to log in to access this page.', 'danger')
        return redirect(url_for('login'))
    order = Order.query.get(order_id)
    if order.user_id != session['user_id']:
        flash('You are not authorized to cancel this order.', 'danger')
        return redirect(url_for('orders'))
    db.session.delete(order)
    db.session.commit()
    flash('Order canceled successfully!', 'success')
    return redirect(url_for('orders'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)
