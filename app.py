from flask import Flask, render_template, session
from flask import request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql.functions import current_user
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
    is_admin = db.Column(db.Boolean, default=False)  # Indicates if the user is an administrator

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


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
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        try:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('You have been registered successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')
            db.session.rollback()

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


@app.route('/profile/update_password', methods=['POST'])
def update_password():
    if 'user_id' not in session:
        flash('You need to log in to access this page.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']

        # Check if the new password and confirmation match
        if new_password != confirm_new_password:
            flash('New password and confirmation do not match.', 'danger')
            return redirect(url_for('profile'))

        # Check if the provided current password is correct
        if not user.check_password(current_password):
            flash('Incorrect current password.', 'danger')
            return redirect(url_for('profile'))

        # Update the current user's password
        user.set_password(new_password)
        db.session.commit()

        flash('Password updated successfully!', 'success')
        return redirect(url_for('profile'))

    # Handle GET requests to this route (e.g., if someone manually navigates to it)
    return redirect(url_for('profile'))


@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session:
        flash('You need to log in to access this page.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if not user.is_admin:
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('index'))

    users = User.query.all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/delete_user', methods=['POST'])
def admin_delete_user():
    if 'user_id' not in session:
        flash('You need to log in to access this page.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if not user.is_admin:
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('index'))

    user_id = request.form.get('user_id')  # Retrieve the user ID from the form data
    user_to_delete = User.query.get(user_id)
    if user_to_delete:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('admin_users'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Add an initial admin user if it doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin_password = generate_password_hash('admin_password')
            admin_user = User(username='admin', password=admin_password, is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
        app.run(debug=True)
