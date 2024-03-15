from flask import Flask, render_template, session, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = 'tajný_klíč_zde'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['PROFILE_IMAGES'] = 'profile_images/'
db = SQLAlchemy(app)


# Třída pro uživatele v databázi
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    profile_image = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, default=False)

    # Metoda pro nastavení hesla uživatele
    def set_password(self, password):
        self.password = generate_password_hash(password)

    # Metoda pro ověření hesla uživatele
    def check_password(self, password):
        return check_password_hash(self.password, password)


# Třída pro objednávky v databázi
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    display = db.Column(db.Boolean, default=True)


# Hlavní stránka
@app.route('/')
def index():
    users = None
    displayed_orders = None

    if 'user_id' in session:
        users = User.query.all()
        displayed_orders = Order.query.all()  # Změna: zobrazí všechny objednávky pro administrátora

    return render_template('index.html', users=users, displayed_orders=displayed_orders)


# Přihlášení uživatele
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Byli jste úspěšně přihlášeni!', 'success')
            return redirect(url_for('orders'))
        else:
            flash('Neplatné uživatelské jméno nebo heslo. Zkuste to znovu.', 'danger')
    return render_template('login.html')


# Registrace uživatele
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Hesla se neshodují. Zkuste to znovu.', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Uživatelské jméno již existuje. Prosím, zvolte jiné.', 'danger')
            return redirect(url_for('register'))

        try:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Byli jste úspěšně zaregistrováni! Prosím, přihlaste se.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Nastala chyba: {str(e)}', 'danger')
            db.session.rollback()

    return render_template('register.html')


# Odhlášení uživatele
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Byli jste úspěšně odhlášeni!', 'success')
    return redirect(url_for('index'))


# Profil uživatele
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('Pro přístup k této stránce se musíte přihlásit.', 'danger')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        if 'profile_image' in request.files:
            profile_image = request.files['profile_image']
            if profile_image.filename:
                filename = secure_filename(profile_image.filename)
                save_folder = app.config['PROFILE_IMAGES']
                os.makedirs(save_folder, exist_ok=True)
                profile_image.save(f"static/{os.path.join(save_folder, filename)}")
                print(os.path.join(save_folder, filename))
                user.profile_image = os.path.join(save_folder, filename)
                db.session.commit()
                flash('Profil byl úspěšně aktualizován!', 'success')
            else:
                flash('Nebyl vybrán žádný obrázek.', 'warning')
            return redirect(url_for('profile'))
    return render_template('profile.html', user=user)


# Objednávky uživatele
@app.route('/orders', methods=['GET', 'POST'])
def orders():
    if 'user_id' not in session:
        flash('Pro přístup k této stránce se musíte přihlásit.', 'danger')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        message = request.form['message']
        display = request.form.get('display') == 'on'
        new_order = Order(message=message, user_id=user.id, display=display)
        db.session.add(new_order)
        db.session.commit()
        flash('Objednávka byla úspěšně vytvořena!', 'success')
        return redirect(url_for('orders'))
    orders = Order.query.filter_by(user_id=user.id).all()
    return render_template('orders.html', user=user, orders=orders)


# Zrušení objednávky
@app.route('/cancel_order/<int:order_id>', methods=['POST'])
def cancel_order(order_id):
    if 'user_id' not in session:
        flash('Pro přístup k této stránce se musíte přihlásit.', 'danger')
        return redirect(url_for('login'))
    order = Order.query.get(order_id)
    if order.user_id != session['user_id']:
        flash('Nemáte oprávnění k zrušení této objednávky.', 'danger')
        return redirect(url_for('orders'))
    db.session.delete(order)
    db.session.commit()
    flash('Objednávka byla úspěšně zrušena!', 'success')
    return redirect(url_for('orders'))


# Změna hesla
@app.route('/profile/update_password', methods=['POST'])
def update_password():
    if 'user_id' not in session:
        flash('Pro přístup k této stránce se musíte přihlásit.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']

        if new_password != confirm_new_password:
            flash('Nové heslo a potvrzení se neshodují.', 'danger')
            return redirect(url_for('profile'))

        if not user.check_password(current_password):
            flash('Nesprávné aktuální heslo.', 'danger')
            return redirect(url_for('profile'))

        user.set_password(new_password)
        db.session.commit()

        flash('Heslo bylo úspěšně aktualizováno!', 'success')
        return redirect(url_for('profile'))

    return redirect(url_for('profile'))


# Správa uživatelů pro administrátora
@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session:
        flash('Pro přístup k této stránce se musíte přihlásit.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if not user.is_admin:
        flash('Nemáte oprávnění k přístupu k této stránce.', 'danger')
        return redirect(url_for('index'))

    users = User.query.all()
    return render_template('admin_users.html', users=users)


# Smazání uživatele administrátorem
@app.route('/admin/delete_user', methods=['POST'])
def admin_delete_user():
    if 'user_id' not in session:
        flash('Pro přístup k této stránce se musíte přihlásit.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if not user.is_admin:
        flash('Nemáte oprávnění k přístupu k této stránce.', 'danger')
        return redirect(url_for('index'))

    user_id = request.form.get('user_id')
    user_to_delete = User.query.get(user_id)
    if user_to_delete:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('Uživatel byl úspěšně smazán!', 'success')
    else:
        flash('Uživatel nebyl nalezen.', 'danger')
    return redirect(url_for('admin_users'))


# Main
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_password = generate_password_hash('admin_password')
            admin_user = User(username='admin', password=admin_password, is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
        app.run(debug=True)
