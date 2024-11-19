from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crud_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.app_context().push()

# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

# Модель для CRUD
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('items', lazy=True))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Формы
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=50)])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

# Роуты
@app.route('/')
@login_required
def home():
    items = Item.query.filter_by(user_id=current_user.id).all()
    return render_template('home.html', items=items)


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Такой логин уже занят. Выберите другой.', 'error')
            return redirect(url_for('register'))
        try:
            hashed_password = generate_password_hash(form.password.data)
            new_user = User(username=form.username.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Успешная регистрация! Теперь авторизируйтесь в приложении.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Возникла ошибка при регистрации. Попробуйте ещё раз.', 'error')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Успешная авторизация!', 'success')
            return redirect(url_for('home'))
        flash('Неправильный логин или пароль.', 'error')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из своего аккаунта.', 'info')
    return redirect(url_for('login'))

@app.route('/add', methods=['POST'])
@login_required
def add_item():
    name = request.form.get('name')
    description = request.form.get('description')
    if not name:
        flash('Имя предмета не уникально.', 'error')
        return redirect(url_for('home'))
    try:
        new_item = Item(name=name, description=description, user_id=current_user.id)
        db.session.add(new_item)
        db.session.commit()
        flash('Предмет успешно создан!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Возникла ошибка при добавлении предмета. Попробуйте ещё раз.', 'error')
    return redirect(url_for('home'))

@app.route('/delete/<int:item_id>')
@login_required
def delete_item(item_id):
    item = Item.query.filter_by(id=item_id, user_id=current_user.id).first()
    if not item:
        flash('Предмет не найден.', 'error')
        return redirect(url_for('home'))
    try:
        db.session.delete(item)
        db.session.commit()
        flash('Предмет успешно удалён!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Возникла ошибка при удалении предмета. Попробуйте ещё раз.', 'error')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
