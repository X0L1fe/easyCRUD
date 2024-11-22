from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
from datetime import datetime, timedelta

SECRET_KEY = "very-very-secret-key"

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crud_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'


db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.app_context().push()

# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def generate_auth_token(self, expires_in=3600):
        return jwt.encode(
            {"id": self.id, "exp": datetime.utcnow() + timedelta(seconds=expires_in)},
            SECRET_KEY,
            algorithm="HS256"
        )

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            return User.query.get(data["id"])
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

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

def unified_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.is_json:  # Если запрос из API (Postman)
            token = request.headers.get("Authorization")
            if not token:
                return {"error": "Токен отсутствует."}, 401
            user = User.verify_auth_token(token.split(" ")[1])
            if not user:
                return {"error": "Неверный или истёкший токен."}, 401
            request.user = user
        else:  # Если запрос из интерфейса (браузер)
            if not current_user.is_authenticated:
                flash('Требуется авторизация.', 'error')
                return redirect(url_for('login'))
            request.user = current_user
        return f(*args, **kwargs)
    return decorated



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из своего аккаунта.', 'info')
    return redirect(url_for('login'))

@app.route('/items', methods=['GET'])
@unified_auth_required
def get_items():
    items = Item.query.filter_by(user_id=request.user.id).all()
    items_list = [{"id": item.id, "name": item.name, "description": item.description} for item in items]

    if request.is_json:
        return {"items": items_list}, 200
    return render_template('items.html', items=items_list)

@app.route('/add', methods=['POST'])
@unified_auth_required
def add_item():
    data = get_request_data()
    name = data.get('name')
    description = data.get('description')

    if not name:
        if request.is_json:
            return {"error": "Имя предмета не может быть пустым."}, 400
        else:
            flash('Имя предмета не может быть пустым.', 'error')
            return redirect(url_for('home'))

    try:
        new_item = Item(name=name, description=description, user_id=request.user.id)
        db.session.add(new_item)
        db.session.commit()
        if request.is_json:
            return {"message": "Предмет успешно создан!", "item_id": new_item.id}, 201
        else:
            flash('Предмет успешно создан!', 'success')
            return redirect(url_for('home'))
    except Exception as e:
        db.session.rollback()
        if request.is_json:
            return {"error": "Ошибка при создании предмета."}, 500
        else:
            flash('Ошибка при создании предмета.', 'error')
            return redirect(url_for('home'))
    
@app.route('/update/<int:item_id>', methods=['POST'])
@unified_auth_required
def update_item(item_id):
    item = Item.query.filter_by(id=item_id, user_id=request.user.id).first()
    if not item:
        if request.is_json:
            return {"error": "Предмет не найден."}, 404
        else:
            flash('Предмет не найден.', 'error')
            return redirect(url_for('home'))

    data = get_request_data()
    name = data.get('name')
    description = data.get('description')

    if not name:
        if request.is_json:
            return {"error": "Имя предмета не может быть пустым."}, 400
        else:
            flash('Имя предмета не может быть пустым.', 'error')
            return redirect(url_for('home'))

    try:
        item.name = name
        item.description = description
        db.session.commit()
        if request.is_json:
            return {"message": "Предмет успешно обновлён!"}, 200
        else:
            flash('Предмет успешно обновлён!', 'success')
            return redirect(url_for('home'))
    except Exception as e:
        db.session.rollback()
        if request.is_json:
            return {"error": "Ошибка при обновлении предмета."}, 500
        else:
            flash('Ошибка при обновлении предмета.', 'error')
            return redirect(url_for('home'))

@app.route('/delete/<int:item_id>', methods=['POST'])
@unified_auth_required
def delete_item(item_id):
    item = Item.query.filter_by(id=item_id, user_id=request.user.id).first()
    if not item:
        if request.is_json:
            return {"error": "Предмет не найден."}, 404
        else:
            flash('Предмет не найден.', 'error')
            return redirect(url_for('home'))

    try:
        db.session.delete(item)
        db.session.commit()
        if request.is_json:
            return {"message": "Предмет успешно удалён!"}, 200
        else:
            flash('Предмет успешно удалён!', 'success')
            return redirect(url_for('home'))
    except Exception as e:
        db.session.rollback()
        if request.is_json:
            return {"error": "Ошибка при удалении предмета."}, 500
        else:
            flash('Ошибка при удалении предмета.', 'error')
            return redirect(url_for('home'))


#API POSTMAN OR 1C_REQUEST
@app.route('/token', methods=['POST'])
def get_token():
    username = request.json.get('username')
    password = request.json.get('password')
    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):  # Метод `check_password` нужно реализовать в модели User
        token = user.generate_auth_token()
        return {"token": token}, 200
    return {"error": "Неверный логин или пароль"}, 401

def get_request_data():
    if request.is_json:
        return request.get_json()
    return request.form.to_dict()


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
