import os
import random
from collections import defaultdict
from typing import Optional, List, Union

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, session, flash, url_for, jsonify
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from markupsafe import Markup, escape
from pydantic import BaseModel, field_validator, ValidationError

from flask_session import Session

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']
app.config["SESSION_TYPE"] = "filesystem"
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['SQL_ADDRESS']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config.update(
    SESSION_COOKIE_SECURE=True,  # Для HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',  # Защита от CSRF
    WTF_CSRF_TIME_LIMIT=3600  # Время жизни токена (1 час)
)

if 'SECRET_KEY' not in os.environ:
    raise RuntimeError("SECRET_KEY environment variable not set")

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)

# Модели
class Character(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Личные данные
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    age = db.Column(db.Integer, nullable=True)
    faction = db.Column(db.String(100), nullable=True)
    has_pda = db.Column(db.Boolean, default=False)

    skills_experience = db.Column(db.Text, nullable=True)
    health_status = db.Column(db.Text, nullable=True)
    backstory = db.Column(db.Text, nullable=True)
    carry_weight = db.Column(db.Float, nullable=True)

    user = db.relationship('User', back_populates='characters')
    blocks = db.relationship('Block', back_populates='character', cascade="all, delete-orphan", order_by='Block.order')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    characters = db.relationship(
        'Character',
        back_populates='user',
        order_by=Character.id,
        cascade='all, delete-orphan'
    )

class Block(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    character_id = db.Column(db.Integer, db.ForeignKey('character.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('block.id'), nullable=True)
    type = db.Column(db.String(50), nullable=False)

    # Добавляем недостающие колонки
    order = db.Column(db.Integer, nullable=False, default=0)  # Важная колонка для сортировки
    position_x = db.Column(db.Integer, default=0)
    position_y = db.Column(db.Integer, default=0)
    width = db.Column(db.Integer, default=300)
    height = db.Column(db.Integer, default=200)
    color = db.Column(db.String(20), default='#ffffff')
    custom_fields = db.Column(db.JSON, nullable=True)
    data = db.Column(db.JSON, nullable=True)

    parent = db.relationship('Block', remote_side=[id], backref=db.backref('children'))
    character = db.relationship('Character', back_populates='blocks')

@app.route("/")
def index():
    return render_template("index.html")

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    characters = user.characters if user else []

    return render_template('dashboard.html', characters=characters)

@app.route("/character/create", methods=["GET", "POST"])
def create_character():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = session['user_id']
        try:
            # Упрощенная обработка без Pydantic
            first_name = request.form['first_name']
            last_name = request.form['last_name']

            character = Character(
                user_id=user_id,
                first_name=first_name,
                last_name=last_name
            )

            db.session.add(character)
            db.session.commit()
            flash('Персонаж создан')
            return redirect(url_for('edit_character', char_id=character.id))

        except Exception as e:
            flash(f"Ошибка создания персонажа: {str(e)}")
            return render_template('create_character.html')
    else:
        # GET-запрос - показать форму
        return render_template('create_character.html')

class CharacterSchema(BaseModel):
    first_name: Union[str, List[str]]
    last_name: Union[str, List[str]]
    age: Union[int, List[int], None] = None
    faction: Union[str, List[str], None] = None

    @field_validator('*')
    @classmethod
    def convert_lists(cls, v):
        """Конвертирует все списки в первые элементы"""
        if isinstance(v, list) and len(v) > 0:
            return v[0]
        return v

    @field_validator('age')
    @classmethod
    def validate_age(cls, v):
        if v is not None and not 1 <= v <= 120:
            raise ValueError("Возраст должен быть от 1 до 120")
        return v

@app.route("/character/<int:char_id>/edit", methods=["GET", "POST"])
def edit_character(char_id):
    character = Character.query.get_or_404(char_id)
    if 'user_id' not in session or session['user_id'] != character.user_id:
        flash("Доступ запрещён.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Обновляем данные персонажа
        character.first_name = request.form.get('first_name')
        character.last_name = request.form.get('last_name')
        character.age = int(request.form.get('age')) if request.form.get('age') else None
        character.faction = request.form.get('faction')
        character.has_pda = bool(request.form.get('has_pda'))
        character.skills_experience = request.form.get('skills_experience')
        character.health_status = request.form.get('health_status')
        character.backstory = request.form.get('backstory')
        character.carry_weight = float(request.form.get('carry_weight')) if request.form.get('carry_weight') else None

        # Сохраняем изменения
        db.session.commit()

        flash('Персонаж обновлён')
        return redirect(url_for('edit_character', char_id=char_id))

    # Получаем блоки с позициями
    blocks = Block.query.filter_by(character_id=char_id).all()

    for block in blocks:
        if block.data is None:
            block.data = {}

    # Группируем по родителям
    blocks_by_parent = defaultdict(list)
    for block in blocks:
        blocks_by_parent[block.parent_id].append(block)

    # Сортируем по position_y
    for blocks in blocks_by_parent.values():
        blocks.sort(key=lambda x: x.position_y if x.position_y is not None else 0)

    return render_template('edit_character.html',
                           character=character,
                           root_blocks=blocks_by_parent[None])  # None = корневые блоки

@app.route("/character/<int:char_id>")
def view_character(char_id):
    char = Character.query.get_or_404(char_id)
    if "user_id" not in session or session["user_id"] != char.user_id:
        flash("Доступ запрещён.")
        return redirect(url_for("login"))

    # Получаем блоки с позициями
    blocks = Block.query.filter_by(character_id=char_id).all()

    # Группируем по родителям
    blocks_by_parent = defaultdict(list)
    for block in blocks:
        blocks_by_parent[block.parent_id].append(block)

    # Сортируем по position_y
    for blocks in blocks_by_parent.values():
        blocks.sort(key=lambda x: x.position_y if x.position_y is not None else 0)

    block_type_translations = {
        'text': 'Текстовый блок',
        'weapon': 'Оружие',
        'armor': 'Броня',
        'helmet': 'Шлем',
        'inventory': 'Инвентарь',
        'character_info': 'Информация о персонаже',
        'table': 'Таблица'
    }

    return render_template("view_character.html",
                           character=char,
                           root_blocks=blocks_by_parent[None],
                           block_type_translations=block_type_translations)

@app.route('/character/<int:char_id>/delete', methods=['GET', 'POST'])
def delete_character(char_id):
    if 'user_id' not in session:
        flash('Требуется авторизация', 'error')
        return redirect(url_for('login'))

    character = Character.query.filter_by(
        id=char_id,
        user_id=session['user_id']
    ).first_or_404()

    if request.method == 'POST':
        try:
            db.session.delete(character)
            db.session.commit()
            flash('Персонаж успешно удалён', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Ошибка удаления: {str(e)}')
            flash(f'Ошибка удаления: {str(e)}', 'error')

    # Для GET-запросов показываем подтверждение
    return render_template('confirm_delete.html', character=character)

@app.route('/character/<int:char_id>/add_block', methods=['POST'])
def add_block(char_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.json

        # Определяем порядок для нового блока
        max_order = db.session.query(db.func.max(Block.order)).filter_by(
            character_id=char_id,
            parent_id=None
        ).scalar() or 0

        new_block = Block(
            character_id=char_id,
            type=data['type'],
            order=max_order + 1,
            position_x=data.get('position_x', 0),
            position_y=data.get('position_y', 0),
            width=data.get('width', 300),
            height=data.get('height', 200),
            color=data.get('color', '#ffffff'),
            data={}  # Пустые данные по умолчанию
        )

        db.session.add(new_block)
        db.session.commit()

        return jsonify({
            'id': new_block.id,
            'type': new_block.type,
            'position_x': new_block.position_x,
            'position_y': new_block.position_y,
            'width': new_block.width,
            'height': new_block.height,
            'color': new_block.color
        })
    except Exception as e:
        app.logger.error(f'Ошибка создания блока: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/block/<int:block_id>/update_position', methods=['POST'])
def update_block_position(block_id):
    block = Block.query.get_or_404(block_id)
    data = request.json
    block.position_x = data.get('position_x', 0)
    block.position_y = data.get('position_y', 0)
    db.session.commit()
    return jsonify(success=True)

@app.route('/block/<int:block_id>/update', methods=['POST'])
def update_block(block_id):
    block = Block.query.get_or_404(block_id)
    data = request.json

    # Просто сохраняем ВСЕ данные, которые пришли
    if 'color' in data:
        block.color = data['color']
        if block.type == 'table':
            if block.data is None:
                block.data = {}
            block.data['bg_color'] = data['color']
    if 'width' in data:
        block.width = data['width']
    if 'height' in data:
        block.height = data['height']
    if 'position_x' in data:
        block.position_x = data['position_x']
    if 'position_y' in data:
        block.position_y = data['position_y']
    if 'color' in data:
        block.color = data['color']

    # Сохраняем JSON данные как есть
    if 'block_data' in data:
        block.data = data['block_data']

    db.session.commit()
    return jsonify(success=True)

@app.route('/block/<int:block_id>/update_color', methods=['POST'])
def update_block_color(block_id):
    block = Block.query.get_or_404(block_id)
    data = request.json
    block.color = data.get('color', '#ffffff')
    db.session.commit()
    return jsonify(success=True)

@app.route('/block/<int:block_id>/update_size', methods=['POST'])
def update_block_size(block_id):
    block = Block.query.get_or_404(block_id)
    data = request.json
    block.width = data.get('width', 300)
    block.height = data.get('height', 200)
    db.session.commit()
    return jsonify(success=True)

@app.route('/block/<int:block_id>/update_field', methods=['POST'])
def update_block_field(block_id):
    block = Block.query.get_or_404(block_id)
    data = request.json
    field = data.get('field')
    value = data.get('value')
    character = block.character

    if 'user_id' not in session or session['user_id'] != character.user_id:
        return jsonify(error="Доступ запрещён"), 403

    if field and value is not None:
        # Инициализируем data, если нужно
        if block.data is None:
            block.data = {}

        # Обработка числовых полей
        if field in ['damage', 'accuracy', 'weight']:
            try:
                value = float(value)
            except ValueError:
                return jsonify(error="Некорректное числовое значение"), 400

        # Обновляем поле
        block.data[field] = value
        db.session.commit()
        return jsonify(success=True)

    return jsonify(error="Invalid request"), 400

@app.route('/block/<int:block_id>/action', methods=['POST'])
def block_action(block_id):
    block = Block.query.get_or_404(block_id)
    data = request.json
    action = data.get('action')

    if action == 'roll_attack':
        # Простой пример броска атаки
        roll = random.randint(1, 20)
        # Можно добавить логику на основе данных блока
        bonus = 3  # Пример бонуса

        return jsonify({
            'success': True,
            'result': {
                'roll': roll,
                'bonus': bonus,
                'total': roll + bonus,
                'success': roll + bonus >= 15
            }
        })

    return jsonify(error="Unknown action"), 400

@app.route('/block/<int:block_id>/delete', methods=['POST'])
def delete_block(block_id):
    block = Block.query.get_or_404(block_id)
    character = block.character
    if 'user_id' not in session or session['user_id'] != character.user_id:
        return jsonify({'error': 'Доступ запрещён.'}), 403

    db.session.delete(block)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/block/<int:block_id>/edit', methods=['POST'])
def edit_block(block_id):
    block = Block.query.get_or_404(block_id)
    character = block.character
    if 'user_id' not in session or session['user_id'] != character.user_id:
        return jsonify({'error': 'Доступ запрещён.'}), 403

    new_data = request.json.get('data')
    if new_data is None:
        return jsonify({'error': 'Нет данных для обновления.'}), 400

    block.data = new_data
    db.session.commit()
    return jsonify({'success': True})

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        if not email or not password:
            flash("Пожалуйста, заполните все поля.")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Пользователь с таким email уже существует.")
            return redirect(url_for("register"))

        pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(email=email, password_hash=pw_hash)
        db.session.add(new_user)
        db.session.commit()
        flash("Регистрация успешна. Войдите в систему.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            session["user_id"] = user.id
            return redirect(url_for("dashboard"))
        else:
            flash("Неверный email или пароль.")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Вы вышли из системы.")
    return redirect(url_for("index"))

@app.template_filter('nl2br')
def nl2br_filter(s):
    if s is None:
        return ''
    escaped = escape(s)
    # Заменяем переносы строк на <br>
    result = escaped.replace('\n', Markup('<br>\n'))
    return Markup(result)

@app.route('/character/<int:char_id>/update_blocks_order', methods=['POST'])
def update_blocks_order(char_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    character = Character.query.get_or_404(char_id)
    if character.user_id != session["user_id"]:
        return jsonify({"error": "Forbidden"}), 403

    order_data = request.get_json()
    try:
        for item in order_data:
            block = Block.query.filter_by(id=int(item['id']), character_id=char_id).first()
            if block:
                block.order = item['order']
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run(debug=True)