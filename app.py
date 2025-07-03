from flask import Flask, render_template, request, redirect, session, flash, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_session import Session
from markupsafe import Markup, escape
import uuid

app = Flask(__name__)
app.secret_key = "change_this_secret_key"  # обязательно замени на свой ключ
app.config["SESSION_TYPE"] = "filesystem"
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://adminuser:2563142@localhost/character_sheet'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)

# Модели
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password_hash = db.Column(db.String(128), nullable=False)
    characters = db.relationship('Character', back_populates='user')
    email = db.Column(db.String(120), unique=True, nullable=False)

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

class Block(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    character_id = db.Column(db.Integer, db.ForeignKey('character.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # например, 'inventory', 'notes'
    order = db.Column(db.Integer, nullable=False, default=0)
    settings = db.Column(db.JSON, nullable=True)  # для хранения параметров блока
    data = db.Column(db.JSON, nullable=True)  # данные блока, например, список предметов или текст заметок

    character = db.relationship('Character', back_populates='blocks')

User.characters = db.relationship('Character', order_by=Character.id, back_populates='user')

@app.before_request
def create_tables_once():
    #if not hasattr(app, 'tables_created'):
        db.create_all()
        app.tables_created = True

@app.route("/")
def index():
    return render_template("index.html")


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    characters = user.characters if user else []

    return render_template('dashboard.html', characters=characters)

@app.route("/character/create", methods=["GET", "POST"])
def create_character():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        age = request.form.get('age')
        faction = request.form.get('faction')
        has_pda = bool(request.form.get('has_pda'))
        skills_experience = request.form.get('skills_experience')
        health_status = request.form.get('health_status')
        backstory = request.form.get('backstory')
        carry_weight = request.form.get('carry_weight')

        character = Character(
            user_id=session['user_id'],
            first_name=first_name,
            last_name=last_name,
            age=int(age) if age else None,
            faction=faction,
            has_pda=has_pda,
            skills_experience=skills_experience,
            health_status=health_status,
            backstory=backstory,
            carry_weight=float(carry_weight) if carry_weight else None
        )

        db.session.add(character)
        db.session.commit()  # Сохраняем персонажа, теперь у него есть ID
        flash('Персонаж создан')
        return redirect(url_for('edit_character', char_id=character.id))

    return render_template('character_form.html', character=None)

@app.route("/character/<int:char_id>/edit", methods=["GET", "POST"])
def edit_character(char_id):
    character = Character.query.get_or_404(char_id)
    if 'user_id' not in session or session['user_id'] != character.user_id:
        flash("Доступ запрещён.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        character.first_name = request.form.get('first_name')
        character.last_name = request.form.get('last_name')
        character.age = int(request.form.get('age')) if request.form.get('age') else None
        character.faction = request.form.get('faction')
        character.has_pda = bool(request.form.get('has_pda'))
        character.skills_experience = request.form.get('skills_experience')
        character.health_status = request.form.get('health_status')
        character.backstory = request.form.get('backstory')
        character.carry_weight = float(request.form.get('carry_weight')) if request.form.get('carry_weight') else None

        db.session.commit()
        flash('Персонаж обновлён')
        return redirect(url_for('edit_character', char_id=char_id))

    blocks = Block.query.filter_by(character_id=char_id).order_by(Block.order).all()

    return render_template('edit_character.html', character=character, blocks=blocks)

@app.route("/character/<int:char_id>")
def view_character(char_id):
    char = Character.query.get_or_404(char_id)
    # Чтобы только владелец мог видеть, можно проверить:
    if "user_id" not in session or session["user_id"] != char.user_id:
        flash("Доступ запрещён.")
        return redirect(url_for("login"))
    return render_template("view_character.html", character=char)



@app.route('/character/<int:char_id>/add_block_ajax', methods=['POST'])
def add_block_ajax(char_id):
    character = Character.query.get_or_404(char_id)
    if 'user_id' not in session or session['user_id'] != character.user_id:
        return jsonify({'error': 'Доступ запрещён.'}), 403

    block_type = request.json.get('block_type')
    if not block_type:
        return jsonify({'error': 'Тип блока не указан.'}), 400

    # Определяем order как последний +1
    max_order = db.session.query(db.func.max(Block.order)).filter_by(character_id=char_id).scalar() or 0
    new_block = Block(character_id=char_id, type=block_type, order=max_order+1, settings={}, data={})
    db.session.add(new_block)
    db.session.commit()

    # Вернём данные нового блока для JS
    return jsonify({
        'id': new_block.id,
        'type': new_block.type,
        'order': new_block.order,
        'settings': new_block.settings,
        'data': new_block.data,
    })

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


# Регистрация
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

# Вход
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

# Выход
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