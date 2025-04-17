from flask import Flask, render_template, request, redirect, url_for, session, jsonify ,flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
import re
import os
import sys
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from datetime import timedelta

app = Flask(__name__)

# Configuration base de données
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'bcp2'
# Configuration de la gestion des sessions
app.config['SECRET_KEY'] = 'hellooo'  # clé secrète pour signer les sessions
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Expiration de la session après 30 minutes


mysql = MySQL(app)


@app.route("/")
def home():
    return render_template("index.html")


@app.route('/check-session')
def check_session():
    return f"""
    user_id: {session.get('user_id')} <br>
    email: {session.get('email')} <br>
    role: {session.get('role')}
 """

from werkzeug.security import check_password_hash

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        print(user)
        if user and check_password_hash(user['password'], password):
            session['email'] = user['email']
            session['role'] = user['role']
            session['user_id'] = user['id']
            session['nom'] = user['nom']

            flash('Connexion réussie', 'success')

            # 🔀 Redirection selon le rôle
            if user['role'] == 'admin':
               return redirect(url_for('dashboard'))
            else:
               return render_template('video.html')
        else:
            flash('Identifiants incorrects', 'danger')

    return render_template('login.html')



@app.route("/logout")
def logout():
    session.clear()
    flash("Déconnexion réussie", "success")
    return redirect(url_for('login'))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        fullname = request.form.get("fullname")
        email = request.form.get("email")
        password = request.form.get("password")
        filiere = request.form.get("filiere")
        
        # Le rôle par défaut est "admin"
        role = "user"

        # Vérification de l'email
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            flash("L'adresse email est déjà utilisée", "danger")
            return redirect(url_for('register'))

        # Hachage du mot de passe
        hashed_password = generate_password_hash(password)

        # Insertion dans la base de données avec le rôle "admin"
        cursor.execute("INSERT INTO users (email, password, nom, role, filiere) VALUES (%s, %s, %s, %s, %s)", 
                       (email, hashed_password, fullname, role, filiere))
        mysql.connection.commit()
        cursor.close()

        flash("Inscription réussie, vous pouvez maintenant vous connecter", "success")
        return render_template('video.html')  # Redirection vers la page des responsables

    return render_template('register.html')  # Redirection vers la page des responsables

def get_user_by_email(email):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    return user


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        # TODO : Vérifie si cet email existe dans ta base de données
        user = get_user_by_email(email)  # Exemple fictif

        if user:
            token = s.dumps(email, salt='reset-password')
            reset_url = url_for('reset_password', token=token, _external=True)

            msg = Message('Réinitialisation de votre mot de passe',
                          sender='ton.email@gmail.com',
                          recipients=[email])
            msg.body = f'Bonjour,\n\nCliquez sur le lien suivant pour réinitialiser votre mot de passe :\n{reset_url}\n\nCe lien expire dans 30 minutes.'
            mail.send(msg)

        flash('Si l’adresse e-mail est correcte, un lien vous a été envoyé.')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


# Configuration pour l'envoi d'e-mails (exemple avec Gmail)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'jarbouaidoha@gmail.com'
app.config['MAIL_PASSWORD'] = 'leao kphx jwho giwg'  # mot de passe d'application

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

def update_user_password(email, new_password):
    hashed_password = generate_password_hash(new_password)
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
    mysql.connection.commit()
    cursor.close()

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='reset-password', max_age=1800)  # lien valide 30 minutes
    except Exception as e:
        flash("Le lien a expiré ou est invalide.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return redirect(request.url)

        # Hasher et mettre à jour le mot de passe dans la base de données
        hashed_pw = generate_password_hash(password)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_pw, email))
        mysql.connection.commit()
        cursor.close()

        flash("Mot de passe réinitialisé avec succès.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')



def hash_password(password):
    from werkzeug.security import generate_password_hash
    return generate_password_hash(password)

@app.route('/video')
def video():
    return render_template('video.html')

@app.route('/quiz')
def quiz():
    return render_template('quiz.html')


correct_answers = {
    'q1': 'b',
    'q2': 'c',
    'q3': 'c',
    'q4': 'c',
    'q5': 'c',
    'q6': 'c',
    'q7': 'c',
    'q8': 'c',
    'q9': 'b',
    'q10': 'c',
    'q11': 'c',
    'q12': 'c',
    'q13': 'c',
    'q14': 'c',
    'q15': 'c'
}

def calculate_score(user_answers):
    score = 0
    for question, answer in user_answers.items():
        if answer == correct_answers.get(question):
            score += 1
    return score

from flask import request, render_template, session

@app.route('/submit_quiz', methods=['POST'])
def submit_quiz():
    user_answers = request.form.to_dict()  # Récupère les réponses de l'utilisateur
    score = calculate_score(user_answers)  # Calcule le score du quiz

    user_id = session.get('user_id')  # Récupère l'identifiant de l'utilisateur connecté

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("INSERT INTO score (user_id, score) VALUES (%s, %s)", (user_id, score))
    mysql.connection.commit()
    cursor.close()

    return render_template('quiz_result.html', score=score, correct_answers=correct_answers, request=request)



@app.route('/dashboard')
def dashboard():
    print('lololololoooooooooooooooooooy')
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT u.nom, u.filiere, s.score FROM users u JOIN score s ON u.id = s.user_id")
    utilisateurs = cursor.fetchall()
    cursor.close()
    return render_template('dashboard.html', utilisateurs=utilisateurs)



if __name__ == "__main__":
    app.run(debug=True)
