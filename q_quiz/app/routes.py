from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, current_user, logout_user, login_required
from app import db
from app.models import User
from app import bcrypt
from flask import Blueprint

main = Blueprint('main', __name__)

@main.route("/")
def home():
    return render_template("base.html")

@main.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        
        # Hash the password and create a new user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash("Account created successfully!", "success")
        return redirect(url_for("main.login"))
    return render_template("register.html")

@main.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        # Check if user exists and password is correct
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("main.dashboard"))
        else:
            flash("Login failed. Check your email and password.", "danger")
    return render_template("login.html")

@main.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@main.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("main.home"))

@main.route("/quizzes")
@login_required
def quizzes():
    quizzes = Quiz.query.all()
    return render_template("quizzes.html", quizzes=quizzes)

@main.route("/quiz/<int:quiz_id>")
@login_required
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    return render_template("take_quiz.html", quiz=quiz)

@main.route("/quiz/<int:quiz_id>/submit", methods=["POST"])
@login_required
def submit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = quiz.questions
    score = 0
    total = len(questions)

    for question in questions:
        selected_answer_id = request.form.get(str(question.id))
        if selected_answer_id:
            answer = Answer.query.get(selected_answer_id)
            if answer.is_correct:
                score += 1

    # Calculate percentage score
    percentage_score = (score / total) * 100

    # Store the quiz result in the database
    quiz_result = QuizResult(score=percentage_score, user_id=current_user.id, quiz_id=quiz.id)
    db.session.add(quiz_result)
    db.session.commit()
    
    flash(f'You scored {score} out of {total}', 'success')
    return redirect(url_for('main.quizzes'))

@main.route("/results")
@login_required
def results():
    results = QuizResult.query.filter_by(user_id=current_user.id).order_by(QuizResult.timestamp.desc()).all()
    return render_template("results.html", results=results)


@main.route("/admin/create_quiz", methods=["GET", "POST"])
@login_required
def create_quiz():
    if not current_user.is_admin:
        abort(403)  # Restrict access to admins

    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        quiz = Quiz(title=title, description=description)
        db.session.add(quiz)
        db.session.commit()
        flash("Quiz created successfully", "success")
        return redirect(url_for('main.quizzes'))

    return render_template("create_quiz.html")

@main.route("/admin/add_question/<int:quiz_id>", methods=["GET", "POST"])
@login_required
def add_question(quiz_id):
    if not current_user.is_admin:
        abort(403)

    quiz = Quiz.query.get_or_404(quiz_id)
    
    if request.method == "POST":
        content = request.form.get("content")
        question = Question(content=content, quiz_id=quiz.id)
        db.session.add(question)
        db.session.commit()
        flash("Question added successfully", "success")
        return redirect(url_for('main.add_question', quiz_id=quiz.id))

    return render_template("add_question.html", quiz=quiz)

@main.route("/admin/add_answer/<int:question_id>", methods=["GET", "POST"])
@login_required
def add_answer(question_id):
    if not current_user.is_admin:
        abort(403)

    question = Question.query.get_or_404(question_id)

    if request.method == "POST":
        content = request.form.get("content")
        is_correct = bool(request.form.get("is_correct"))
        answer = Answer(content=content, is_correct=is_correct, question_id=question.id)
        db.session.add(answer)
        db.session.commit()
        flash("Answer added successfully", "success")
        return redirect(url_for('main.add_answer', question_id=question.id))

    return render_template("add_answer.html", question=question)
