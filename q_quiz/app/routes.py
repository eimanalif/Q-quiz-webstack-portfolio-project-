from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, current_user, logout_user, login_required
from app import db
from app.models import User
from app import bcrypt
from flask import Blueprint
from functools import wraps
from app.models import Quiz, Question, Choice
from flask import jsonify


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

@main.route('/quiz/<int:quiz_id>', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    score = 0
    total_questions = len(questions)

    for question in questions:
        selected_choice_id = request.form.get(f'question_{question.id}')
        if selected_choice_id:
            selected_choice = Choice.query.get(int(selected_choice_id))
            if selected_choice.is_correct:
                score += 1

    # Calculate percentage score
    percentage = (score / total_questions) * 100

    # Store the result in the database
    quiz_result = QuizResult(
        user_id=session['user_id'],
        quiz_id=quiz.id,
        score=score,
        total_questions=total_questions,
        percentage=percentage
    )
    db.session.add(quiz_result)
    db.session.commit()
    
    flash(f'Quiz completed! Your score: {score}/{total_questions} ({percentage:.2f}%)')
    return redirect(url_for('view_results', quiz_result_id=quiz_result.id))

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

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to be logged in to access this page.')
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function

# Example: Protecting the quiz route
@main.route('/quiz')
@login_required
def quiz():
    # Load quiz data and render quiz page
    pass

@main.route('/quiz/<int:quiz_id>')
@login_required
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    return render_template('quiz.html', quiz=quiz, questions=questions)

@main.route('/results/<int:quiz_result_id>')
@login_required
def view_results(quiz_result_id):
    result = QuizResult.query.get_or_404(quiz_result_id)
    return render_template('results.html', result=result)

@main.route('/admin/quiz/new', methods=['GET', 'POST'])
@login_required
def new_quiz():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        time_limit = int(request.form['time_limit'])

        quiz = Quiz(title=title, description=description, time_limit=time_limit)
        db.session.add(quiz)
        db.session.commit()

        flash('Quiz created successfully!')
        return redirect(url_for('main.index'))

    return render_template('admin/new_quiz.html')

@main.route('/api/quiz/<int:quiz_id>', methods=['GET'])
def get_quiz_api(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()

    quiz_data = {
        'title': quiz.title,
        'description': quiz.description,
        'questions': []
    }

    for question in questions:
        question_data = {
            'text': question.text,
            'choices': [{'id': choice.id, 'text': choice.text} for choice in question.choices]
        }
        quiz_data['questions'].append(question_data)

    return jsonify(quiz_data)