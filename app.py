import os
import json
import random
import string
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Length
from wtforms import StringField, PasswordField, HiddenField
from wtforms.validators import DataRequired, Email
from flask_wtf.csrf import CSRFProtect

from wtforms import StringField, TextAreaField, IntegerField, BooleanField, HiddenField
from wtforms.validators import DataRequired
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test_prep.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  
csrf = CSRFProtect()
csrf = CSRFProtect()
csrf.init_app(app)  # 10MB max file size
app.config['WTF_CSRF_ENABLED'] = False

# Email configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

# Gemini API configuration
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
genai.configure(api_key=GEMINI_API_KEY)

db = SQLAlchemy(app)

# Configure logging
handler = RotatingFileHandler('app.log', maxBytes=1000000, backupCount=5)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)

MATERIALS_FOLDER = os.path.join(os.getcwd(), 'materials')

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(120), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, index=True)
    otp_code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    purpose = db.Column(db.String(50), nullable=False)  # 'registration', 'password_reset'

class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    total_marks = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    time_limit = db.Column(db.Integer, nullable=False)  # in minutes
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    marks_per_question = db.Column(db.Integer, nullable=False)
    chapters = db.relationship('Chapter', backref='subject', lazy=True)

class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id', ondelete='CASCADE'))
    name = db.Column(db.String(100), nullable=False)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(500), nullable=False)
    option_b = db.Column(db.String(500), nullable=False)
    option_c = db.Column(db.String(500), nullable=False)
    option_d = db.Column(db.String(500), nullable=False)
    correct_answer = db.Column(db.String(1), nullable=False)  # A, B, C, D
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TestResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    correct_answers = db.Column(db.Integer, nullable=False)
    incorrect_answers = db.Column(db.Integer, nullable=False)
    time_taken = db.Column(db.Integer, nullable=False)  # in minutes
    percentage = db.Column(db.Float, nullable=False)
    subjects_attempted = db.Column(db.Text, nullable=False)  # JSON string
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_result_id = db.Column(db.Integer, db.ForeignKey('test_result.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    user_answer = db.Column(db.String(1))  # A, B, C, D or None if not answered
    is_correct = db.Column(db.Boolean, nullable=False)

class StudyMaterial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    material_type = db.Column(db.String(50), nullable=False)  # notes, formulas, pdf
    file_path = db.Column(db.String(500), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Forms
class AdminActionForm(FlaskForm):
    csrf_token = HiddenField()

class AddTestForm(FlaskForm):
    name = StringField('Test Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    total_marks = IntegerField('Total Marks', validators=[DataRequired()])
    total_questions = IntegerField('Total Questions', validators=[DataRequired()])
    time_limit = IntegerField('Time Limit (minutes)', validators=[DataRequired()])
    is_active = BooleanField('Active (Visible to students)')
    csrf_token = HiddenField()

class AddSubjectForm(FlaskForm):
    name = StringField('Subject Name', validators=[DataRequired()])
    total_questions = IntegerField('Total Questions', validators=[DataRequired()])
    marks_per_question = IntegerField('Marks per Question', validators=[DataRequired()])
    csrf_token = HiddenField()

class AddChapterForm(FlaskForm):
    name = StringField('Chapter Name', validators=[DataRequired(), Length(min=2, max=100)])
    csrf_token = HiddenField()

# Utility Functions
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_email(to_email, subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_ADDRESS, to_email, text)
        server.quit()
        return True
    except Exception as e:
        app.logger.error(f"Email sending failed: {e}")
        return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('admin_login'))
        
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Admin access required.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def format_gemini_response(response_text):
    """Format Gemini response by breaking at double asterisks"""
    lines = response_text.split('**')
    formatted_lines = []
    for i, line in enumerate(lines):
        if line.strip():
            if i % 2 == 0:
                formatted_lines.append(line.strip())
            else:
                formatted_lines.append(f"**{line.strip()}**")
    return '\n'.join(formatted_lines)

def handle_db_operation(operation, success_message, error_message):
    try:
        operation()
        db.session.commit()
        flash(success_message, 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error: {str(e)}")
        flash(error_message, 'error')

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please use a different email.', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken. Please choose a different username.', 'error')
            return render_template('register.html')
        
        # Generate OTP
        otp_code = generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        
        # Save OTP to database
        otp = OTP(email=email, otp_code=otp_code, expires_at=expires_at, purpose='registration')
        db.session.add(otp)
        
        # Create user (unverified)
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_verified=False
        )
        db.session.add(user)
        db.session.commit()
        
        # Send OTP email
        subject = "Email Verification - Entry Test Preparation"
        body = f"Your OTP for email verification is: {otp_code}\nThis OTP will expire in 10 minutes."
        
        if send_email(email, subject, body):
            session['registration_email'] = email
            flash('OTP sent to your email. Please verify to complete registration.', 'success')
            return redirect(url_for('verify_otp', purpose='registration'))
        else:
            flash('Failed to send OTP. Please try again.', 'error')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/verify_otp/<purpose>', methods=['GET', 'POST'])
def verify_otp(purpose):
    if purpose not in ['registration', 'password_reset']:
        flash('Invalid verification purpose.', 'error')
        return redirect(url_for('login'))

    email = session.get('registration_email' if purpose == 'registration' else 'reset_email')
    if not email:
        flash('Session expired. Please try again.', 'error')
        return redirect(url_for('register' if purpose == 'registration' else 'forgot_password'))

    if request.method == 'POST':
        otp_code = request.form.get('otp')
        
        # Verify OTP
        otp = OTP.query.filter_by(
            email=email,
            otp_code=otp_code,
            purpose=purpose,
            is_used=False
        ).first()
        
        if not otp:
            flash('Invalid OTP. Please try again.', 'error')
            return render_template('verify_otp.html', purpose=purpose, email=email)
        
        if otp.expires_at < datetime.utcnow():
            flash('OTP has expired. Please request a new one.', 'error')
            return render_template('verify_otp.html', purpose=purpose, email=email)
        
        # Mark OTP as used
        otp.is_used = True
        
        if purpose == 'registration':
            user = User.query.filter_by(email=email).first()
            if user:
                user.is_verified = True
                session.pop('registration_email', None)
                db.session.commit()
                flash('Email verified successfully! You can now log in.', 'success')
                return redirect(url_for('login'))
        else:
            session['verified_reset_email'] = email
            db.session.commit()
            flash('OTP verified. Please reset your password.', 'success')
            return redirect(url_for('reset_password'))

        flash('Error processing verification.', 'error')
        return render_template('verify_otp.html', purpose=purpose, email=email)
    
    return render_template('verify_otp.html', purpose=purpose, email=email)

from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # create an instance of the form

    if form.validate_on_submit():  # checks if it's a POST and CSRF is valid
        email = form.email.data
        password = form.password.data
        
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Email not found. Please check your email or register.', 'error')
            return render_template('login.html', form=form)

        if not user.is_verified:
            otp_code = generate_otp()
            expires_at = datetime.utcnow() + timedelta(minutes=10)

            old_otps = OTP.query.filter_by(email=email, purpose='registration', is_used=False).all()
            for otp in old_otps:
                otp.is_used = True

            new_otp = OTP(email=email, otp_code=otp_code, expires_at=expires_at, purpose='registration')
            db.session.add(new_otp)
            db.session.commit()

            subject = "Email Verification - Entry Test Preparation"
            body = f"Your OTP for email verification is: {otp_code}\nThis OTP will expire in 10 minutes."

            if send_email(email, subject, body):
                session['registration_email'] = email
                flash('Your email is not verified. A new OTP has been sent to your email.', 'error')
                return redirect(url_for('verify_otp', purpose='registration'))
            else:
                flash('Failed to send OTP. Please try again.', 'error')
                return render_template('login.html', form=form)

        if not user.is_active:
            flash('Account is deactivated. Please contact administrator.', 'error')
            return render_template('login.html', form=form)

        if check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid password. Please try again.', 'error')
            return render_template('login.html', form=form)

    return render_template('login.html', form=form)  # <-- pass form


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email not found. Please check your email.', 'error')
            return render_template('forgot_password.html')
        
        # Generate OTP
        otp_code = generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        
        otp = OTP(email=email, otp_code=otp_code, expires_at=expires_at, purpose='password_reset')
        db.session.add(otp)
        db.session.commit()
        
        # Send OTP email
        subject = "Password Reset - Entry Test Preparation"
        body = f"Your OTP for password reset is: {otp_code}\nThis OTP will expire in 10 minutes."
        
        if send_email(email, subject, body):
            session['reset_email'] = email
            flash('OTP sent to your email for password reset.', 'success')
            return redirect(url_for('verify_otp', purpose='password_reset'))
        else:
            flash('Failed to send OTP. Please try again.', 'error')
            return render_template('forgot_password.html')
    
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'verified_reset_email' not in session:
        flash('Please verify OTP first.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html')
        
        email = session['verified_reset_email']
        user = User.query.filter_by(email=email).first()
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        session.pop('verified_reset_email', None)
        flash('Password reset successfully! You can now log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    
    # Get user statistics
    total_tests = TestResult.query.filter_by(user_id=user_id).count()
    results = TestResult.query.filter_by(user_id=user_id).all()
    
    avg_percentage = 0
    total_time = 0
    recent_tests = []
    
    if results:
        avg_percentage = sum(r.percentage for r in results) / len(results)
        total_time = sum(r.time_taken for r in results)
        recent_tests = TestResult.query.filter_by(user_id=user_id).order_by(TestResult.completed_at.desc()).limit(5).all()
    
    # Get test names for recent tests
    test_data = {}
    for result in recent_tests:
        test = Test.query.get(result.test_id)
        test_data[result.test_id] = test.name if test else 'Unknown Test'
    
    # Calculate subject-wise performance
    subject_performance = {}
    subject_names = {}  # Store subject names by ID
    
    for result in results:
        subjects = json.loads(result.subjects_attempted)
        for subject_id in subjects:
            # Get subject name
            subject = Subject.query.get(subject_id)
            if subject:
                subject_names[subject_id] = subject.name
                
                if subject_id not in subject_performance:
                    subject_performance[subject_id] = {'total': 0, 'correct': 0, 'name': subject.name}
                subject_performance[subject_id]['total'] += 1
                # This is simplified - you'd need to calculate actual correct answers per subject
    
    return render_template('dashboard.html', 
                         total_tests=total_tests,
                         avg_percentage=avg_percentage,
                         total_time=total_time,
                         recent_tests=recent_tests,
                         test_data=test_data,
                         subject_performance=subject_performance)

@app.route('/tests')
@login_required
def tests():
    available_tests = Test.query.filter_by(is_active=True).all()
    
    # Get test results for statistics
    test_results = TestResult.query.all()
    
    # Get user's test results for completion status
    user_test_results = TestResult.query.filter_by(user_id=session['user_id']).all()
    user_completed_tests = {result.test_id for result in user_test_results}
    
    # Calculate average scores and attempt counts for each test
    test_stats = {}
    for test in available_tests:
        test_results_for_test = [r for r in test_results if r.test_id == test.id]
        attempt_count = len(test_results_for_test)
        
        if attempt_count > 0:
            avg_score = sum(r.percentage for r in test_results_for_test) / attempt_count
            test_stats[test.id] = {
                'attempt_count': attempt_count,
                'avg_score': avg_score,
                'user_completed': test.id in user_completed_tests
            }
        else:
            test_stats[test.id] = {
                'attempt_count': 0,
                'avg_score': 0,
                'user_completed': False
            }
    
    return render_template('tests.html', 
                         tests=available_tests,
                         test_stats=test_stats,
                         test_results=test_results)

@app.route('/test/<int:test_id>')
@login_required
def test_subjects(test_id):
    test = Test.query.get_or_404(test_id)
    subjects = Subject.query.filter_by(test_id=test_id).all()
    return render_template('test_subjects.html', test=test, subjects=subjects)

@app.route('/take_test/<int:test_id>', methods=['POST'])
@login_required

def take_test(test_id):
    # Use CSRFProtect form instead of AdminActionForm
      # Create a basic form for CSRF protection
    
    selected_subjects = request.form.getlist('subjects')
    
    if not selected_subjects:
        flash('Please select at least one subject.', 'error')
        return redirect(url_for('test_subjects', test_id=test_id))
    
    # Get questions from selected subjects, randomize and limit
    total_questions = sum(Subject.query.get(int(sid)).total_questions for sid in selected_subjects)
    questions = Question.query.filter(
        Question.test_id == test_id,
        Question.subject_id.in_(selected_subjects)
    ).order_by(db.func.random()).limit(total_questions).all()
    
    if not questions:
        flash('No questions available for selected subjects.', 'error')
        return redirect(url_for('test_subjects', test_id=test_id))
    
    test = Test.query.get(test_id)
    session['current_test'] = {
        'test_id': test_id,
        'subjects': selected_subjects,
        'questions': [q.id for q in questions],
        'start_time': datetime.utcnow().isoformat(),
        'time_limit': test.time_limit
    }
    
    return render_template('test_interface.html', 
                         test=test, 
                         questions=questions, 
                         time_limit=test.time_limit,
                         )  
csrf.exempt(take_test)
# Pass the form to the template
@app.route('/submit_test', methods=['POST'])
@login_required
def submit_test():
    if 'current_test' not in session:
        flash('No active test found.', 'error')
        return redirect(url_for('tests'))
    
    test_data = session['current_test']
    user_id = session['user_id']
    
    # Calculate time taken
    start_time = datetime.fromisoformat(test_data['start_time'])
    time_taken = (datetime.utcnow() - start_time).total_seconds() / 60  # in minutes
    
    # Get user answers
    user_answers = {}
    for key, value in request.form.items():
        if key.startswith('question_'):
            question_id = int(key.split('_')[1])
            user_answers[question_id] = value
    
    # Calculate results
    questions = Question.query.filter(Question.id.in_(test_data['questions'])).all()
    correct_answers = 0
    total_questions = len(questions)
    
    # Create test result
    test_result = TestResult(
        user_id=user_id,
        test_id=test_data['test_id'],
        total_questions=total_questions,
        correct_answers=0,  # Will be updated below
        incorrect_answers=0,  # Will be updated below
        time_taken=int(time_taken),
        percentage=0,  # Will be updated below
        subjects_attempted=json.dumps(test_data['subjects'])
    )
    db.session.add(test_result)
    db.session.flush()  # To get the ID
    
    # Check answers and create user answer records
    for question in questions:
        user_answer = user_answers.get(question.id)
        is_correct = user_answer == question.correct_answer
        
        if is_correct:
            correct_answers += 1
        
        answer_record = UserAnswer(
            test_result_id=test_result.id,
            question_id=question.id,
            user_answer=user_answer,
            is_correct=is_correct
        )
        db.session.add(answer_record)
    
    # Update test result
    test_result.correct_answers = correct_answers
    test_result.incorrect_answers = total_questions - correct_answers
    test_result.percentage = (correct_answers / total_questions) * 100 if total_questions > 0 else 0
    
    db.session.commit()
    
    session.pop('current_test', None)
    return redirect(url_for('test_results', result_id=test_result.id))

@app.route('/test_results/<int:result_id>')
@login_required
def test_results(result_id):
    result = TestResult.query.get_or_404(result_id)
    
    if result.user_id != session['user_id']:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get test information
    test = Test.query.get(result.test_id)
    
    # Prepare subject performance data
    subject_performance = {}
    subjects_attempted = json.loads(result.subjects_attempted)
    
    for subject_id in subjects_attempted:
        # Get subject name
        subject = Subject.query.get(subject_id)
        if subject:
            # Count correct answers for this subject
            correct_count = UserAnswer.query.join(Question).filter(
                UserAnswer.test_result_id == result_id,
                Question.subject_id == subject_id,
                UserAnswer.is_correct == True
            ).count()
            
            # Count total questions for this subject
            total_count = UserAnswer.query.join(Question).filter(
                UserAnswer.test_result_id == result_id,
                Question.subject_id == subject_id
            ).count()
            
            percentage = (correct_count / total_count * 100) if total_count > 0 else 0
            
            subject_performance[subject.name] = {
                'correct': correct_count,
                'total': total_count,
                'percentage': percentage
            }
    
    # Get best and worst subjects for insights
    best_subject = None
    worst_subject = None
    
    if subject_performance:
        best_subject = max(subject_performance.items(), key=lambda x: x[1]['percentage'])
        worst_subject = min(subject_performance.items(), key=lambda x: x[1]['percentage'])
    
    return render_template('test_results.html', 
                         result=result, 
                         test=test,
                         subject_performance=subject_performance,
                         best_subject=best_subject,
                         worst_subject=worst_subject)

@app.route('/review_test/<int:result_id>')
@login_required
def review_test(result_id):
    result = TestResult.query.get_or_404(result_id)

    # Security check
    if result.user_id != session['user_id']:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))

    test = Test.query.get(result.test_id)
    user_answers = UserAnswer.query.filter_by(test_result_id=result_id).all()
    questions_data = []

    for ua in user_answers:
        question = Question.query.get(ua.question_id)
        if not question:
            continue  # Skip if missing

        # Map A/B/C/D to actual text
        options = {
            'A': question.option_a,
            'B': question.option_b,
            'C': question.option_c,
            'D': question.option_d
        }

        questions_data.append({
            'question_text': question.question_text,
            'options': options,
            'correct_answer': question.correct_answer,
            'correct_answer_text': options.get(question.correct_answer, ''),
            'user_answer': ua.user_answer,
            'user_answer_text': options.get(ua.user_answer, ''),
            'is_correct': ua.is_correct
        })

    return render_template(
        'review_test.html',
        result=result,
        test=test,
        questions_data=questions_data
    )

# In-memory conversation storage (you can also store per user in a DB)

chat_history = [
    {"role": "model", "parts": [
        "You are an AI assistant built for the Entry Test Preparation platform. "
        "Your job is to clearly explain concepts, solve doubts, and guide students preparing for entry tests. "
        "If someone asks 'who are you' or similar, say: 'I am an AI assistant for Entry Test Preparation, here to help clear your doubts.'"
    ]}
]


@app.route('/ask_ai', methods=['POST'])
@csrf.exempt  # disable CSRF for this route
# Keep chat history in memory (per session or globally)


def ask_ai():

    global chat_history
    model = genai.GenerativeModel("gemini-2.0-flash")

    try:
        data = request.get_json(force=True)  # Force JSON parsing
        user_question = data.get("user_question", "").strip()
        if not user_question:
            return jsonify({"success": False, "error": "No question provided"}), 400

        # Add user's message to history
        chat_history.append({"role": "user", "parts": [user_question]})

        # Send full history
        response = model.generate_content(chat_history)
        ai_answer = response.text.strip()

        # Add AI's response to history
        chat_history.append({"role": "model", "parts": [ai_answer]})

        return jsonify({"success": True, "response": ai_answer})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500



@app.route('/progress')
@login_required
def progress():
    user_id = session['user_id']
    results = TestResult.query.filter_by(user_id=user_id).order_by(TestResult.completed_at.desc()).all()

    test_data = {}
    for result in results:
        test = Test.query.get(result.test_id)
        test_data[result.test_id] = test.name if test else 'Unknown Test'

    progress_data = []
    total_time = sum(r.time_taken for r in results)
    avg_score = (sum(r.percentage for r in results) / len(results)) if results else 0

    for result in results:
        progress_data.append({
            'date': result.completed_at.strftime('%Y-%m-%d'),
            'percentage': result.percentage,
            'test_name': test_data.get(result.test_id, 'Unknown Test')
        })

    return render_template(
        'progress.html',
        results=results,
        progress_data=progress_data,
        test_data=test_data,
        total_time=total_time,
        avg_score=avg_score
    )

@app.route('/preparation')
@login_required
def preparation():
    notes = StudyMaterial.query.filter_by(material_type='notes').all()
    formulas = StudyMaterial.query.filter_by(material_type='formulas').all()
    pdfs = StudyMaterial.query.filter_by(material_type='pdf').all()

    def attach_subject_name(materials):
        for m in materials:
            if m.subject_id:
                subject = Subject.query.get(m.subject_id)
                m.subject_name = subject.name if subject else "General"
            else:
                m.subject_name = "General"

    attach_subject_name(notes)
    attach_subject_name(formulas)
    attach_subject_name(pdfs)

    return render_template(
        'preparation.html',
        notes=notes,
        formulas=formulas,
        pdfs=pdfs
    )

@app.route('/material/<int:material_id>')
@login_required
def view_material(material_id):
    material = StudyMaterial.query.get_or_404(material_id)

    # Get subject name
    if material.subject_id:
        subject = Subject.query.get(material.subject_id)
        material.subject_name = subject.name if subject else "General"
    else:
        material.subject_name = "General"

    # Verify file exists
    file_path = os.path.join(MATERIALS_FOLDER, material.file_path)
    if not os.path.exists(file_path):
        flash('Material file not found.', 'error')
        return redirect(url_for('preparation'))

    return render_template('view_material.html', material=material)

@app.route('/materials/<path:filename>')
@login_required
def serve_material(filename):
    try:
        return send_from_directory(MATERIALS_FOLDER, filename)
    except Exception as e:
        flash('Error accessing material file.', 'error')
        return redirect(url_for('preparation'))
# Define LoginForm if not already present
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    csrf_token = HiddenField()
# Admin Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        user = User.query.filter_by(email=email, is_admin=True).first()
        
        if not user:
            app.logger.warning(f"Failed admin login attempt for email: {email}")
            flash('Admin account not found.', 'error')
            return render_template('admin_login.html', form=form)
        
        if not user.is_active:
            flash('Admin account is deactivated.', 'error')
            return render_template('admin_login.html', form=form)
        
        if check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['is_admin'] = True
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid password.', 'error')
            return render_template('admin_login.html', form=form)
    
    return render_template('admin_login.html', form=form)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'], endpoint='admin_delete_user')
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin_users'))
    
    user = User.query.get_or_404(user_id)
    if user.is_admin and User.query.filter_by(is_admin=True, is_active=True).count() <= 1:
        flash('Cannot delete the last active admin.', 'error')
        return redirect(url_for('admin_users'))
    
    try:
        test_result_ids = [tr.id for tr in TestResult.query.filter_by(user_id=user_id).all()]
        if test_result_ids:
            UserAnswer.query.filter(UserAnswer.test_result_id.in_(test_result_ids)).delete()
        TestResult.query.filter_by(user_id=user_id).delete()
        OTP.query.filter_by(email=user.email).delete()
       
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the user.', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/toggle_admin/<int:user_id>', methods=['POST'])
@admin_required
def toggle_admin(user_id):
    if user_id == session['user_id']:
        flash('You cannot change your own admin status.', 'error')
        return redirect(url_for('admin_users'))
    
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    status = "promoted to admin" if user.is_admin else "demoted to regular user"
    db.session.commit()
    
    flash(f'User {user.username} has been {status}.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Get statistics
    total_users = User.query.filter_by(is_admin=False).count()
    total_tests = Test.query.count()
    total_questions = Question.query.count()
    total_test_attempts = TestResult.query.count()
    
    # Recent activity
    recent_users = User.query.filter_by(is_admin=False).order_by(User.created_at.desc()).limit(5).all()
    recent_results = TestResult.query.order_by(TestResult.completed_at.desc()).limit(5).all()
    
    # Map test_id to test name and user_id to username
    test_names = {test.id: test.name for test in Test.query.all()}
    user_names = {user.id: user.username for user in User.query.all()}

    return render_template(
        'admin_dashboard.html',
        total_users=total_users,
        total_tests=total_tests,
        total_questions=total_questions,
        total_test_attempts=total_test_attempts,
        recent_users=recent_users,
        recent_results=recent_results,
        test_names=test_names,
        user_names=user_names,
        now=datetime.now()
    )

@app.route('/admin/users')
@admin_required
def admin_users():
    form = AdminActionForm()
    page = request.args.get('page', 1, type=int)
    per_page = 20
    users = User.query.filter_by(is_admin=False).paginate(page=page, per_page=per_page)
    return render_template('admin_users.html', users=users.items, form=form, pagination=users)

@app.route('/admin/toggle_user/<int:user_id>', methods=['POST'])
@admin_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    
    status = "activated" if user.is_active else "deactivated"
    flash(f'User {user.username} has been {status}.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/admin/questions')
@admin_required
def admin_questions():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    questions = Question.query.order_by(Question.created_at.desc()).paginate(page=page, per_page=per_page)
    
    # Get test names for all questions
    test_data = {test.id: test.name for test in Test.query.all()}
    
    # Get subject names for all questions
    subject_data = {subject.id: subject.name for subject in Subject.query.all()}
    
    return render_template('admin_questions.html', 
                         questions=questions.items,
                         pagination=questions,
                         test_data=test_data,
                         subject_data=subject_data)

@app.route('/admin/add_question', methods=['GET', 'POST'])
@admin_required
def add_question():
    tests = Test.query.all()
    form = AdminActionForm()
    
    if request.method == 'POST':
        question_text = request.form['question_text']
        option_a = request.form['option_a']
        option_b = request.form['option_b']
        option_c = request.form['option_c']
        option_d = request.form['option_d']
        correct_answer = request.form['correct_answer']
        test_id = int(request.form['test_id'])
        subject_id = int(request.form['subject_id'])
        chapter_id = int(request.form['chapter_id'])
        
        question = Question(
            question_text=question_text,
            option_a=option_a,
            option_b=option_b,
            option_c=option_c,
            option_d=option_d,
            correct_answer=correct_answer,
            test_id=test_id,
            subject_id=subject_id,
            chapter_id=chapter_id
        )
        handle_db_operation(
            lambda: db.session.add(question),
            'Question added successfully!',
            'An error occurred while adding the question.'
        )
        return redirect(url_for('admin_questions'))
    
    return render_template('add_question.html', tests=tests,form=form)

@app.route('/admin/edit_question/<int:question_id>', methods=['GET', 'POST'])
@admin_required
def edit_question(question_id):
    form = AdminActionForm()
    question = Question.query.get_or_404(question_id)
    tests = Test.query.all()
    subjects = Subject.query.all()
    chapters = Chapter.query.all()

    if request.method == 'POST':
        question.question_text = request.form['question_text']
        question.option_a = request.form['option_a']
        question.option_b = request.form['option_b']
        question.option_c = request.form['option_c']
        question.option_d = request.form['option_d']
        question.correct_answer = request.form['correct_answer']
        question.test_id = int(request.form['test_id'])
        question.subject_id = int(request.form['subject_id'])
        question.chapter_id = int(request.form['chapter_id'])

        handle_db_operation(
            lambda: db.session.commit(),
            'Question updated successfully!',
            'An error occurred while updating the question.'
        )
        return redirect(url_for('admin_questions'))

    return render_template(
        'edit_question.html',
        question=question,
        tests=tests,
        subjects=subjects,
        chapters=chapters,
        form=form
    )


@app.route('/admin/get_subjects/<int:test_id>')
@admin_required
def get_subjects(test_id):
    subjects = Subject.query.filter_by(test_id=test_id).all()
    return jsonify([{'id': s.id, 'name': s.name} for s in subjects])

@app.route('/admin/get_chapters/<int:subject_id>')
@admin_required
def get_chapters(subject_id):
    chapters = Chapter.query.filter_by(subject_id=subject_id).all()
    return jsonify([{'id': c.id, 'name': c.name} for c in chapters])

@app.route('/admin/tests')
@admin_required
def admin_tests():
    form = AdminActionForm()
    tests = Test.query.all()
    return render_template('admin_tests.html', tests=tests, form=form)

@app.route('/admin/add_test', methods=['GET', 'POST'], endpoint='add_test')
@admin_required
def add_test():
    form = AddTestForm()
    if form.validate_on_submit():
        test = Test(
            name=form.name.data,
            description=form.description.data,
            total_marks=form.total_marks.data,
            total_questions=form.total_questions.data,
            time_limit=form.time_limit.data,
            is_active=form.is_active.data
        )
        handle_db_operation(
            lambda: db.session.add(test),
            'Test added successfully.',
            'An error occurred while adding the test.'
        )
        return redirect(url_for('admin_tests'))
    return render_template('add_test.html', form=form)

@app.route('/admin/subjects/<int:test_id>', methods=['GET', 'POST'])
@admin_required
def admin_subjects(test_id):
    test = Test.query.get_or_404(test_id)
    subjects = Subject.query.filter_by(test_id=test_id).all()
    form = AddSubjectForm()  # Assuming a form is passed for other functionality
    app.logger.debug(f"Rendering admin_subjects for test_id={test_id}, subjects={len(subjects)}")
    return render_template('admin_subjects.html', test=test, subjects=subjects, form=form)

@app.route('/admin/add_subject/<int:test_id>', methods=['GET', 'POST'], endpoint='add_subject')
@admin_required
def add_subject(test_id):
    test = Test.query.get_or_404(test_id)
    form = AddSubjectForm()
    if form.validate_on_submit():
        subject = Subject(
            name=form.name.data,
            test_id=test_id,
            total_questions=form.total_questions.data,
            marks_per_question=form.marks_per_question.data
        )
        handle_db_operation(
            lambda: db.session.add(subject),
            'Subject added successfully.',
            'An error occurred while adding the subject.'
        )
        return redirect(url_for('admin_subjects', test_id=test_id))
    return render_template('add_subject.html', form=form, test=test)

@app.route('/admin/edit_subject/<int:test_id>/<int:subject_id>', methods=['GET', 'POST'])
@admin_required
def edit_subject(test_id, subject_id):
    test = Test.query.get_or_404(test_id)
    subject = Subject.query.get_or_404(subject_id)
    if subject.test_id != test_id:
        flash('Subject does not belong to this test.', 'error')
        return redirect(url_for('admin_subjects', test_id=test_id))
    
    form = AddSubjectForm(obj=subject)  # Pre-populate form with subject data
    
    if request.method == 'POST':
        app.logger.debug(f"Form data: {form.data}")
        if form.validate_on_submit():
            # Check for duplicate subject name (excluding current subject)
            existing_subject = Subject.query.filter_by(test_id=test_id, name=form.name.data).filter(Subject.id != subject_id).first()
            if existing_subject:
                flash('A subject with this name already exists for this test.', 'error')
                return render_template('edit_subject.html', form=form, test=test, subject=subject)
            
            subject.name = form.name.data
            subject.total_questions = form.total_questions.data
            subject.marks_per_question = form.marks_per_question.data
            handle_db_operation(
                                lambda: db.session.commit(),
                                'updated successfully.',
                                'An error occurred while updating the subject.'
)

            return redirect(url_for('admin_subjects', test_id=test_id))
        else:
            app.logger.debug(f"Form validation errors: {form.errors}")
            flash('Please correct the errors in the form.', 'error')
    
    return render_template('edit_subject.html', form=form, test=test, subject=subject)

@app.route('/admin/delete_subject/<int:test_id>/<int:subject_id>', methods=['POST'])
@admin_required
def delete_subject(test_id, subject_id):
    test = Test.query.get_or_404(test_id)
    subject = Subject.query.get_or_404(subject_id)
    
    if subject.test_id != test_id:
        flash('Subject does not belong to this test.', 'error')
        return redirect(url_for('admin_subjects', test_id=test_id))
    
    form = AdminActionForm()
    if not form.validate_on_submit():
        app.logger.debug(f"CSRF validation failed: {form.errors}")
        flash('Invalid CSRF token.', 'error')
        return redirect(url_for('admin_subjects', test_id=test_id))
    
    handle_db_operation(
        lambda: db.session.delete(subject),
        'Subject deleted successfully.',
        f'An error occurred while deleting the subject: '
    )
    return redirect(url_for('admin_subjects', test_id=test_id))

@app.route('/admin/chapters/<int:subject_id>', endpoint='admin_chapters')
@admin_required
def admin_chapters(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    chapters = Chapter.query.filter_by(subject_id=subject_id).all()
    form = AdminActionForm()
    return render_template('admin_chapters.html', subject=subject, chapters=chapters, form=form)
@app.route('/admin/add_chapter/<int:test_id>/<int:subject_id>', methods=['GET', 'POST'])
@admin_required
def add_chapter(test_id, subject_id):
    test = Test.query.get_or_404(test_id)
    subject = Subject.query.get_or_404(subject_id)
    
    if subject.test_id != test_id:
        flash('Subject does not belong to this test.', 'error')
        return redirect(url_for('admin_subjects', test_id=test_id))
    
    form = AddChapterForm()
    
    if request.method == 'POST':
        app.logger.debug(f"Form data: {form.data}")
        if form.validate_on_submit():
            # Check for duplicate chapter name for this subject
            if Chapter.query.filter_by(subject_id=subject_id, name=form.name.data).first():
                flash('A chapter with this name already exists for this subject.', 'error')
                return render_template('add_chapter.html', form=form, test=test, subject=subject)
            
            chapter = Chapter(
                name=form.name.data,
                subject_id=subject_id
            )
            handle_db_operation(
                lambda: db.session.add(chapter),
                'Chapter added successfully.',
                f'An error occurred while adding the chapter:'
            )
            return redirect(url_for('admin_subjects', test_id=test_id))
        else:
            app.logger.debug(f"Form validation errors: {form.errors}")
            flash('Please correct the errors in the form.', 'error')
    
    return render_template('add_chapter.html', form=form, test=test, subject=subject)

@app.route('/admin/edit_chapter/<int:test_id>/<int:subject_id>/<int:chapter_id>', methods=['GET', 'POST'])
@admin_required
def edit_chapter(test_id, subject_id, chapter_id):
    test = Test.query.get_or_404(test_id)
    subject = Subject.query.get_or_404(subject_id)
    chapter = Chapter.query.get_or_404(chapter_id)
    if subject.test_id != test_id or chapter.subject_id != subject_id:
        flash('Invalid test or subject.', 'error')
        return redirect(url_for('admin_subjects', test_id=test_id))
    form = AddChapterForm(obj=chapter)
    if form.validate_on_submit():
        if Chapter.query.filter_by(subject_id=subject_id, name=form.name.data).filter(Chapter.id != chapter_id).first():
            flash('A chapter with this name already exists.', 'error')
            return render_template('edit_chapter.html', form=form, test=test, subject=subject, chapter=chapter)
        chapter.name = form.name.data
        handle_db_operation(
            lambda: db.session.commit(),
            'Chapter updated successfully.',
            f'An error occurred while updating the chapter: '
        )
        return redirect(url_for('admin_subjects', test_id=test_id))
    return render_template('edit_chapter.html', form=form, test=test, subject=subject, chapter=chapter)

@app.route('/admin/delete_chapter/<int:chapter_id>', methods=['POST'], endpoint='delete_chapter')
@admin_required
def delete_chapter(chapter_id):
    form = AdminActionForm()
    if not form.validate_on_submit():
        flash('Invalid CSRF token.', 'error')
        return redirect(url_for('admin_subjects', test_id=Subject.query.get(Chapter.query.get(chapter_id).subject_id).test_id))
    chapter = Chapter.query.get_or_404(chapter_id)
    subject_id = chapter.subject_id
    handle_db_operation(
        lambda: db.session.delete(chapter),
        'Chapter deleted successfully.',
        'An error occurred while deleting the chapter.'
    )
    return redirect(url_for('admin_chapters', subject_id=subject_id))

@app.route('/admin/edit_test/<int:test_id>', methods=['GET', 'POST'], endpoint='edit_test')
@admin_required
def edit_test(test_id):
    test = Test.query.get_or_404(test_id)
    form = AddTestForm(obj=test)
    if form.validate_on_submit():
        test.name = form.name.data
        test.description = form.description.data
        test.total_marks = form.total_marks.data
        test.total_questions = form.total_questions.data
        test.time_limit = form.time_limit.data
        test.is_active = form.is_active.data
        handle_db_operation(
            lambda: None,
            'Test updated successfully.',
            'An error occurred while updating the test.'
        )
        return redirect(url_for('admin_tests'))
    return render_template('edit_test.html', form=form, test=test)

@app.route('/admin/delete_test/<int:test_id>', methods=['POST'], endpoint='delete_test')
@admin_required
def delete_test(test_id):
    form = AdminActionForm()
    if not form.validate_on_submit():
        flash('Invalid CSRF token.', 'error')
        return redirect(url_for('admin_tests'))
    test = Test.query.get_or_404(test_id)
    handle_db_operation(
        lambda: db.session.delete(test),
        'Test deleted successfully.',
        'An error occurred while deleting the test.'
    )
    return redirect(url_for('admin_tests'))

@app.route('/admin/delete_question/<int:question_id>')
@admin_required
def delete_question(question_id):
    question = Question.query.get_or_404(question_id)
    handle_db_operation(
        lambda: db.session.delete(question),
        'Question deleted successfully!',
        'An error occurred while deleting the question.'
    )
    return redirect(url_for('admin_questions'))

@app.route('/admin/materials')
@admin_required
def admin_materials():
    # Fetch all materials
    materials = StudyMaterial.query.all()
    
    # Add subject_name to each material
    for material in materials:
        if material.subject_id:
            subject = Subject.query.get(material.subject_id)
            material.subject_name = subject.name if subject else "General"
        else:
            material.subject_name = "General"
    
    return render_template('admin_materials.html', materials=materials)

@app.route('/admin/delete_material/<int:material_id>')
@admin_required
def delete_material(material_id):
    material = StudyMaterial.query.get_or_404(material_id)
    try:
        os.remove(os.path.join(MATERIALS_FOLDER, material.file_path))
    except OSError:
        pass  # File might already be deleted
    handle_db_operation(
        lambda: db.session.delete(material),
        'Material deleted successfully.',
        'An error occurred while deleting the material.'
    )
    return redirect(url_for('admin_materials'))

@app.route('/admin/add_material', methods=['GET', 'POST'])
@admin_required
def add_material():
    subjects = Subject.query.all()
    
    if request.method == 'POST':
        title = request.form.get('title')
        material_type = request.form.get('material_type')
        subject_id = request.form.get('subject_id') or None
        
        # Validate inputs
        if not title or not material_type:
            flash('Title and material type are required.', 'error')
            return render_template('add_material.html', subjects=subjects)
        
        if material_type not in ['notes', 'formulas', 'pdf']:
            flash('Invalid material type.', 'error')
            return render_template('add_material.html', subjects=subjects)
        
        # Handle file upload
        if 'file' not in request.files:
            flash('No file uploaded.', 'error')
            return render_template('add_material.html', subjects=subjects)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'error')
            return render_template('add_material.html', subjects=subjects)
        
        if file:
            # Validate file extension
            allowed_extensions = {'txt', 'pdf', 'doc', 'docx'}
            if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
                flash('Invalid file type. Allowed types: txt, pdf, doc, docx.', 'error')
                return render_template('add_material.html', subjects=subjects)
            
            # Save file
            filename = secure_filename(file.filename)
            file_path = os.path.join(MATERIALS_FOLDER, filename)
            try:
                file.save(file_path)
            except Exception as e:
                flash(f'Error saving file: {str(e)}', 'error')
                return render_template('add_material.html', subjects=subjects)
            
            # Save to database
            material = StudyMaterial(
                title=title,
                material_type=material_type,
                file_path=filename,
                subject_id=subject_id if subject_id else None
            )
            handle_db_operation(
                lambda: db.session.add(material),
                'Study material added successfully!',
                'An error occurred while adding the study material.'
            )
            return redirect(url_for('admin_materials'))
    
    return render_template('add_material.html', subjects=subjects)

@app.route('/admin/analytics')
@admin_required
def admin_analytics():
    # Get statistics
    total_users = User.query.filter_by(is_admin=False).count()
    active_users = User.query.filter_by(is_admin=False, is_active=True).count()
    total_tests = Test.query.count()
    total_questions = Question.query.count()
    total_attempts = TestResult.query.count()

    # Get all test results for metrics
    all_results = TestResult.query.all()

    if all_results:
        scores = [res.percentage for res in all_results]
        times = [res.time_taken for res in all_results if res.time_taken]  # Assuming `time_taken` exists

        avg_score = round(sum(scores) / len(scores), 2)
        highest_score = round(max(scores), 2)
        avg_time = round(sum(times) / len(times), 2) if times else 0
    else:
        avg_score = 0
        highest_score = 0
        avg_time = 0

    # Monthly user registrations
    monthly_registrations = db.session.query(
        db.func.strftime('%Y-%m', User.created_at).label('month'),
        db.func.count(User.id).label('count')
    ).filter(User.is_admin == False).group_by('month').all()

    # Test popularity
    test_popularity = db.session.query(
        Test.name,
        db.func.count(TestResult.id).label('attempts')
    ).join(TestResult).group_by(Test.id, Test.name).all()

    # Average scores by test
    avg_scores = db.session.query(
        Test.name,
        db.func.avg(TestResult.percentage).label('avg_score')
    ).join(TestResult).group_by(Test.id, Test.name).all()

    # Score distribution for chart
    score_ranges = {'0-20': 0, '21-40': 0, '41-60': 0, '61-80': 0, '81-100': 0}
    for result in all_results:
        if result.percentage <= 20:
            score_ranges['0-20'] += 1
        elif result.percentage <= 40:
            score_ranges['21-40'] += 1
        elif result.percentage <= 60:
            score_ranges['41-60'] += 1
        elif result.percentage <= 80:
            score_ranges['61-80'] += 1
        else:
            score_ranges['81-100'] += 1

    # Prepare chart data
    score_distribution_chart = {
        "type": "bar",
        "data": {
            "labels": list(score_ranges.keys()),
            "datasets": [{
                "label": "Score Distribution",
                "data": list(score_ranges.values()),
                "backgroundColor": ["#36A2EB", "#FF6384", "#FFCE56", "#4BC0C0", "#9966FF"],
            }]
        },
        "options": {
            "scales": {
                "y": {"beginAtZero": True}
            }
        }
    }

    return render_template(
        'admin_analytics.html',
        total_users=total_users,
        active_users=active_users,
        total_tests=total_tests,
        total_questions=total_questions,
        total_attempts=total_attempts,
        avg_score=avg_score,
        highest_score=highest_score,
        avg_time=avg_time,
        monthly_registrations=monthly_registrations,
        test_popularity=test_popularity,
        avg_scores=avg_scores,
        score_distribution_chart=score_distribution_chart
    )

@app.route('/admin/user_details/<int:user_id>')
@admin_required
def user_details(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('Cannot view admin user details.', 'error')
        return redirect(url_for('admin_users'))
    
    test_results = TestResult.query.filter_by(user_id=user_id).order_by(TestResult.completed_at.desc()).all()
    
    # Calculate user statistics
    total_tests = len(test_results)
    avg_percentage = sum(r.percentage for r in test_results) / total_tests if total_tests > 0 else 0
    total_time = sum(r.time_taken for r in test_results)
    best_score = max((r.percentage for r in test_results), default=0)
    
    return render_template('user_details.html',
                         user=user,
                         test_results=test_results,
                         total_tests=total_tests,
                         avg_percentage=avg_percentage,
                         total_time=total_time,
                         best_score=best_score)

@app.route('/admin/test_analytics/<int:test_id>')
@admin_required
def test_analytics(test_id):
    test = Test.query.get_or_404(test_id)
    results = TestResult.query.filter_by(test_id=test_id).all()
    
    if not results:
        flash('No results found for this test.', 'info')
        return redirect(url_for('admin_tests'))
    
    # Calculate statistics
    total_attempts = len(results)
    avg_score = sum(r.percentage for r in results) / total_attempts
    highest_score = max(r.percentage for r in results)
    lowest_score = min(r.percentage for r in results)
    avg_time = sum(r.time_taken for r in results) / total_attempts
    
    # Score distribution
    score_ranges = {'0-20': 0, '21-40': 0, '41-60': 0, '61-80': 0, '81-100': 0}
    for result in results:
        if result.percentage <= 20:
            score_ranges['0-20'] += 1
        elif result.percentage <= 40:
            score_ranges['21-40'] += 1
        elif result.percentage <= 60:
            score_ranges['41-60'] += 1
        elif result.percentage <= 80:
            score_ranges['61-80'] += 1
        else:
            score_ranges['81-100'] += 1
    
    return render_template('test_analytics.html',
                         test=test,
                         results=results,
                         total_attempts=total_attempts,
                         avg_score=avg_score,
                         highest_score=highest_score,
                         lowest_score=lowest_score,
                         avg_time=avg_time,
                         score_ranges=score_ranges)

@app.route('/api/chat', methods=['POST'])
@login_required
def chat_with_ai():
    data = request.get_json()
    message = data.get('message', '')
    context = data.get('context', '')
    
    try:
        model = genai.GenerativeModel('gemini-pro')
        
        if context:
            prompt = f"""
            Context: {context}
            
            Student's question: {message}
            
            Please provide a helpful explanation or answer to the student's question.
            """
        else:
            prompt = f"Student's question: {message}\n\nPlease provide a helpful answer."
        
        response = model.generate_content(prompt)
        formatted_response = format_gemini_response(response.text)
        
        return jsonify({
            'success': True,
            'response': formatted_response
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'AI service temporarily unavailable: {str(e)}'
        })

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    data = request.get_json()
    email = data.get('email')
    purpose = data.get('purpose')
    
    if not email or not purpose:
        return jsonify({'success': False, 'error': 'Email and purpose required'})
    
    # Mark old OTPs as used
    old_otps = OTP.query.filter_by(email=email, purpose=purpose, is_used=False).all()
    for otp in old_otps:
        otp.is_used = True
    
    # Generate new OTP
    otp_code = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    new_otp = OTP(email=email, otp_code=otp_code, expires_at=expires_at, purpose=purpose)
    db.session.add(new_otp)
    db.session.commit()
    
    # Send email
    if purpose == 'registration':
        subject = "Email Verification - Entry Test Preparation (Resent)"
        body = f"Your new OTP for email verification is: {otp_code}\nThis OTP will expire in 10 minutes."
    else:
        subject = "Password Reset - Entry Test Preparation (Resent)"
        body = f"Your new OTP for password reset is: {otp_code}\nThis OTP will expire in 10 minutes."
    
    if send_email(email, subject, body):
        return jsonify({'success': True, 'message': 'New OTP sent successfully'})
    else:
        return jsonify({'success': False, 'error': 'Failed to send OTP'})

@app.route('/check_session')
@login_required
def check_session():
    return jsonify({'valid': True, 'user_id': session.get('user_id')})

@app.route('/api/progress_data')
@login_required
def progress_data():
    user_id = session['user_id']
    results = TestResult.query.filter_by(user_id=user_id).order_by(TestResult.completed_at.asc()).all()
    
    # Prepare data for charts
    progress_chart = []
    subject_performance = {}
    monthly_performance = {}
    
    for result in results:
        # Progress over time
        progress_chart.append({
            'date': result.completed_at.strftime('%Y-%m-%d'),
            'percentage': result.percentage,
            'test_name': Test.query.get(result.test_id).name
        })
        
        # Monthly performance
        month = result.completed_at.strftime('%Y-%m')
        if month not in monthly_performance:
            monthly_performance[month] = {'total': 0, 'sum': 0}
        monthly_performance[month]['total'] += 1
        monthly_performance[month]['sum'] += result.percentage
        
        # Subject-wise performance (simplified)
        subjects = json.loads(result.subjects_attempted)
        for subject_id in subjects:
            subject = Subject.query.get(int(subject_id))
            if subject:
                if subject.name not in subject_performance:
                    subject_performance[subject.name] = {'total': 0, 'sum': 0}
                subject_performance[subject.name]['total'] += 1
                subject_performance[subject.name]['sum'] += result.percentage
    
    # Calculate averages
    for month in monthly_performance:
        monthly_performance[month]['average'] = monthly_performance[month]['sum'] / monthly_performance[month]['total']
    
    for subject in subject_performance:
        subject_performance[subject]['average'] = subject_performance[subject]['sum'] / subject_performance[subject]['total']
    
    return jsonify({
        'progress_chart': progress_chart,
        'subject_performance': subject_performance,
        'monthly_performance': monthly_performance
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(email='admin@test.com').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@test.com',
                password_hash=generate_password_hash('admin123'),
                is_verified=True,
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created: admin@test.com / admin123")
        
        # Create sample data for testing
        if Test.query.count() == 0:
            # Create sample test
            sample_test = Test(
                name='Sample Entry Test',
                description='A sample test for demonstration',
                total_marks=100,
                total_questions=10,
                time_limit=60
            )
            db.session.add(sample_test)
            db.session.commit()
            
            # Create sample subjects
            math_subject = Subject(
                name='Mathematics',
                test_id=sample_test.id,
                total_questions=5,
                marks_per_question=10
            )
            
            physics_subject = Subject(
                name='Physics',
                test_id=sample_test.id,
                total_questions=5,
                marks_per_question=10
            )
            
            db.session.add(math_subject)
            db.session.add(physics_subject)
            db.session.commit()
            
            # Create sample chapters
            algebra_chapter = Chapter(name='Algebra', subject_id=math_subject.id)
            geometry_chapter = Chapter(name='Geometry', subject_id=math_subject.id)
            mechanics_chapter = Chapter(name='Mechanics', subject_id=physics_subject.id)
            
            db.session.add(algebra_chapter)
            db.session.add(geometry_chapter)
            db.session.add(mechanics_chapter)
            db.session.commit()
            
            # Create sample questions
            sample_questions = [
                Question(
                    question_text="What is 2 + 2?",
                    option_a="3",
                    option_b="4",
                    option_c="5",
                    option_d="6",
                    correct_answer="B",
                    test_id=sample_test.id,
                    subject_id=math_subject.id,
                    chapter_id=algebra_chapter.id
                ),
                Question(
                    question_text="What is the area of a circle with radius 5?",
                    option_a="25π",
                    option_b="10π",
                    option_c="15π",
                    option_d="20π",
                    correct_answer="A",
                    test_id=sample_test.id,
                    subject_id=math_subject.id,
                    chapter_id=geometry_chapter.id
                ),
                Question(
                    question_text="What is Newton's first law?",
                    option_a="F = ma",
                    option_b="Object at rest stays at rest",
                    option_c="Action equals reaction",
                    option_d="Energy cannot be destroyed",
                    correct_answer="B",
                    test_id=sample_test.id,
                    subject_id=physics_subject.id,
                    chapter_id=mechanics_chapter.id
                )
            ]
            
            for question in sample_questions:
                db.session.add(question)
            
            # Create sample study materials
            sample_materials = [
                StudyMaterial(
                    title="Basic Mathematics Notes",
                    material_type="notes",
                    file_path="materials/math_notes.pdf",
                    subject_id=math_subject.id
                ),
                StudyMaterial(
                    title="Physics Formulas",
                    material_type="formulas",
                    file_path="materials/physics_formulas.pdf",
                    subject_id=physics_subject.id
                ),
                StudyMaterial(
                    title="Complete Study Guide",
                    material_type="pdf",
                    file_path="materials/study_guide.pdf"
                )
            ]
            
            for material in sample_materials:
                db.session.add(material)
            
            db.session.commit()
            print("Sample data created successfully!")

    csrf = CSRFProtect(app)
    app.run(debug=True)