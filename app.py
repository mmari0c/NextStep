from flask import Flask, flash, redirect, render_template, request, redirect, session, url_for, make_response, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import datetime
from helpers import login_required
from google_auth_oauthlib.flow import Flow
from flask_session import Session
import sqlite3
import re
import os
from flask_mail import Mail, Message
from dotenv import load_dotenv
import os
# Configure the database connection
app = Flask(__name__)
app.secret_key = os.urandom(24)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Folder to store uploaded images
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Function to validate allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Configure the upload folder
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/upload_profile_picture', methods=['GET', 'POST'])
@login_required
def upload_profile_picture():
    if request.method == 'POST':
        # Check if a file is part of the POST request
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']

        # Check if the file is selected and valid
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{session['user_id']}_{filename}")
            file.save(filepath)

            # Save the file path in the database
            with sqlite3.connect('jobtrack.db') as connection:
                cursor = connection.cursor()
                cursor.execute(
                    "UPDATE info SET profile_picture = ? WHERE user_id = ?",
                    (filepath, session['user_id'])
                )
                connection.commit()

            flash('Profile picture uploaded successfully!')
            return redirect(url_for('profile'))

    return render_template('upload_profile_picture.html')

@app.route('/profile_with_image/<filename>')
def profile_with_image(filename):
    return render_template('profile.html', filename=filename)

# Set the path to the credentials JSON file
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # for local development only
GOOGLE_CLIENT_SECRET_FILE = 'credentials.json'
SCOPES = ['https://www.googleapis.com/auth/calendar', 'https://www.googleapis.com/auth/calendar.events']

flow = Flow.from_client_secrets_file(
    GOOGLE_CLIENT_SECRET_FILE,
    scopes=SCOPES,
    redirect_uri='http://localhost:5000/callback'
)

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/", methods = ['GET'])
@login_required
def home():
    connection = sqlite3.connect('jobtrack.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM applications WHERE user_id = ? AND app_status != 'Rejected' AND app_status != 'Offer' ORDER BY date DESC", (session["user_id"],))
    applications = cursor.fetchall()
    connection.close()
    
    return render_template("index.html", applications=applications)

@app.route('/login', methods = ['GET','POST']) 
def login():

    error = None
    if 'user_id' in session:
     session.clear()

    if request.method == 'POST':
        # Ensure username was submitted
        if not request.form.get("username"):
            error = "Please enter username"
            return render_template("login.html", error=error)

        # Ensure password was submitted
        elif not request.form.get("password"):
            error = "Please enter password"
            return render_template("login.html", error=error)

        # Query database for username
        else:
            username = request.form.get("username")

            connection = sqlite3.connect('jobtrack.db')
            connection.row_factory = sqlite3.Row
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            rows = cursor.fetchall()
            connection.close()

        # Ensure username exists and password is correct
            if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
                error = "invalid username and/or password"
                return render_template("login.html", error=error)
            # Remember which user has logged in
            session["user_id"] = rows[0]["id"]

        # Redirect user to home page
            flash('You were successfully logged in!')
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        confirm_email = request.form.get("confirm_email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Validation
        if not username:
            error = "Please enter a username"
        elif not email or not confirm_email:
            error = "Please enter and confirm your email"
        elif email != confirm_email:
            error = "Emails do not match"
        elif not password or not confirmation:
            error = "Please enter and confirm your password"
        elif password != confirmation:
            error = "Passwords do not match"

        if error:
            return render_template("register.html", error=error)

        hashed_password = generate_password_hash(password)

        # Insert user into the database
        try:
            with sqlite3.connect('jobtrack.db') as connection:
                cursor = connection.cursor()
                cursor.execute(
                    "INSERT INTO users (username, email, hash) VALUES (?, ?, ?)",
                    (username, email, hashed_password)
                )
                connection.commit()
        except sqlite3.IntegrityError:
            error = "Username or email already exists"
            return render_template("register.html", error=error)

        # Log in the new user
        with sqlite3.connect('jobtrack.db') as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

        if user:
            session["user_id"] = user[0]
            return redirect("/custom")

        error = "An unknown error occurred. Please try again."
    return render_template("register.html", error=error)

@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Handle profile picture update
        if 'file' not in request.files:
            flash('No file part in the request.')
            return redirect(request.url)

        file = request.files['file']

        # Check if the user selected a file
        if file.filename == '':
            flash('No file selected.')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            # Save the file with a unique name based on user_id
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{session['user_id']}_{filename}")
            file.save(filepath)

            # Update the database with the new profile picture path
            with sqlite3.connect('jobtrack.db') as connection:
                cursor = connection.cursor()
                cursor.execute(
                    "UPDATE info SET profile_picture = ? WHERE user_id = ?",
                    (filepath, session["user_id"])
                )
                connection.commit()

            flash('Profile picture updated successfully!')
            return redirect(url_for('profile'))

    # Fetch user information for GET request
    connection = sqlite3.connect('jobtrack.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM info WHERE user_id = ? ORDER BY id DESC", (session["user_id"],))
    info = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) AS rejected_count FROM applications WHERE user_id = ? AND app_status = 'Rejected'", (session["user_id"],))
    rejected_count = cursor.fetchone()["rejected_count"]

    cursor.execute("SELECT COUNT(*) AS offer_count FROM applications WHERE user_id = ? AND app_status = 'Offer'", (session["user_id"],))
    offer_count = cursor.fetchone()["offer_count"]

    cursor.execute("SELECT COUNT(*) AS interview_count FROM applications WHERE user_id = ? AND app_status = 'Interview'", (session["user_id"],))
    interview_count = cursor.fetchone()["interview_count"]

    cursor.execute("SELECT COUNT(*) AS application_count FROM applications WHERE user_id = ?", (session["user_id"],))
    application_count = cursor.fetchone()["application_count"]

    connection.close()

    # Provide default values if no info is available
    if not info:
        info = [{
            "full_name": "N/A",
            "current_job": "N/A",
            "current_salary": "N/A",
            "current_location": "N/A",
            "dob": "N/A",
            "profile_picture": None
        }]

    return render_template("profile.html", info=info, rejected_count=rejected_count, offer_count=offer_count, interview_count=interview_count, application_count=application_count)


@app.route("/forgot", methods=["GET", "POST"])
def forget():
    if request.method == "POST":
        error = None
        username = request.form.get("username")
        if not username:
            error = "Please enter username"
            return render_template("forgot_pass.html", error=error)
        password = request.form.get("new_password")
        confirmation = request.form.get("confirm_password")
        if not password or not confirmation:
            error = "Please provide password and confirmation"
            return render_template("forgot_pass.html", error=error)
        
        if password != confirmation:
            error = "Passwords do not match"
            return render_template("forgot_pass.html", error=error)
        
        with sqlite3.connect('jobtrack.db') as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            rows = cursor.fetchall()
           # connection.close()
        # Ensure username exists and password is correct
        if len(rows) != 1:
            error = "invalid username"
            return render_template("forgot_pass.html", error=error)
        
        hashed_password = generate_password_hash(password)
        with sqlite3.connect('jobtrack.db') as connection:
            cursor = connection.cursor()
            cursor.execute("UPDATE users SET hash = ? WHERE username = ?", (hashed_password, username))
            connection.commit()

        flash('Password has been changed successfully!')
        if 'user_id' in session:
            return redirect("/")
        else:
            return redirect("/login")
        
    return render_template("forgot_pass.html")

@app.route("/add", methods = ['GET', 'POST'])
@login_required
def add():
    if request.method == "POST":
        job_title = request.form.get("job_title")
        if not job_title:
            return apology("Please enter job title")
        
        company = request.form.get("company")
        if not company:
            return apology("Please enter company name")
        
        salary = request.form.get("salary")
        if not salary:
            return apology("Please enter salary")

        location = request.form.get("location")
        if not location:
            return apology("Please enter location")
        
        date = request.form.get("date")
        if not date:
            return apology("Please enter date")
        
        with sqlite3.connect('jobtrack.db') as connection:
            cursor = connection.cursor()
            cursor.execute("INSERT INTO applications (user_id, job_title, company, salary, location, date) VALUES (?, ?, ?, ?, ?, ?)", (session["user_id"], job_title, company, salary, location, date))
            connection.commit()
        
        return redirect("/")
    
    return render_template("add.html")

@app.route("/history", methods = ['GET'])
@login_required
def history():
    connection = sqlite3.connect('jobtrack.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM applications WHERE user_id = ? AND (app_status = ? OR app_status = ?) ORDER BY date DESC", (session["user_id"], "Rejected", "Offer"))
    applications = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) AS rejected_count FROM applications WHERE user_id = ? AND app_status = 'Rejected'", (session["user_id"],))
    rejected_count = cursor.fetchone()["rejected_count"]

    cursor.execute("SELECT COUNT(*) AS offer_count FROM applications WHERE user_id = ? AND app_status = 'Offer'", (session["user_id"],))
    offer_count = cursor.fetchone()["offer_count"]
    connection.close()
    
    return render_template("history.html", applications=applications, rejected_count=rejected_count, offer_count=offer_count)

    connection.close()
    
    return render_template("history.html", applications=applications)

from flask import render_template, flash
import datetime
import urllib.parse

@app.route('/update_status/<int:application_id>', methods=['POST'])
def update_status(application_id):
    new_status = request.form.get('app_status')
    if not new_status:
        return "Bad Request", 400

    # Update the status in the database
    with sqlite3.connect('jobtrack.db') as connection:
        cursor = connection.cursor()
        cursor.execute("UPDATE applications SET app_status = ? WHERE id = ? AND user_id = ?",
                       (new_status, application_id, session["user_id"]))
        connection.commit()

    # If status is "Interview", render the calendar input page
    if new_status == "Interview":
        # Fetch application details for the email
        with sqlite3.connect('jobtrack.db') as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT job_title, company FROM applications WHERE id = ? AND user_id = ?",
                           (application_id, session["user_id"]))
            application = cursor.fetchone()

        if application:
            return render_template("schedule_interview.html", application_id=application_id,
                                   job_title=application[0], company=application[1])

    return redirect("/")

import urllib.parse

@app.route('/send_interview_email/<int:application_id>', methods=['POST'])
@login_required
def send_interview_email(application_id):
    interview_date = request.form.get("interview_date")
    interview_time = request.form.get("interview_time")
    # Validate input fields
    if not interview_date or not interview_time:
        flash("Date and time are required.", "danger")
        return redirect(url_for('schedule_interview', application_id=application_id))

    # Fetch application details from the database
    with sqlite3.connect('jobtrack.db') as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT job_title, company FROM applications WHERE id = ? AND user_id = ?",
                       (application_id, session["user_id"]))
        application = cursor.fetchone()

        cursor.execute("SELECT email FROM users WHERE id = ?", (session["user_id"],))
        email = cursor.fetchone()

    if not application:
        flash("Application not found or access denied.", "danger")
        return redirect(url_for('home'))

    job_title, company = application

    # Compose email content
    subject = "Interview Reminder"
    body = f"""
    Job Title: {job_title}
    Company: {company}
    Interview Date and Time: {interview_date} at {interview_time}
    """

    # Create Google Calendar event link
    start_datetime = f"{interview_date}T{interview_time}:00"
    end_datetime = f"{interview_date}T{str(int(interview_time.split(':')[0]) + 1).zfill(2)}:{interview_time.split(':')[1]}:00"  # Adds 1 hour
    event_title = f"Interview: {job_title} for {company}"
    event_description = f"Interview with {company} for the {job_title} position!"
    event_location = "Virtual or In-person (specify in description)"

    google_calendar_url = (
        "https://calendar.google.com/calendar/render?"
        + urllib.parse.urlencode({
            "action": "TEMPLATE",
            "text": event_title,
            "dates": f"{start_datetime.replace(':', '').replace('-', '')}/{end_datetime.replace(':', '').replace('-', '')}",
            "details": event_description,
            "location": event_location,
            "sf": "true",
            "output": "xml"
        })
    )

    body += f"\nAdd to your calendar: {google_calendar_url}"

    print(email[0])
    # Send email
    try:
        msg = Message(subject, recipients=[email[0]])
        msg.body = body
        mail.send(msg)
        flash("Interview reminder email sent successfully!", "success")
    except Exception as e:
        flash("An error occurred while sending the email, please try again")
        return render_template("schedule_interview.html", application_id=application_id,
                                   job_title=application[0], company=application[1])

    # Redirect to the home page after successful email
    return redirect(url_for('home'))

@app.route("/custom", methods = ['GET', 'POST'])
def custom():
    if request.method == "POST":
        full_name = request.form.get("full_name")
        if not full_name:
            return apology("Please enter your name")
        
        current_job = request.form.get("current_job")
        if not current_job:
            return apology("Please enter your current employer")
        
        current_salary = request.form.get("current_salary")
        if not current_salary:
            return apology("Please enter your current salary")

        current_location = request.form.get("current_location")
        if not current_location:
            return apology("Please enter your current location")
        
        dob = request.form.get("dob")
        if not dob:
            return apology("Please enter your date of birth")
        
        with sqlite3.connect('jobtrack.db') as connection:
            cursor = connection.cursor()
            cursor.execute("INSERT INTO info (user_id, full_name, current_job, current_salary, current_location, dob) VALUES (?, ?, ?, ?, ?, ?)", (session["user_id"], full_name, current_job, current_salary, current_location, dob))
            connection.commit()
        
        return redirect("/")
    
    return render_template("custom.html")

@app.route('/authorize')
def authorize():
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session.get('state') == request.args.get('state'):
        return redirect(url_for('profile'))

    session['credentials'] = {
        'token': flow.credentials.token,
        'refresh_token': flow.credentials.refresh_token,
        'token_uri': flow.credentials.token_uri,
        'client_id': flow.credentials.client_id,
        'client_secret': flow.credentials.client_secret,
        'scopes': flow.credentials.scopes
    }
    return redirect(url_for('calendar'))

@app.route('/create_event', methods=['GET', 'POST'])
def create_event():
    if 'credentials' not in session:
        return redirect(url_for('authorize'))

    service = get_calendar_service()
    connection = sqlite3.connect('jobtrack.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("SELECT company, location, date FROM applications WHERE user_id = ?", (session["user_id"],))
    applications = cursor.fetchall()
    connection.close()

    for job in applications:
        company, location, date = job

        
        event = {
            'summary': company,
            'location': location,
            'description': f'Job Application: {company} in {location}',
            'start': {
                'dateTime': f'{date}T09:00:00',
                'timeZone': 'America/Chicago',
            },
            'end': {
                'dateTime': f'{date}T17:00:00',
                'timeZone': 'America/Chicago',
            },
        }
        
        event_result = service.events().insert(calendarId='primary', body=event).execute()
        print(f"Event created: {event_result.get('htmlLink')}")

    return "Job application events have been added to your Google Calendar!"

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
   return render_template("contact.html")

@app.route("/resources")
@login_required
def resources():
   return render_template("resources.html")

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect("/")


# Load environment variables
load_dotenv()



# Session setup
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Flask-Mail setup
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('NextStep', os.getenv('MAIL_USERNAME'))

mail = Mail(app)

# Routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/send_email", methods=["POST"])
def send_email():
    try:
        recipient = request.form["email"]
        subject = request.form["subject"]
        body = request.form["body"]

        msg = Message(subject, recipients=[recipient])
        msg.body = body
        mail.send(msg)
        flash("Email sent successfully!", "success")
    except Exception as e:
        flash(f"An error occurred: {str(e)}", "danger")
    return redirect(url_for("index"))

if __name__ == '__main__':
    app.run(debug=True)

print(app.url_map)
