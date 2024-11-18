from flask import Flask, request, render_template, redirect, url_for
from datetime import datetime, timedelta, date

from apscheduler.schedulers.background import BackgroundScheduler
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

import pytz
import random


YOUTUBE_API_KEYS = [
    'AIzaSyBVQUO8bPJN9YFfoGna3-vuqwdl8f11n4I',
    'AIzaSyAXhXAyqTC776JzFLgH4kkKKcEkq-cXW0o',
    'AIzaSyCVvKYAFiIWTNpqDe92hyRtfwh1s3zU5Hg',
    'AIzaSyBzajMQXVq5bsJmKwb2sOU9maBg87C1HcA',
    'AIzaSyDi4JCFBM-WmIiyNg3d4-tQN7J9IxN7wjY',
    'AIzaSyDFAh4_OCSl-duiI0Tt7qSv3swOl4hlBro'
]


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)

############################################ Register users ###########################################
class User(UserMixin, db.Model):
    # usermixin is use to get the user id, ensures they are authenticated, and keep track of their activeness
    # create the column for the database
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(10), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    first_name = db.Column(db.String(10), nullable=False)
    last_name = db.Column(db.String(10), nullable=False)
    user_email = db.Column(db.String(10), nullable=False, unique=True)
    is_active = db.Column(db.Boolean, default=True)
    eastern_time = pytz.timezone('US/Eastern')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(tz=eastern_time))
    last_login = db.Column(db.DateTime, nullable=False, default=datetime.now(tz=eastern_time))
    login_count = db.Column(db.Integer, default=1, nullable=True)
    


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data inputed by the users
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        first_name = request.form['fname']
        last_name = request.form['lname']
        email = request.form['email']

        # check if the user emai already exists
        existing_email = User.query.filter_by(user_email=email).first()
        if existing_email:
            return render_template('/login/register.html', error='Email has an Account!', form_data=request.form)


        # check if the user name already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('/login/register.html', error='Username already taken!', form_data=request.form)


        # Checks if the password and the confirm password are the same
        if password != confirm_password:
            return render_template('/login/register.html', error='Passwords do not match!', form_data=request.form)
        
        
        # hashes the password
        hashed_password = generate_password_hash(password)

        # Create a new user
        new_user = User(username=username, password=hashed_password, first_name=first_name, last_name=last_name, user_email=email)

            # if it matches it log in the user to a session and redirect them to the index page
        # Add the user to the database
        with app.app_context():
            db.session.add(new_user)
            db.session.commit()

        # Redirect to login page so that the user can then login
        return redirect(url_for('index'))
    else:
        return render_template('/login/register.html', form_data={})


#####################################################################################################
############################################ LOGIN IN USERS #########################################
# Initialize Flask-Login to manage sessions
login_manager = LoginManager()
login_manager.init_app(app)

# User loader function, by loading user object from their id in the database
@login_manager.user_loader
def load_user(user_id):
    # return  the user with the corresponding ID
    return User.query.get(int(user_id))

# Login route
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Gets the username and password
        username = request.form['username']
        password = request.form['password']

        # it then query the username through the database and returns the first match if any
        user = User.query.filter_by(username=username).first()

        # if the user exist it then compare the provided password with the hash verision in the database
        if user and check_password_hash(user.password, password):
            # Log the user into the session

            # if the user has login already within the same day
            if user.last_login.date() != date.today():
                # if not it increments login count(The days they visited)
                user.login_count += 1
                
            # it then updates their last login time to the this current log in
            user.last_login = datetime.now()
            db.session.commit()
            login_user(user)
            return redirect(url_for('home'))

        else:
            # if condition above are not met it simply reload the page with an error message
            return render_template('/login/index.html', error='Invalid username or password', form_data=request.form)
    else:
        return render_template('/login/index.html', form_data={})

@app.route('/logout')
@login_required  # This decorator ensures that only logged in users can access this route
def logout():
    logout_user()
    # when the user log out it just redirect them back to the login page
    return redirect(url_for('index'))

#######################################################################################################
##################################### Change Password #################################################

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        # Get form data inputed by the users
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Get the current logged in user
        user = current_user

        # Check if the current password matches the user's existing password
        if not check_password_hash(user.password, old_password):
            return render_template('/login/change_password.html', error='Current Password is incorrect!', form_data=request.form)

        # Check if the new password and the confirm new password are the same
        if new_password != confirm_password:
            return render_template('/login/change_password.html', error_new='New Passwords do not match!', form_data=request.form)

        # Hash the new password
        hashed_password = generate_password_hash(new_password)

        # Update the user's password in the database
        user.password = hashed_password
        db.session.commit()

        return redirect(url_for('account'))
    else:
        return render_template('/login/change_password.html', form_data={})
    
#######################################################################################################
##################################### Change USERNAME #################################################

@app.route('/change_username', methods=['GET', 'POST'])
@login_required
def change_username():
    if request.method == 'POST':
        # Get the new username and password from the user
        new_username = request.form['new_username']
        password = request.form['password']

        user = current_user

        # check if the password given is the user password
        if not check_password_hash(user.password, password):
            return render_template('/login/change_username.html', error='Password is incorrect!', form_data=request.form)
        
        # check if the user name already exists
        existing_user = User.query.filter_by(username=new_username).first()
        if existing_user:
            return render_template('/login/change_username.html', error='Username already taken!', form_data=request.form)

        # adds the username to the database
        # Their username is changed in every table and every past submissions they made
        current_username = current_user.username
        gain_muscle_table = gain_muscle_data.query.filter_by(username=current_username).all()
        for entry in gain_muscle_table:
            entry.username = new_username

        lose_weight_table = lose_weight_data.query.filter_by(username=current_username).all()
        for entry in lose_weight_table:
            entry.username = new_username

        yoga_table = daily_yoga_workout.query.filter_by(username=current_username).all()
        for entry in yoga_table:
            entry.username = new_username

        cardio_table = daily_cardio_workout.query.filter_by(username=current_username).all()
        for entry in cardio_table:
            entry.username = new_username

        hiit_table = daily_hiit_workout.query.filter_by(username=current_username).all()
        for entry in hiit_table:
            entry.username = new_username

        Review_table = Review.query.filter_by(username=current_username).all()
        for entry in Review_table:
            entry.username = new_username

        Report_table = Report.query.filter_by(username=current_username).all()
        for entry in Report_table:
            entry.username = new_username
 
        user.username = new_username
        db.session.commit()

        # if successful I takes the user back to the index pages
        return redirect(url_for('account'))
    else:
        return render_template('/login/change_username.html', form_data={} )
    
#######################################################################################################
##################################### Change Email ####################################################
    
@app.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    if request.method == 'POST':
        # Get the new username and password from the user
        new_email = request.form['new_email']
        password = request.form['password']

        user = current_user

        # check if the password given is the user password
        if not check_password_hash(user.password, password):
            return render_template('/login/change_email.html', error='Password is incorrect!', form_data=request.form)
        
        # check if the email already exists
        existing_email = User.query.filter_by(user_email=new_email).first()
        if existing_email:
            return render_template('/login/change_email.html', error='Email already exist!', form_data=request.form )
        
        # update the user email in all tables within the database, even in their past submissions
        current_email = current_user.user_email
        gain_muscle_table = gain_muscle_data.query.filter_by(user_email=current_email).all()
        for entry in gain_muscle_table:
            entry.user_email = new_email

        lose_weight_table = lose_weight_data.query.filter_by(user_email=current_email).all()
        for entry in lose_weight_table:
            entry.user_email = new_email

        yoga_table = daily_yoga_workout.query.filter_by(user_email=current_email).all()
        for entry in yoga_table:
            entry.user_email = new_email

        cardio_table = daily_cardio_workout.query.filter_by(user_email=current_email).all()
        for entry in cardio_table:
            entry.user_email = new_email

        hiit_table = daily_hiit_workout.query.filter_by(user_email=current_email).all()
        for entry in hiit_table:
            entry.user_email = new_email

        Review_table = Review.query.filter_by(user_email=current_email).all()
        for entry in Review_table:
            entry.user_email = new_email

        Report_table = Report.query.filter_by(user_email=current_email).all()
        for entry in Report_table:
            entry.user_email = new_email
        
        # adds the username to the database 
        user.user_email = new_email
        db.session.commit()

        # if successful I takes the user back to the index pages
        return redirect(url_for('account'))
    else:
        return render_template('/login/change_email.html', form_data={})
    
#######################################################################################################
##################################### Change Name ####################################################

@app.route('/change_name', methods=['GET', 'POST'])
@login_required
def change_name():
    if request.method == 'POST':
        # Get the new names and password from the user
        new_first_name = request.form['new_fname']
        new_last_name = request.form['new_lname']
        password = request.form['password']

        user = current_user

        # check if the password given is the user password
        if not check_password_hash(user.password, password):
            return render_template('/login/change_name.html', error='Password is incorrect!', form_data=request.form)
        
        # updates the user last name in all the databases
        current_last_name = current_user.last_name

        gain_muscle_table = gain_muscle_data.query.filter_by(user_lastname=current_last_name).all()
        for entry in gain_muscle_table:
            entry.user_lastname = new_last_name

        lose_weight_table = lose_weight_data.query.filter_by(user_lastname=current_last_name).all()
        for entry in lose_weight_table:
            entry.user_lastname = new_last_name

        yoga_table = daily_yoga_workout.query.filter_by(user_lastname=current_last_name).all()
        for entry in yoga_table:
            entry.user_lastname = new_last_name

        cardio_table = daily_cardio_workout.query.filter_by(user_lastname=current_last_name).all()
        for entry in cardio_table:
            entry.user_lastname = new_last_name

        hiit_table = daily_hiit_workout.query.filter_by(user_lastname=current_last_name).all()
        for entry in hiit_table:
            entry.user_lastname = new_last_name

        Review_table = Review.query.filter_by(user_lastname=current_last_name).all()
        for entry in Review_table:
            entry.user_lastname = new_last_name

        Report_table = Report.query.filter_by(user_lastname=current_last_name).all()
        for entry in Report_table:
            entry.user_lastname = new_last_name
      

        # adds the name to the database 
        user.first_name = new_first_name
        user.last_name = new_last_name
        db.session.commit()

        # if successful it takes the user back to the index pages
        return redirect(url_for('account'))
    else:
        return render_template('/login/change_name.html', form_data={}) 


########################################## Gain Muscles Workouts Generator ##############################################
# list of catergorized exercsies
gain_muscles_list1 = ['Push-Ups', 'Pike Push-Ups', 'Diamond Push-Ups', 'Tricep Push-Ups', 'Shoulder Tap Push-Up']
gain_muscles_list2 = ['Chair Dips', 'Lateral Squats', 'Wall Sits', 'Squat Jacks', 'High Knee Lift' ]
gain_muscles_list3 = ['Sit-Ups', 'Russian Twists', 'Heel Touches', 'Shoulder Bridge', 'Sprinter Sit-Ups']
gain_muscles_list4 = ['Mountain Climbers', 'Burpee', 'Handstand Push-Ups', 'Inchworm', 'Donkey Kicks']
gain_muscles_list5 = ['Superman Lifts', 'Plank', 'Side Plank', 'Reverse Planks', 'Plank Hip Dips']
gain_muscles_list6 = ['Leg Raises', 'Calf Raises', 'Glute Bridges', 'Single Leg Lifts', 'Side-Lying Leg Raise']
gain_muscles_list7 = ['Reverse Crunches', 'Cross Crunches', 'Vertical Leg Crunch', 'Butterfly Crunches', 'Crunches']
gain_muscles_list8 = ['Jumping Lunges', 'Walking Lunges', 'Forward Lunges', 'Front to Back Lunge', 'Curtsy Lunge']

def get_gain_pushups():
    random.shuffle(gain_muscles_list1)
    return gain_muscles_list1[:1]

def get_gain_standing():
    random.shuffle(gain_muscles_list2)
    return gain_muscles_list2[:1]

def get_gain_floor():
    random.shuffle(gain_muscles_list3)
    return gain_muscles_list3[:1]

def get_gain_body():
    random.shuffle(gain_muscles_list4)
    return gain_muscles_list4[:1]

def get_gain_planks():
    random.shuffle(gain_muscles_list5)
    return gain_muscles_list5[:1]

def get_gain_raises():
    random.shuffle(gain_muscles_list6)
    return gain_muscles_list6[:1]

def get_gain_crunches():
    random.shuffle(gain_muscles_list7)
    return gain_muscles_list7[:1]

def get_gain_lunges():
    random.shuffle(gain_muscles_list8)
    return gain_muscles_list8[:1]


################################ Back-end for the gain_muscle #################################
class gain_muscle_data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(10), nullable=False)
    user_lastname = db.Column(db.String(10), nullable=False)
    user_email = db.Column(db.String(10), nullable=False)
    gain_muscle = db.Column(db.Integer, nullable=True)
    eastern_time = pytz.timezone('US/Eastern')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(tz=eastern_time))

@app.route('/gain_muscles', methods=['GET', 'POST'])
@login_required
def gain_muscles():
    username = current_user.username

    #gets the random workouts from the array list fucntions
    random_gain_workoutset1 = get_gain_pushups()[0]
    random_gain_workoutset2 = get_gain_standing()[0]
    random_gain_workoutset3 = get_gain_floor()[0]
    random_gain_workoutset4 = get_gain_body()[0]
    random_gain_workoutset5 = get_gain_planks()[0]
    random_gain_workoutset6 = get_gain_raises()[0]
    random_gain_workoutset7 = get_gain_crunches()[0]
    random_gain_workoutset8 = get_gain_lunges()[0]


    if request.method == 'POST':
        # gets the amout of workout the user did, if they don't it markes it as 0
        workout_1 = int(request.form.get('gain_workout_1', 0))
        workout_2 = int(request.form.get('gain_workout_2', 0))
        workout_3 = int(request.form.get('gain_workout_3', 0))
        workout_4 = int(request.form.get('gain_workout_4', 0))
        workout_5 = int(request.form.get('gain_workout_5', 0))
        workout_6 = int(request.form.get('gain_workout_6', 0))
        workout_7 = int(request.form.get('gain_workout_7', 0))
        workout_8 = int(request.form.get('gain_workout_8', 0))

        # checks the gain_muscle_data database to retrive the last time the current user submitted a daily_workout form
        last_submission = gain_muscle_data.query.filter_by(user_id=current_user.id).order_by(gain_muscle_data.created_at.desc()).first()

        # the same day time in eastern time zone
        same_day = datetime.now(pytz.timezone('US/Eastern')).date()

        # Checks if the user has already submitted a form in the current day
        if last_submission and last_submission.created_at.date() == same_day:
            # if so returns a sorry page
            return redirect(url_for('workout_sorry'))
        
        # adds up the inputs for all the gain_muscles workouts to get the total
        gain_muscle = workout_1 + workout_2 + workout_3 + workout_4 + workout_5 + workout_6 + workout_7 + workout_8

        # the the function input to the current user data with the number of workout they did
        gain_muscle_workout = gain_muscle_data(user_id=current_user.id, username=current_user.username, 
                    user_lastname=current_user.last_name, user_email=current_user.user_email, gain_muscle=gain_muscle)
        
        # adds that information to the database
        db.session.add(gain_muscle_workout)
        db.session.commit()
        
        # returns a thank you page base on the amount of workout the user submits
        if gain_muscle == 1:       
            return redirect(url_for('thankyou_course', total=gain_muscle))
        elif gain_muscle == 2: 
            return redirect(url_for('thankyou_course', total=gain_muscle))
        elif gain_muscle == 3:
            return redirect(url_for('thankyou_course', total=gain_muscle))
        elif gain_muscle == 4:
            return redirect(url_for('thankyou_course', total=gain_muscle))
        elif gain_muscle == 5:
            return redirect(url_for('thankyou_course', total=gain_muscle))
        elif gain_muscle == 6:
            return redirect(url_for('thankyou_course', total=gain_muscle))
        elif gain_muscle == 7:
            return redirect(url_for('thankyou_course', total=gain_muscle))
        elif gain_muscle == 8:
            return redirect(url_for('thankyou_course', total='all'))
        else:
            return redirect(url_for('thanks_none'))
        
    # Query to get the usernames of users in first, second, and third place for gain muscle workouts
    top_users = db.session.query(
    gain_muscle_data.username,
    func.sum(gain_muscle_data.gain_muscle)
    .label('total_workouts')
    ).group_by(gain_muscle_data.username
    ).order_by(func.sum(gain_muscle_data.gain_muscle).desc()
    ).all()


    # extracts the top 3 usernames and assigning them to separate variables
    # otherwise if there is no user, return None
    first_place = top_users[0].username if len(top_users) >= 1 else None
    second_place = top_users[1].username if len(top_users) >= 2 else None
    third_place = top_users[2].username if len(top_users) >= 3 else None

    # gets the total workout for the top 3 users, otherwise return none
    total1 = top_users[0].total_workouts if len(top_users) >= 1 else None
    total2 = top_users[1].total_workouts if len(top_users) >= 2 else None
    total3 = top_users[2].total_workouts if len(top_users) >= 3 else None
        

    
    user_rank = None
    user_total_workout = None
    # goes through the tops_users query list to get the current user rank and their total workout
    for rank, user in enumerate(top_users, start=1):
        # within the list, if the rank user username is the same as our current user username
        if user.username == current_user.username:
            # then it's our logged in user id, store their rank in the user_rank variable
            user_rank = rank
            # and their total workout
            user_total_workout = user.total_workouts
            break

    
    return render_template("gain_muscles.html", username=username, workout1=random_gain_workoutset1, workout2=random_gain_workoutset2, 
    workout3=random_gain_workoutset3, workout4=random_gain_workoutset4, 
    workout5=random_gain_workoutset5, workout6=random_gain_workoutset6, 		
    workout7=random_gain_workoutset7, workout8=random_gain_workoutset8, 

    first_place=first_place, total1=total1, 
    second_place=second_place, total2=total2, 
    third_place=third_place, total3=total3, 
    user_rank=user_rank, user_total_workout=user_total_workout)

################################## Gain Muscle rank table #################################
@app.route('/rank')
@login_required
def rank():
    # uses the same query to get the top 3 user
    # but instead of limiting the output to 3 instead return all the users in a rank order
    ranks  = db.session.query(
        gain_muscle_data.username,
        func.sum(gain_muscle_data.gain_muscle).label('total_workouts')
    ).group_by(gain_muscle_data.username
    ).order_by(func.sum(gain_muscle_data.gain_muscle).desc()).all()

    # create an empty array to store user data so that they can be iterate through to get all users on the html page
    user_ranks = []
    usernames = []
    total_workouts = []

    # put every data from the query into the lists
    for rank, user in enumerate(ranks, start=1):
        user_ranks.append(rank)
        usernames.append(user.username)
        total_workouts.append(user.total_workouts)

    #zipped the data so that they can be iterated through all at once on the html page
    zipped_data = zip(user_ranks, usernames, total_workouts)


    # store the current username 
    current_username = current_user.username

    # gets the rank of the current user so that it can be mark with red in the table
    current_user_rank = next((i + 1 for i, username in enumerate(usernames) if username == current_username), None)

    return render_template('/rank_tables/rank.html',  zipped_data=zipped_data, current_user_rank=current_user_rank)

        

###################################### Lose Weight Workouts Generator #######################################
# The code is a the same as the gain muscles but with different tables and excercise
# list of catergorized exercsies
lose_weight_list1 = ['Jumping Jacks', 'High Knees', 'Burpees', 'Tuck Jumps', 'Ground Zero Jump']
lose_weight_list2 = ['Jump Squats', 'Squats', 'Boxing Squats', 'Side Step to Squat', 'Pistol Squat']
lose_weight_list3 = ['Lunges', 'Side Lunges', 'Jumping Lunges', 'Pendulum Lunge', 'Curtsy Lunge']
lose_weight_list4 = ['Plank', 'Plank Shoulder Tap', 'Elbow Plank', 'Knee Planks', 'Plank Tucks']
lose_weight_list5 = ['Running in Place', 'Jogging in Place', 'Side to Side Shuffle', 'Side Toe Taps', 'Standing Cross-Crunch']
lose_weight_list6 = ['Arm Circles', 'Arm Lateral Raises', 'Torso Twist', 'Hip Circles', 'Leg Circles']
lose_weight_list7 = ['Russian Twists', 'Flutter Kicks', 'Bicycle Crunches', 'Ab Curl Hollow Hold', 'Oblique Twists']
lose_weight_list8 = ['Inchworm', 'Mountain Climbers', 'Push-Ups', 'Bear Crawl', 'Cross-Body Mountain Climber']

def get_lose_jumps():
    random.shuffle(lose_weight_list1)
    return lose_weight_list1[:1]

def get_lose_squats():
    random.shuffle(lose_weight_list2)
    return lose_weight_list2[:1]

def get_lose_lunges():
    random.shuffle(lose_weight_list3)
    return lose_weight_list3[:1]

def get_lose_planks():
    random.shuffle(lose_weight_list4)
    return lose_weight_list4[:1]

def get_lose_fast():
    random.shuffle(lose_weight_list5)
    return lose_weight_list5[:1]

def get_lose_standing():
    random.shuffle(lose_weight_list6)
    return lose_weight_list6[:1]

def get_lose_floor():
    random.shuffle(lose_weight_list7)
    return lose_weight_list7[:1]

def get_lose_vertical():
    random.shuffle(lose_weight_list8)
    return lose_weight_list8[:1]

###################################### Back-end for lose weight #######################################3
class lose_weight_data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(10), nullable=False)
    user_lastname = db.Column(db.String(10), nullable=False)
    user_email = db.Column(db.String(10), nullable=False)
    lose_weight = db.Column(db.Integer, nullable=True)
    eastern_time = pytz.timezone('US/Eastern')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(tz=eastern_time))


@app.route('/lose_weight', methods=['GET', 'POST'])
@login_required
def lose_weight():
    username = current_user.username

    random_lose_workoutset1 = get_lose_jumps()[0]
    random_lose_workoutset2 = get_lose_squats()[0]
    random_lose_workoutset3 = get_lose_lunges()[0]
    random_lose_workoutset4 = get_lose_planks()[0]
    random_lose_workoutset5 = get_lose_fast()[0]
    random_lose_workoutset6 = get_lose_standing()[0]
    random_lose_workoutset7 = get_lose_floor()[0]
    random_lose_workoutset8 = get_lose_vertical()[0]

    
    if request.method == 'POST':
        # gets the amout of workout the user did, if they don't it markes it as 0
        workout_1 = int(request.form.get('lose_workout_1', 0))
        workout_2 = int(request.form.get('lose_workout_2', 0))
        workout_3 = int(request.form.get('lose_workout_3', 0))
        workout_4 = int(request.form.get('lose_workout_4', 0))
        workout_5 = int(request.form.get('lose_workout_5', 0))
        workout_6 = int(request.form.get('lose_workout_6', 0))
        workout_7 = int(request.form.get('lose_workout_7', 0))
        workout_8 = int(request.form.get('lose_workout_8', 0))

        # checks the daily_yoga_workout database to retrive the last time the current user submitted a daily_workout form
        last_submission = lose_weight_data.query.filter_by(user_id=current_user.id).order_by(lose_weight_data.created_at.desc()).first()

        # the same day time in eastern time zone
        same_day = datetime.now(pytz.timezone('US/Eastern')).date()

        # Checks if the user has already submitted a form in the current day
        if last_submission and last_submission.created_at.date() == same_day:
            # if so returns a sorry page
            return redirect(url_for('workout_sorry'))
        
        # adds up the inputs for all the lose_weight workouts to get the total
        lose_weight = workout_1 + workout_2 + workout_3 + workout_4 + workout_5 + workout_6 + workout_7 + workout_8

        # the the function input to the current user data with the number of workout they did
        lose_weight_workout = lose_weight_data(user_id=current_user.id, username=current_user.username, 
                    user_lastname=current_user.last_name, user_email=current_user.user_email, lose_weight=lose_weight)
        
        # adds that information to the database
        db.session.add(lose_weight_workout)
        db.session.commit()
        
        # returns a thank you page base on the amount of workout the user submits
        if lose_weight == 1:       
            return redirect(url_for('thankyou_course', total=lose_weight))
        elif lose_weight == 2: 
            return redirect(url_for('thankyou_course', total=lose_weight))
        elif lose_weight == 3:
            return redirect(url_for('thankyou_course', total=lose_weight))
        elif lose_weight == 4:
            return redirect(url_for('thankyou_course', total=lose_weight))
        elif lose_weight == 5:
            return redirect(url_for('thankyou_course', total=lose_weight))
        elif lose_weight == 6:
            return redirect(url_for('thankyou_course', total=lose_weight))
        elif lose_weight == 7:
            return redirect(url_for('thankyou_course', total=lose_weight))
        elif lose_weight == 8:
            return redirect(url_for('thankyou_course', total='all'))
        else:
            return redirect(url_for('thanks_none'))
        
    # query to get the usernames of users in first, second, and third place for lose weight workouts
    lose_top_users = db.session.query(
        lose_weight_data.username,
        func.sum(lose_weight_data.lose_weight).label('total_workouts')
    ).group_by(lose_weight_data.username).order_by(func.sum(lose_weight_data.lose_weight).desc()).all()

    # extracts usernames and assigning them to separate variables
    first_place = lose_top_users[0].username if len(lose_top_users) >= 1 else None
    second_place = lose_top_users[1].username if len(lose_top_users) >= 2 else None
    third_place = lose_top_users[2].username if len(lose_top_users) >= 3 else None

    # Check for the user in the current user is in the top users list
    lose_user_rank = None
    lose_user_total_workout = None
    for lose_rank, lose_user in enumerate(lose_top_users, start=1):
        if lose_user.username == current_user.username:
            lose_user_rank = lose_rank
            lose_user_total_workout =  lose_user.total_workouts
            break

    total1 = lose_top_users[0].total_workouts if len(lose_top_users) >= 1 else None
    total2 = lose_top_users[1].total_workouts if len(lose_top_users) >= 2 else None
    total3 = lose_top_users[2].total_workouts if len(lose_top_users) >= 3 else None

    return render_template(
        "lose_weight.html", username=username, workout1=random_lose_workoutset1, workout2=random_lose_workoutset2, 
        workout3=random_lose_workoutset3, workout4=random_lose_workoutset4, 
        workout5=random_lose_workoutset5, workout6=random_lose_workoutset6,
        workout7=random_lose_workoutset7, workout8=random_lose_workoutset8,
        
        first_place=first_place, total1=total1, 
        second_place=second_place, total2=total2, 
        third_place=third_place, total3=total3, 

        lose_user_rank=lose_user_rank, lose_user_total_workout=lose_user_total_workout)

################################# Lose weight rank ####################################
@app.route('/lose weight rank')
@login_required
def lose_weight_rank():
    ranks  = db.session.query(
        lose_weight_data.username,
        func.sum(lose_weight_data.lose_weight).label('total_workouts')
    ).group_by(lose_weight_data.username
    ).order_by(func.sum(lose_weight_data.lose_weight).desc()).all()

    user_ranks = []
    usernames = []
    total_workouts = []

    for rank, user in enumerate(ranks, start=1):
        user_ranks.append(rank)
        usernames.append(user.username)
        total_workouts.append(user.total_workouts)

    zipped_data = zip(user_ranks, usernames, total_workouts)
    current_username = current_user.username
    current_user_rank = next((i + 1 for i, username in enumerate(usernames) if username == current_username), None)

    return render_template('/rank_tables/lose_rank.html',  zipped_data=zipped_data, current_user_rank=current_user_rank)


# Displays a thank you message once the daily workout forms have been submitted
@app.route('/thankyou')
@login_required
def thankyou_course():
    username = current_user.username
    total = request.args.get('total', '')
    return render_template('/thank_you/thankyou_course.html', total=total, username=username)
#######################################################################################################

################################# Nutrition calculator ################################################

@app.route('/nutrition', methods=[ 'POST'])
@login_required
def calculate_calories():
    if request.method == 'POST':
        # gets the inputs from the form
        age = int(request.form['age'])
        height_ft = int(request.form['height_ft'])
        height_in = int(request.form['height_in'])
        weight = int(request.form['weight'])
        gender = request.form['gender']
        active_level = request.form['option']

        # convert the height into inches
        height = height_ft * 12 + height_in

        if gender == 'Male':
            # Mifflin-St Jeor Equation
            bmr = (10 * weight) + (6.25 * height) - (5 * age) + 5
        elif gender == 'Female':
            bmr = (10 * weight) + (6.25 * height) - (5 * age) - 161

        # calcualte calories to gain, maintain and lose weight for each activity level
        if active_level == 'inactive':
            maintain_weight = bmr * 1.2
            lose_weight = maintain_weight - 500
            gain_weight = maintain_weight + 500
        elif active_level == 'active':
            maintain_weight = bmr * 1.375
            lose_weight = maintain_weight - 500
            gain_weight = maintain_weight + 500
        elif active_level == 'very':
            maintain_weight = bmr * 1.55
            lose_weight = maintain_weight - 500
            gain_weight = maintain_weight + 500

        # Format the outputed numbers to look more presentable, and round them up to a whole
        maintain_weight = '{:,.0f}'.format(round(maintain_weight))
        lose_weight = '{:,.0f}'.format(round(lose_weight))
        gain_weight = '{:,.0f}'.format(round(gain_weight))

        username = current_user.username
        return render_template('nutrition.html', maintain_weight=maintain_weight, lose_weight=lose_weight, gain_weight=gain_weight, username=username, form_data=request.form)
####################################################################################################################
    
############################################ Youtube API ###########################################################
    
#request for the yoga videos

index = 0 
def fetch_workout_yoga_videos():
    global index
    # try to get the video
    while index < len(YOUTUBE_API_KEYS):
        try:
            youtube = build('youtube', 'v3', developerKey=YOUTUBE_API_KEYS[index])
            request1 = youtube.search().list(
                part='snippet',
                q='5 minutes yin yoga workout random',
                type='video',
                maxResults=1,
            )
            response1 = request1.execute()
            videos1 = response1['items']
            
        
            request2 = youtube.search().list(
                part='snippet',
                q='5 minute accessible yoga random',
                type='video',
                maxResults=1,
            )
            response2 = request2.execute()
            videos2 = response2['items']


            request3 = youtube.search().list(
                part='snippet',
                q='5 minutes yoga for night time random',
                type='video',
                maxResults=1,
            )
            response3 = request3.execute()
            videos3 = response3['items']
            return videos1, videos2, videos3
            
        #If we exceeded quota
        except HttpError as e:
            #check if we exceed the quota
            if e.resp.status == 403 and 'quotaExceeded' in str(e):
                # if we do it tells us 
                print('Quota exceeded, switching ')
                # go to the next key
                index += 1
            #otherwise return nothing
            else:
                # and return nothing
                return None, None, None 
            
    print('All key exceeded')
    return None, None, None 
     #this code is the exact same for the other api builds

#request for the cardio vidoes
def fetch_workout_cardio_videos():
    global index

    while index < len(YOUTUBE_API_KEYS):
        try:
            youtube = build('youtube', 'v3', developerKey=YOUTUBE_API_KEYS[index])
            request4 = youtube.search().list(
                part='snippet',
                q='5 minutes intense cardio Running',
                type='video',
                maxResults=2
            )
            response4 = request4.execute()
            videos4 = response4['items']
            
        
            request5 = youtube.search().list(
                part='snippet',
                q='cardio in place for 5 minutes',
                type='video',
                maxResults=2
            )
            response5 = request5.execute()
            videos5 = response5['items']


            request6 = youtube.search().list(
                part='snippet',
                q='5 minute Circuit training cardio',
                type='video',
                maxResults=2 
            )
            response6 = request6.execute()
            videos6 = response6['items']
            return videos4, videos5, videos6
        except HttpError as e:
            if e.resp.status == 403 and 'quotaExceeded' in str(e):
                print('Quota exceeded ')
                index += 1
            else:
                return None, None, None 
    print('All key exceeded')
    return None, None, None

# request for the hiit videos
def fetch_workout_hiit_videos():
    global index

    while index < len(YOUTUBE_API_KEYS):
        try:
            youtube = build('youtube', 'v3', developerKey=YOUTUBE_API_KEYS[index])
            request7 = youtube.search().list(
                part='snippet',
                q='15 Min Intense HIIT Workout For Fat Burn & Cardio (No Equipment, No Repeats)',
                type='video',
                maxResults=2 
            )
            response7 = request7.execute()
            videos7 = response7['items']
            
            request8 = youtube.search().list(
                part='snippet',
                q='just give me something for 5 intense minute hiit',
                type='video',
                maxResults=2 
            )
            response8 = request8.execute()
            videos8 = response8['items']


            request9 = youtube.search().list(
                part='snippet',
                q='Replace Treadmill With This 10 Min HIIT/CARDIO Workout',
                type='video',
                maxResults=2 
            )
            response9 = request9.execute()
            videos9 = response9['items']
            return videos7, videos8, videos9
        except HttpError as e:
            if e.resp.status == 403 and 'quotaExceeded' in str(e):
                print('Quota exceeded ')
                index += 1
            else:
                return None, None, None
    print('All key exceeded')
    return None, None, None

def update_videos():
    global cardio_videos, yoga_videos, hiit_videos
    yoga_videos = list(fetch_workout_yoga_videos())
    cardio_videos = list(fetch_workout_cardio_videos())
    hiit_videos = list(fetch_workout_hiit_videos())

    # randomly shuffle the videos
    random.shuffle(yoga_videos)
    random.shuffle(cardio_videos)
    random.shuffle(hiit_videos)



# update the videos to a different one every 24 hours
update_videos()
scheduler = BackgroundScheduler()
scheduler.add_job(update_videos, 'interval', hours=24)
scheduler.start()
####################################################################################################################

######################################### Back-end data for YOGA workout page ######################################
# creates a database to store all the users workout
class daily_yoga_workout(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(10), nullable=False)
    user_lastname = db.Column(db.String(10), nullable=False)
    user_email = db.Column(db.String(10), nullable=False)
    yoga = db.Column(db.Integer, nullable=True)
    eastern_time = pytz.timezone('US/Eastern')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(tz=eastern_time))

@app.route('/workout_yoga', methods=['POST'])
@login_required
def yoga_workout_funct():
    if request.method == 'POST':
        # checks the daily_yoga_workout database to retrive the last time the current user submitted a daily_workout form
        last_submission = daily_yoga_workout.query.filter_by(user_id=current_user.id).order_by(daily_yoga_workout.created_at.desc()).first()

       # the same day time in eastern time zone
        same_day = datetime.now(pytz.timezone('US/Eastern')).date()

        # Checks if the user has already submitted a form in the current day
        if last_submission and last_submission.created_at.date() == same_day:
            # if so returns a sorry page
            return redirect(url_for('workout_sorry'))

        # otherwise it goes on to gets the inputs from the form
        first_yoga_vid = int(request.form.get('first_yoga_vid', 0))
        second_yoga_vid = int(request.form.get('second_yoga_vid', 0))
        third_yoga_vid = int(request.form.get('third_yoga_vid', 0))
        
        # adds up the inputs for all yoga workouts
        yoga = first_yoga_vid + second_yoga_vid + third_yoga_vid

        # the the function input to the current user data with the number of workout they did
        yoga_workout = daily_yoga_workout(user_id=current_user.id, username=current_user.username, 
                    user_lastname=current_user.last_name, user_email=current_user.user_email, yoga=yoga)
        
        # adds that information to the database
        db.session.add(yoga_workout)
        db.session.commit()
        
        # returns a thank you page base on the amount of workout the user submits
        if yoga == 1:       
            return redirect(url_for('thanks_workout_1', workout_type='Yoga'))
        elif yoga == 2:
            
            return redirect(url_for('thanks_workout_2', workout_type='Yoga'))
        elif yoga == 3:
            return redirect(url_for('thanks_workout_3', workout_type='Yoga'))
        else:
            return redirect(url_for('thanks_none', workout_type='Yoga' ))
        
################################# Yoga rank ####################################
@app.route('/yoga rank')
@login_required
def yoga_rank():
    ranks  = db.session.query(
        daily_yoga_workout.username,
        func.sum(daily_yoga_workout.yoga).label('total_workouts')
    ).group_by(daily_yoga_workout.username).order_by(func.sum(daily_yoga_workout.yoga).desc()).all()

    user_ranks = []
    usernames = []
    total_workouts = []

    for rank, user in enumerate(ranks, start=1):
        user_ranks.append(rank)
        usernames.append(user.username)
        total_workouts.append(user.total_workouts)

    zipped_data = zip(user_ranks, usernames, total_workouts)
    current_username = current_user.username
    current_user_rank = next((i + 1 for i, username in enumerate(usernames) if username == current_username), None)

    return render_template('/rank_tables/yoga_rank.html',  zipped_data=zipped_data, current_user_rank=current_user_rank)


###################################### Back-end data for CARDIO workout page ########################################

class daily_cardio_workout(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(10), nullable=False)
    user_lastname = db.Column(db.String(10), nullable=False)
    user_email = db.Column(db.String(10), nullable=False)
    cardio = db.Column(db.Integer, nullable=True)
    eastern_time = pytz.timezone('US/Eastern')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(tz=eastern_time))

        
#### The function and method use for the cardio and hiit are the same as the yoga
@app.route('/workout_cardio', methods=['POST'])
@login_required
def cardio_workout_funct():
    if request.method == 'POST':
        last_submission = daily_cardio_workout.query.filter_by(user_id=current_user.id).order_by(daily_cardio_workout.created_at.desc()).first()

        same_day = datetime.now(pytz.timezone('US/Eastern')).date()

        if last_submission and last_submission.created_at.date() == same_day:
            return redirect(url_for('workout_sorry'))

        first_cardio_vid = int(request.form.get('first_cardio_vid', 0))
        second_cardio_vid = int(request.form.get('second_cardio_vid', 0))
        third_cardio_vid = int(request.form.get('third_cardio_vid', 0))
        
        cardio = first_cardio_vid + second_cardio_vid + third_cardio_vid

        cardio_workout = daily_cardio_workout(user_id=current_user.id, username=current_user.username, 
                    user_lastname=current_user.last_name, user_email=current_user.user_email, cardio=cardio)
        
        db.session.add(cardio_workout)
        db.session.commit()

        if cardio == 1:
            return redirect(url_for('thanks_workout_1', workout_type='Cardio'))
        elif cardio == 2:
            return redirect(url_for('thanks_workout_2', workout_type='Cardio'))
        elif cardio == 3:
            return redirect(url_for('thanks_workout_3', workout_type='Cardio'))
        else:
            return redirect(url_for('thanks_none', workout_type='Cardio'))
        

################################# Cardio rank ####################################
@app.route('/cardio rank')
@login_required
def cardio_rank():
    ranks  = db.session.query(
        daily_cardio_workout.username,
        func.sum(daily_cardio_workout.cardio).label('total_workouts')
    ).group_by(daily_cardio_workout.username).order_by(func.sum(daily_cardio_workout.cardio).desc()).all()

    user_ranks = []
    usernames = []
    total_workouts = []

    for rank, user in enumerate(ranks, start=1):
        user_ranks.append(rank)
        usernames.append(user.username)
        total_workouts.append(user.total_workouts)

    zipped_data = zip(user_ranks, usernames, total_workouts)
    current_username = current_user.username
    current_user_rank = next((i + 1 for i, username in enumerate(usernames) if username == current_username), None)

    return render_template('/rank_tables/cardio_rank.html',  zipped_data=zipped_data, current_user_rank=current_user_rank)
   
        
###################################### Back-end data for HIIT workout page ###########################################
class daily_hiit_workout(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(10), nullable=False)
    user_lastname = db.Column(db.String(10), nullable=False)
    user_email = db.Column(db.String(10), nullable=False)
    hiit = db.Column(db.Integer, nullable=True)
    eastern_time = pytz.timezone('US/Eastern')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(tz=eastern_time))

@app.route('/workout_hiit', methods=['POST'])
@login_required
def hiit_workout_funct():
    if request.method == 'POST':
        eastern = pytz.timezone('US/Eastern')
        last_submission = daily_hiit_workout.query.filter_by(user_id=current_user.id).order_by(daily_hiit_workout.created_at.desc()).first()

        same_day = datetime.now(pytz.timezone('US/Eastern')).date()

        if last_submission and last_submission.created_at.date() == same_day:         
            return redirect(url_for('workout_sorry'))


        first_hiit_vid = int(request.form.get('first_hiit_vid', 0))
        second_hiit_vid = int(request.form.get('second_hiit_vid', 0))
        third_hiit_vid = int(request.form.get('third_hiit_vid', 0))
        
        hiit = first_hiit_vid + second_hiit_vid + third_hiit_vid

        hiit_workout = daily_hiit_workout(user_id=current_user.id, username=current_user.username, 
                                          user_lastname=current_user.last_name, user_email=current_user.user_email, hiit=hiit)
        
        db.session.add(hiit_workout)
        db.session.commit()
        
        if hiit == 1:
            return redirect(url_for('thanks_workout_1', workout_type='Hiit'))
        elif hiit == 2:
            return redirect(url_for('thanks_workout_2', workout_type='Hiit'))
        elif hiit == 3:
            return redirect(url_for('thanks_workout_3', workout_type='Hiit'))
        else:
            return redirect(url_for('thanks_none', workout_type='Hiit'))
###########################################################################################################
################################# Hiit rank ###############################################################
@app.route('/hiit rank')
@login_required
def hiit_rank():
    ranks  = db.session.query(
        daily_hiit_workout.username,
        func.sum(daily_hiit_workout.hiit).label('total_workouts')
    ).group_by(daily_hiit_workout.username).order_by(func.sum(daily_hiit_workout.hiit).desc()).all()

    user_ranks = []
    usernames = []
    total_workouts = []

    for rank, user in enumerate(ranks, start=1):
        user_ranks.append(rank)
        usernames.append(user.username)
        total_workouts.append(user.total_workouts)

    zipped_data = zip(user_ranks, usernames, total_workouts)
    current_username = current_user.username
    current_user_rank = next((i + 1 for i, username in enumerate(usernames) if username == current_username), None)

    return render_template('/rank_tables/hiit_rank.html',  zipped_data=zipped_data, current_user_rank=current_user_rank)
##################################################################################################################


# Displays a thank you message once the daily workout forms have been submitted
@app.route('/thanks_workout_1')
def thanks_workout_1():
    username = current_user.username
    workout_type = request.args.get('workout_type', '')
    return render_template('/thank_you/thanks_workout_1.html', workout_type=workout_type, username=username)

@app.route('/thanks_workout_2')
def thanks_workout_2():
    username = current_user.username
    workout_type = request.args.get('workout_type', '')
    return render_template('/thank_you/thanks_workout_2.html', workout_type=workout_type, username=username)

@app.route('/thanks_workout_3')
def thanks_workout_3():
    username = current_user.username
    workout_type = request.args.get('workout_type', '')
    return render_template('/thank_you/thanks_workout_3.html', workout_type=workout_type, username=username)

@app.route('/thanks_none')
def thanks_none():
    username = current_user.username
    workout_type = request.args.get('workout_type', '')
    return render_template('/thank_you/thanks_none.html', workout_type=workout_type, username=username)

# Displays a sorry message if user tries to submit a second form
@app.route('/sorry')
def workout_sorry():
    username = current_user.username
    workout_type = request.args.get('workout_type', '')
    return render_template('/thank_you/workout_sorry.html', workout_type=workout_type, username=username)
#################################################################################################################

############################################ Report database ####################################################

# database model to store the reports submitted by users
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(10), nullable=False)  # Remove unique=True
    user_lastname = db.Column(db.String(10), nullable=False)
    user_email = db.Column(db.String(10), nullable=False)
    problem = db.Column(db.Integer, nullable=True)
    extra = db.Column(db.Text, nullable=False)
    eastern_time = pytz.timezone('US/Eastern')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(tz=eastern_time))

@app.route('/report', methods=['POST'])
@login_required
def submit_report():
    eastern = pytz.timezone('US/Eastern')
    current_date = datetime.now(eastern).date()

    # Get the user's submission count for today
    submission_count = (
        Report.query
        .filter_by(user_id=current_user.id)
        .filter(Report.created_at >= current_date)
        .count()
    )
    # check if the user had submitted more than 2 report forms per day
    if submission_count >= 2:         
        return redirect(url_for('limit_footer', form_type='Report'))

    # check the is an input given for problem
    if 'problem' in request.form:
        # if so get it
        problem = request.form['problem']
    # otherwise
    else:
        # if there is none the problem will be set to none
        problem = 'none'
    # get the extra request from the form
    extra = request.form['extra']
    # put those input into the function
    report = Report(user_id=current_user.id, username=current_user.username, 
                    user_lastname=current_user.last_name, user_email=current_user.user_email, problem=problem, extra=extra)
    # add those to the database
    db.session.add(report)
    db.session.commit()
    # and redirects the user to a thank you page
    return redirect(url_for('thanks_report'))

@app.route('/thanks_report')
@login_required
def thanks_report():
    username = current_user.username
    return render_template('/thank_you/thanks_report.html', username=username)
##################################################################################################################

################################################ Review database #################################################

# The function and structure method for review is the same as the report page
class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(10), nullable=False)
    user_lastname = db.Column(db.String(10), nullable=False)
    user_email = db.Column(db.String(10), nullable=False)
    rating = db.Column(db.Integer, nullable=True)
    extra = db.Column(db.Text, nullable=True)
    status = db.Column(db.Text, nullable=True)
    eastern_time = pytz.timezone('US/Eastern')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(tz=eastern_time))

    # allows call on specific elements such as the rating, id of a particular comment
    def __repr__(self):
        return f"<Review id={self.id}, username={self.username}, rating={self.rating}, created_at={self.created_at}>"


# Create tables all the databases for the application when the application is run
with app.app_context():
    db.create_all()

@app.route('/review', methods=['POST'])
@login_required 
def submit_review():
    last_submission = Review.query.filter_by(user_id=current_user.id).order_by(Review.created_at.desc()).first()
    same_day = datetime.now(pytz.timezone('US/Eastern')).date()


    # allows 3 review submission per day
    if last_submission and last_submission.created_at.date() == same_day:       
        return redirect(url_for('limit_footer', form_type='Review'))

    # if user give a rating, get it
    if 'rating' in request.form:
        rating = int(request.form['rating'])
    # otherwise
    else:
        # if none is given then rating will be set to 0
        rating = 0
    
    extra = request.form['extra']

    status = request.form['status']

    review = Review(user_id=current_user.id, username=current_user.username, 
                    user_lastname=current_user.last_name, user_email=current_user.user_email, rating=rating, extra=extra, status=status)
    db.session.add(review)
    db.session.commit()
    return redirect(url_for('thanks_review'))

###################### Edit comments #########################
@app.route('/edit_comment/<int:comment_id>', methods=['GET', 'POST'])
@login_required 
def edit_comment(comment_id):
    comment = Review.query.get(comment_id)

    # check if the user owns the comment
    if comment.user_id == current_user.id:
        if request.method == 'POST':
            # Update the comment content with the form data

            # check if the user gives a rating star
            if 'edited_rating' in request.form:
                comment.rating = int(request.form['edited_rating'])
            # otherwise
            else:
            # if none is given then rating will be set to 0
                comment.rating = 0

            # gets the other updates made
            comment.extra = request.form['edited_comment']
            comment.status = request.form['edited_status']
            db.session.commit()
            return redirect(url_for('review'))
        else:
            # Render the edit comment form when the user hits edit
            return render_template('/footer/edit.html', comments=comment)
    
    return redirect(url_for('review'))

@app.route('/show_template', methods=['GET'])
@login_required
def show_template():
    return render_template('/footer/edit.html')

###################### Delete Comments #######################
@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required  
def delete_comment(comment_id):
    #Gets the comment from the database
    comment = Review.query.get(comment_id)

    # Check if the user owns comment
    if comment.user_id == current_user.id:
        # Delete the comment
        db.session.delete(comment)
        db.session.commit()
    # Redirect them back to the page
    return redirect(url_for('review'))
###############################################################

# creates a route for the review thank you page
@app.route('/thanks_review')
@login_required
def thanks_review():
    username = current_user.username
    return render_template('/thank_you/thanks_review.html', username=username)


@app.route('/form limit')
@login_required
def limit_footer():
    username = current_user.username
    form_type = request.args.get('form_type', '')
    test1 = request.args.get('test1', '')
    return render_template('/thank_you/footer_limit.html', username=username, form_type=form_type, test1=test1)
####################################################################################################################

############################################### Summary Page #######################################################
@app.route('/summary', methods=['GET', 'POST'])
@login_required
def summary():
    username = current_user.username
    
    gm_total_workouts = db.session.query(func.sum(gain_muscle_data.gain_muscle)).filter_by(username=username).scalar()
    lw_total_workouts = db.session.query(func.sum(lose_weight_data.lose_weight)).filter_by(username=username).scalar()
    yoga_total_workouts = db.session.query(func.sum(daily_yoga_workout.yoga)).filter_by(username=username).scalar()
    cardio_total_workouts = db.session.query(func.sum(daily_cardio_workout.cardio)).filter_by(username=username).scalar()
    hiit_total_workouts = db.session.query(func.sum(daily_hiit_workout.hiit)).filter_by(username=username).scalar()
    total_review = (Review.query.filter_by(user_id=current_user.id).count())
    total_report = (Report.query.filter_by(user_id=current_user.id).count())
    


    # if the user has done a specific workout yet
    if gm_total_workouts is None:
        gm_total_workouts = 0
    if lw_total_workouts is None:
        lw_total_workouts = 0
    if yoga_total_workouts is None:
       yoga_total_workouts = 0
    if cardio_total_workouts is None:
       cardio_total_workouts = 0
    if hiit_total_workouts is None:
       hiit_total_workouts = 0

    login_count = current_user.login_count
    return render_template('summary.html', username=username, gm_total_workouts=gm_total_workouts, lw_total_workouts=lw_total_workouts, 
                           yoga_total_workouts=yoga_total_workouts, cardio_total_workouts=cardio_total_workouts, 
                           hiit_total_workouts=hiit_total_workouts, login_count=login_count, total_review=total_review, total_report=total_report)



############################################### Pages routing ######################################################

@app.route("/forgot")
def forgot():
    return render_template("/login/forgot.html")

@app.route("/Home")
@login_required
def home():
    username = current_user.username
    return render_template("home.html", username=username)

@app.route('/nutrition')
@login_required
def nutrition():
    username = current_user.username
    return render_template("nutrition.html", username=username, form_data={})

@app.route("/workout_yoga")
@login_required
def workout_yoga():
    username = current_user.username
    return render_template("workout_yoga.html", videos1=yoga_videos[0], videos2=yoga_videos[1], videos3=yoga_videos[2], username=username)

@app.route("/workout_cardio")
@login_required
def workout_cardio():
    username = current_user.username
    return render_template("workout_cardio.html", videos4=cardio_videos[0], videos5=cardio_videos[1], videos6=cardio_videos[2], username=username, datetime=datetime, timedelta=timedelta)


@app.route("/workout_hiit")
@login_required
def workout_hiit():
    username = current_user.username
    return render_template("workout_hiit.html", videos7=hiit_videos[0], videos8=hiit_videos[1], videos9=hiit_videos[2], username=username)

@app.route('/acount_detail')
@login_required
def account():
    first_name = current_user.first_name
    last_name = current_user.last_name
    email = current_user.user_email
    username = current_user.username
    return render_template("/login/account.html", first_name=first_name, last_name=last_name, email=email, username=username)


# FOOTER PAGES ROUTING
@app.route('/report')
@login_required
def report():
    return render_template("/footer/report.html")

@app.route('/review')
@login_required
def review():
    all_comments = Review.query.filter((Review.status == 'public') | ((Review.status == 'private') & 
        (Review.user_id == current_user.id)), (Review.extra != '') | ((Review.user_id == current_user.id) & (Review.extra == ''))).all()
    return render_template("/footer/review.html", comment=all_comments)

@app.route('/aboutus')
@login_required
def aboutus():
    return render_template("/footer/aboutus.html")

if __name__ == '__main__':
    app.run(debug=True)

