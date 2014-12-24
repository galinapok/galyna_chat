from flask import Flask, flash, get_flashed_messages, render_template, request, redirect, url_for, abort, session, g
import sqlite3, bcrypt
import datetime
from flask.ext.socketio import SocketIO, emit
import time
from threading import Thread
import urllib2
import re
from werkzeug.contrib.fixers import ProxyFix

### WEB APP (HTTP)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'F34TF$($e34Dfff';
app.debug = True
DATABASE = 'app_db.db'
socketio = SocketIO(app)
thread = None

def connect_to_database():	
	return sqlite3.connect(DATABASE )

def connect_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = connect_to_database()
        sqlite3.enable_callback_tracebacks(True)
    return db

def get_parsed_news():
	news_html = urllib2.urlopen("https://news.ycombinator.com/newest").read()
	regex = re.compile('<td\s+class="title">(<a[^>]*>[^<]*</a>)')
	titles = regex.findall(news_html)
	titles = titles[:5]

	digest_message = ""
	for title in titles:
		digest_message = digest_message + title + '<br>'

	return digest_message

def background_thread():
	while True:
		time.sleep(15)
		#print "timer tick"
		news_message = get_parsed_news()
		socketio.emit('server message sent',
			{'user': 'bot', 'message': news_message, 'room': '*', 'time_received': str(datetime.datetime.now()) },
			namespace= '/room-socket')
		time.sleep(45)


@app.route('/')
def home():
#!!!	global thread
#	if thread is None:
#		thread = Thread(target=background_thread)
#		thread.start()

	db =  connect_db()
	cur = db.cursor()
	room_exception = ""
	create_room =""
	login_status=""
	name= ""
	cur.execute('''SELECT ID, NAME FROM ROOMS ''')
	room_all = cur.fetchall()
	#print (room_all)			
	if 'name' in session:
		name = session['name']	
	print ("session is ", session)
	if 'login_status' in session:
		login_status = session['login_status']
	exceptions = get_flashed_messages(True)				
	return render_template('index.html', login_status=login_status, name=name, exceptions=exceptions, create_room=create_room,  room_all=room_all)

@app.route('/logout-action', methods=['POST'])
def logout():
	if 'login_status' in session:	
		del session['login_status']
	if 'name' in session:
		del session['name']
	return redirect('/', code=303)

@app.route('/signup-action', methods=['POST'])
def signup_action():
	print request.form
	db =  connect_db()
	cur = db.cursor()
	session['name'] = request.form['username']
	session['email'] = request.form['email']
	password = request.form['password']
	password= bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
	exception = "";
	cur.execute('''SELECT NAME,EMAIL FROM USERS WHERE NAME=? or EMAIL=?''', (session['name'], session['email']))
	all_rows=cur.fetchall()
	print("all_rows")
	if not all_rows:
		if len(session['name'])==0:
			message = "Name cannot be empty"
			flash(message, category='error')
		elif len(session['email'])==0:
			message = "Email cannot be empty"
			flash(message, category='error')
		else:
			cur.execute('''INSERT INTO USERS(NAME, EMAIL, PASSWORD)
	                  VALUES(?,?,?)''', (session['name'], session['email'], password))
			db.commit()
			message = "You registered as "+ session['name']
			flash(message, category='ok')
	else:
		for a in all_rows:
			if session['name'] in a:
				message = "Name already exists"
				flash(message, category='error')				
			elif session['email'] in a:
				message = "email already exists"
				flash(message, category='error')	
	return redirect('/', code=303)

@app.route('/login-action', methods=['POST'])
def signup():
	print request.form
	db =  connect_db()
	cur = db.cursor()
	session['name'] = request.form['username']
	password = request.form['password']
	password = password.encode('utf-8')
	cur.execute('''SELECT PASSWORD FROM USERS WHERE NAME=? ''', (session['name'],)) 
	db_hashed_password_all=cur.fetchone()
	if db_hashed_password_all and db_hashed_password_all is not None:
		db_hashed_password=db_hashed_password_all[0]
	else:
		db_hashed_password=""
	
	if not db_hashed_password:
		message ="Wrong user name"
		flash(message, category='error')					
	elif bcrypt.hashpw(password, db_hashed_password.encode('utf-8')) == db_hashed_password:		
		session['login_status']="Your are now logged on"
		return redirect ("/", code=303)		
	else: 
		message="Wrong password"
		flash(message, category='error')
	return redirect ("/login", code=303)

@app.route('/login')
def signup2():
	login_errors = get_flashed_messages(True)
	return render_template('login.html', login_errors=login_errors)


@app.route('/create-room-action', methods=['POST'])
def create_room():
	print('redirect2')
	db =  connect_db()
	cur = db.cursor()
	print(request.form)

	session['room_name'] = request.form['room_name']
	if 'create_new' in request.form:
		session['create_new'] = request.form['create_new']
	print('redirect1')
	exception = "";
	if session['room_name'] : 
		cur.execute('''SELECT NAME FROM ROOMS WHERE NAME=? ''', (session['room_name'],))
		all_rows=cur.fetchall()
		if 'create_new' in session and not all_rows:
			cur.execute('''INSERT INTO ROOMS(NAME)
			          VALUES(?)''', (session['room_name'],))
			db.commit()
			message = "Room succesfully created"
			flash(message, category='ok')
		elif 'create_new' in session:
			message = "Room already exists"
			flash(message, category='error')
		print('redirect')
	if 'create_new' in session:
		del session['create_new']
	return redirect ("/", code=303)


@app.route('/room-delete-action',  methods=['POST'])
def room_delete_action():
	db =  connect_db()
	cur = db.cursor()
	print ('room-delete-action ', request.form)		
	for room_delete in request.form.getlist('room_delete'):
		
		
		print ('room-delete-action2 ', room_delete)
		cur.execute('''DELETE FROM ROOMS WHERE ID=? ''',  (room_delete,))
		db.commit()
	return redirect ("/", code=303)	

@app.route('/room/<path:name>')
def room(name):
	if 'login_status' in session:
		return render_template('room.html', room_name=name)
	else:
		message = "You need to login"
		flash(message, category='error')
		return redirect ("/", code=303)

### WEB APP (socket io)

@socketio.on('client message sent', namespace= '/room-socket')
def clent_message_receive(message):  
	# TODO: here we save client message later
    if 'name' in session:
		name = session['name']	
    emit('server message sent',
         {'user': name, 'message': message['data'], 'room': message['room'], 'time_received': str(datetime.datetime.now()) },
         broadcast=True)

### WEB APP (static)
@app.route('/static/<path:filename>')
def send_foo(filename):
    return send_from_directory('static', filename)

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:	
    	db.close()
    	
#app.wsgi_app = ProxyFix(app.wsgi_app)

if __name__ == '__main__':
    app.run(debug=True)
    #!!!socketio.run(app)

