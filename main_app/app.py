from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import os
import pandas as pd
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import plaid
from plaid.api import plaid_api
from plaid.model.link_token_create_request import LinkTokenCreateRequest
from plaid.model.products import Products
from plaid.model.country_code import CountryCode
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.transactions_sync_request import TransactionsSyncRequest
import os
from dotenv import load_dotenv
from plaid import ApiClient, Configuration, Environment



app = Flask(__name__)

# Load environment variables from .env file
load_dotenv()

# Set up Plaid API credentials
client_id = os.getenv('PLAID_CLIENT_ID')
key = os.getenv('PLAID_SECRET')
if not client_id or not key:
    raise ValueError("PLAID_CLIENT_ID and PLAID_SECRET must be set in the environment variables.")

#Plaid API configuration
config = Configuration(
            host=Environment.Sandbox,
            api_key={
                'clientId': client_id,
                'secret': key,
            }
)


api_client = plaid.ApiClient(config)
client = plaid_api.PlaidApi(api_client)


app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('DB_SECRET', 'default_secret_key')
db = SQLAlchemy(app)

#User model for the database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False)
    plaid_access_token = db.Column(db.String(200), nullable=True)

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')
    
@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'uid' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['uid'])
    if user.plaid_access_token:
        return render_template('dashboard.html')
    return render_template('plaid_connect.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method=='POST':
        username=request.form['username']
        password=generate_password_hash(request.form['password'])
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return 'User already exists!'
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method=='POST':
        username=request.form['username']
        password=request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['uid'] = user.id
            return redirect(url_for('dashboard'))
        else:
            return 'Invalid credentials!'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/api/create_link_token', methods=['POST'])
def create_link_token():

    request = LinkTokenCreateRequest(
        client_name='Plaid Test App',
        products=[Products('transactions')],
        country_codes=[CountryCode('US')],
        language='en',
        user={
            'client_user_id': 'user-id'
        }
    )

    response = client.link_token_create(request)
    return jsonify(response.to_dict())

@app.route('/api/exchange_public_token', methods=['POST'])
def exchange_public_token():
    if 'uid' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    public_token = request.json['public_token']
    exchange_request = ItemPublicTokenExchangeRequest(
        public_token=public_token
    )
    exchange_response = client.item_public_token_exchange(exchange_request)
    access_token = exchange_response.access_token
    user = User.query.get(session['uid'])
    user.plaid_access_token = access_token
    db.session.commit()
    return jsonify({
        'access_token': access_token
    })

@app.route('/api/transactions', methods=['POST'])
def get_transactions():
    if 'uid'not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = User.query.get(session['uid'])

    if not user or not user.plaid_access_token:
        return jsonify({'error': 'No access token found'}), 400
    
    access_token = user.plaid_access_token
    sync_request = TransactionsSyncRequest(access_token=access_token)
    sync_response = client.transactions_sync(sync_request)
    transactions = [txn.to_dict() for txn in sync_response.added]
    return jsonify(transactions)

if __name__ == '__main__':
    app.run(debug=True)


