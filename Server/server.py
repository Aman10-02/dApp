import os
import urllib.request
import ipfshttpclient
from my_constants import app, socketio
import pyAesCrypt
from flask import Flask, flash, request, redirect, render_template, url_for, jsonify
from flask_socketio import SocketIO, send, emit
from werkzeug.utils import secure_filename
from web3storage import Client
# import socket
import pickle
from blockchain import Blockchain
import requests

# The package requests is used in the 'hash_user_file' and 'retrieve_from hash' functions to send http post requests.
# Notice that 'requests' is different than the package 'request'.
# 'request' package is used in the 'add_file' function for multiple actions.

# socketio = SocketIO(app)
blockchain = Blockchain()

async def replace_chain():
    network = blockchain.nodes
    longest_chain = None
    max_length = len(blockchain.chain)

    def res(data) :
        print("data", data)
        nonlocal longest_chain, max_length
        length = data['length']
        chain = data['chain']
        if length > max_length and blockchain.validate_blockchain(chain):
            print("inside")
            max_length = length
            blockchain.chain = chain
    
    for node in network:
        socketio.emit('get_chain', {}, room = node, callback = res)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def append_file_extension(uploaded_file, file_path):
    file_extension = uploaded_file.filename.rsplit('.', 1)[1].lower()
    user_file = open(file_path, 'a')
    user_file.write('\n' + file_extension)
    user_file.close()

def decrypt_file(file_path, file_key):
    encrypted_file = file_path + ".aes"
    os.rename(file_path, encrypted_file)
    pyAesCrypt.decryptFile(encrypted_file, file_path,  file_key, app.config['BUFFER_SIZE'])

def encrypt_file(file_path, file_key):
    pyAesCrypt.encryptFile(file_path, file_path + ".aes",  file_key, app.config['BUFFER_SIZE'])

def hash_user_file(user_file, file_key):
    encrypt_file(user_file, file_key)
    encrypted_file_path = user_file + ".aes"
    # client = ipfshttpclient.connect('/dns/ipfs.infura.io/tcp/5001/https')
    client = Client(api_key = app.config['KEY'] )
    response = client.upload_file(encrypted_file_path)
    print("response", response)
    file_hash = response['cid']
    return file_hash

async def retrieve_from_hash(file_hash, file_key):
    # client = ipfshttpclient.connect('/dns/ipfs.infura.io/tcp/5001/https')
    # client = Client(api_key = app.config['KEY'] )
    # file_content = client.download(file_hash)
    response = requests.get(f'https://{file_hash}.ipfs.dweb.link') # add error handelling
    file_content = response.content

    file_path = os.path.join("./downloads", file_hash)
    # file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], file_hash)
    user_file = open(file_path, 'wb')
    user_file.write(file_content)
    user_file.close()
    decrypt_file(file_path, file_key)
    with open(file_path, 'rb') as f:
        lines = f.read().splitlines()
        last_line = lines[-1]
    user_file.close()
    file_extension = last_line
    saved_file = file_path + '.' + file_extension.decode()
    os.rename(file_path, saved_file)
    print(saved_file)
    return saved_file

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/upload')
def upload():
    return render_template('upload.html' , message = "Welcome!")

@app.route('/download')
def download():
    return render_template('download.html' , message = "Welcome!")

@app.route('/connect_blockchain')
async def connect_blockchain():
    print("con")
    await replace_chain()
    return render_template('connect_blockchain.html', chain = blockchain.chain, nodes = len(blockchain.nodes))

@app.errorhandler(413)
def entity_too_large(e):
    return render_template('upload.html' , message = "Requested Entity Too Large!")

@app.route('/add_file', methods=['POST'])
async def add_file():
    if request.method == 'POST':
        error_flag = True
        if 'file' not in request.files:
            message = 'No file part'
        else:
            user_file = request.files['file']
            if user_file.filename == '':
                message = 'No file selected for uploading'

            if user_file and allowed_file(user_file.filename):
                error_flag = False
                filename = secure_filename(user_file.filename)
                # file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file_path = os.path.join("./uploads", filename)
                user_file.save(file_path)
                append_file_extension(user_file, file_path)
                sender = request.form['sender_name']
                receiver = request.form['receiver_name']
                file_key = request.form['file_key']

                try:
                    hashed_output1 = hash_user_file(file_path, file_key)
                    # index = blockchain.add_file(sender, receiver, hashed_output1)
                    index = blockchain.create_block(sender, receiver, hashed_output1)
                    socketio.emit('update_chain', {"chain" : blockchain.chain})
                except Exception as err:
                    message = str(err)
                    error_flag = True
                    if "ConnectionError:" in message:
                        message = "Gateway down or bad Internet!"

            else:
                error_flag = True
                message = 'Allowed file types are txt, pdf, png, jpg, jpeg, gif'
    
        if error_flag == True:
            return render_template('upload.html' , message = message)
        else:
            return render_template('upload.html' , message = "File succesfully uploaded")

@app.route('/retrieve_file', methods=['POST'])
async def retrieve_file():

    if request.method == 'POST':

        error_flag = True

        if request.form['file_hash'] == '':
            message = 'No file hash entered.'
        elif request.form['file_key'] == '':
            message = 'No file key entered.'
        else:
            error_flag = False
            file_key = request.form['file_key']
            file_hash = request.form['file_hash']
            try:
                file_path = await retrieve_from_hash(file_hash, file_key)
            except Exception as err:
                message = str(err)
                error_flag = True
                if "ConnectionError:" in message:
                    message = "Gateway down or bad Internet!"

        if error_flag == True:
            return render_template('download.html' , message = message)
        else:
            return render_template('download.html' , message = "File successfully downloaded")

# Getting the full Blockchain
@app.route('/get_chain', methods = ['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200




# def add_node(client_node):
    

def remove_node(client_node):
    blockchain.nodes.remove(client_node)
    socketio.emit('my_response', {'data': pickle.dumps(blockchain.nodes)})


@socketio.on('connect')
def connect():
    print(f"A user connected: {request.sid}")
    print("requests", request.sid)
    socketio.emit('me', {"id":request.sid}, room = request.sid)
    # add_node(request.sid)

@socketio.on('add_client')
def add_client(data):
    key = data.get("key")
    userName = data.get("userName")
    blockchain.clients[userName] = key
    blockchain.nodes.add(request.sid)
    socketio.emit('my_response', {'nodes': pickle.dumps(blockchain.nodes), "clients" : blockchain.clients})



@socketio.on('disconnect')
def disconnect():
    print(f"A user disconnected: {request.sid}")
    remove_node(request.sid)

@socketio.on('set_chain')
def set_chain(data):
    chain = blockchain.chain
    newchain = data.get("chain")
    # if len(chain) < len(newchain) and blockchain.is_chain_valid(newchain):
    if len(chain) < len(newchain) and blockchain.validate_blockchain(newchain):
        blockchain.chain = newchain
        socketio.emit('update_chain', {"chain" : blockchain.chain})
        return {"flag" : True }
    return {"flag" : False }


if __name__ == '__main__':
    # socketio.run(app, "https://eed5-14-139-196-13.ngrok-free.app", debug=True)
    socketio.run(app, host = '127.0.0.1', port= 5111, debug=True)