# from server2 
import socketio

# Create a Socket.IO server instance
# socketio = socketio.Server(cors_allowed_origins='*')

active_connections = {}

@socketio.on('connect')
def connect(sid):
    print(f"A user connected: {sid}")
    active_connections[sid] = sid

@socketio.on('disconnect')
def disconnect(sid):
    print(f"A user disconnected: {sid}")
    active_connections.pop(sid, None)

@socketio.on('message')
def handle_message(sid, data):
    print(f"Received message from {sid}: {data}")
    event, peer_id, payload = data.split(':')

    if event == 'offer':
        send_offer(peer_id, payload, sid)
    elif event == 'answer':
        send_answer(peer_id, payload, sid)
    elif event == 'ice-candidate':
        send_ice_candidate(peer_id, payload, sid)

def send_offer(peer_id, offer, sender_sid):
    peer_sid = active_connections.get(peer_id)
    if peer_sid:
        socketio.emit('message', f'offer:{sender_sid}:{offer}', room=peer_sid)

def send_answer(peer_id, answer, sender_sid):
    peer_sid = active_connections.get(peer_id)
    if peer_sid:
        socketio.emit('message', f'answer:{sender_sid}:{answer}', room=peer_sid)

def send_ice_candidate(peer_id, candidate, sender_sid):
    peer_sid = active_connections.get(peer_id)
    if peer_sid:
        socketio.emit('message', f'ice-candidate:{sender_sid}:{candidate}', room=peer_sid)


