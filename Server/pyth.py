# import asyncio
# import websockets

# active_connections = {}

# async def handle_connection(websocket, path):
#     print('A user connected')

#     async for message in websocket:
#         data = message.split(':')
#         event = data[0]
#         peer_id = data[1]

#         if event == 'offer':
#             offer = data[2]
#             await send_offer(peer_id, offer, websocket)
#         elif event == 'answer':
#             answer = data[2]
#             await send_answer(peer_id, answer, websocket)
#         elif event == 'ice-candidate':
#             candidate = data[2]
#             await send_ice_candidate(peer_id, candidate, websocket)

#     print('A user disconnected')
#     active_connections.pop(websocket, None)

# async def send_offer(peer_id, offer, sender_websocket):
#     peer_websocket = active_connections.get(peer_id)
#     if peer_websocket:
#         await peer_websocket.send(f'offer:{sender_websocket}:{offer}')

# async def send_answer(peer_id, answer, sender_websocket):
#     peer_websocket = active_connections.get(peer_id)
#     if peer_websocket:
#         await peer_websocket.send(f'answer:{sender_websocket}:{answer}')

# async def send_ice_candidate(peer_id, candidate, sender_websocket):
#     peer_websocket = active_connections.get(peer_id)
#     if peer_websocket:
#         await peer_websocket.send(f'ice-candidate:{sender_websocket}:{candidate}')

# async def main():
#     server = await websockets.serve(handle_connection, 'localhost', 3000)

#     async for websocket, _ in server.connections:
#         active_connections[websocket] = websocket

#     print(f'Server listening on port 3000')
#     await asyncio.Future()  # Run indefinitely

# if __name__ == '__main__':
#     asyncio.run(main())
