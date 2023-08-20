// const express = require('express');
// const http = require('http');
// const socketIo = require('socket.io');

// const app = express();
// const server = http.createServer(app);
// const io = socketIo(server);

// const PORT = 3000;

// // Serve HTML file
// app.get('/', (req, res) => {
//   res.sendFile(__dirname + '/index.html');
// });

// // Handle socket connections
// io.on('connection', (socket) => {
//   console.log('A user connected');

//   // Handle offer and answer exchange
//   socket.on('offer', (offer, peerId) => {
//     socket.to(peerId).emit('offer', offer, socket.id);
//   });

//   socket.on('answer', (answer, peerId) => {
//     socket.to(peerId).emit('answer', answer, socket.id);
//   });

//   // Handle ice candidate exchange
//   socket.on('ice-candidate', (candidate, peerId) => {
//     socket.to(peerId).emit('ice-candidate', candidate, socket.id);
//   });

//   // Handle disconnection
//   socket.on('disconnect', () => {
//     console.log('A user disconnected');
//   });
// });

// server.listen(PORT, () => {
//   console.log(`Server listening on port ${PORT}`);
// });
