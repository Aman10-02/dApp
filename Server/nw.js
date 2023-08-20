// const socket = io.connect('http://localhost:3000');

// const peerConnections = {};

// // Function to create a new peer connection
// function createPeerConnection(peerId) {
//   const peerConnection = new RTCPeerConnection();

//   peerConnection.ondatachannel = (event) => {
//     const dataChannel = event.channel;
//     dataChannel.onmessage = (event) => {
//       console.log(`Received data: ${event.data}`);
//       // Process the received block data and update the blockchain
//     };
//   };

//   // Add more configuration to the peer connection as needed

//   peerConnections[peerId] = peerConnection;
// }

// socket.on('connect', () => {
//   console.log('Connected to signaling server');
// });

// // Handle offer and answer exchange
// socket.on('offer', (offer, peerId) => {
//   const peerConnection = createPeerConnection(peerId);

//   peerConnection.setRemoteDescription(new RTCSessionDescription(offer));
//   // Create an answer
//   peerConnection.createAnswer()
//     .then(answer => {
//       peerConnection.setLocalDescription(answer);
//       socket.emit('answer', answer, peerId);
//     })
//     .catch(error => {
//       console.error('Error creating answer:', error);
//     });
// });

// socket.on('answer', (answer, peerId) => {
//   const peerConnection = peerConnections[peerId];
//   if (peerConnection) {
//     peerConnection.setRemoteDescription(new RTCSessionDescription(answer));
//   }
// });

// // Handle ice candidate exchange
// socket.on('ice-candidate', (candidate, peerId) => {
//   const peerConnection = peerConnections[peerId];
//   if (peerConnection) {
//     peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
//   }
// });
