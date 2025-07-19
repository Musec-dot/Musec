const express = require('express');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
require('dotenv').config();
const { v4: uuidv4 } = require('uuid')
const User = require('./user');
const music = require('./music');
const friendRoutes = require('./routes/friendRoutes');
const Message = require('./models/Message');
const LiveStream = require('./liveStream')
const app = express();
const server = http.createServer(app);
const io = new Server(server);


app.set('view engine', 'ejs');
app.set('views', path.resolve('./'));

app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));

mongoose.connect('mongodb+srv://microsoftrishik:Kathikebab-14@musec.1atpodc.mongodb.net/', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log(' Connected to MongoDB Atlas'))
  .catch(err => console.error(' MongoDB connection error:', err));


const secret = 'rishik@123';

function setUser(user) {
  return jwt.sign({
    _id: user._id,
    email: user.email,
    role: user.role,
    username: user.username
  }, secret);
}

function getUser(token) {
  if (!token) return null;
  try {
    return jwt.verify(token, secret);
  } catch (err) {
    return null;
  }
}


async function check(req, res, next) {
  const token = req.cookies?.uid;
  if (!token) {
    req.user = null;
    return next();
  }
  try {
    const decoded = jwt.verify(token, secret);
    const fullUser = await User.findById(decoded._id).populate('friends');
    req.user = fullUser;
  } catch (err) {
    req.user = null;
  }
  next();
}

app.use(check);

const streamBroadcasters = {}; 
io.on("connection", (socket) => {
  console.log(" A user connected");

  socket.on("joinRoom", ({ userId, friendId }) => {
    const room = [userId, friendId].sort().join("_");
    socket.join(room);
  });
  

  socket.on("sendMessage", async ({ from, to, content }) => {
    const newMsg = await Message.create({ from, to, content });
    const room = [from, to].sort().join("_");
    io.to(room).emit("newMessage", newMsg);
  });
   socket.on('broadcaster', ({ streamId }) => {
    streamBroadcasters[streamId] = socket.id;
    socket.join(streamId);
  });

  socket.on('watcher', ({ streamId }) => {
    const bId = streamBroadcasters[streamId];
    if (bId) io.to(bId).emit('watcher', socket.id);
  });

  socket.on('offer', (id, desc)   => io.to(id).emit('offer', socket.id, desc));
  socket.on('answer', (id, desc)  => io.to(id).emit('answer', socket.id, desc));
  socket.on('candidate', (id, c)  => io.to(id).emit('candidate', socket.id, c));

  socket.on('disconnect', () => {

    socket.broadcast.emit('disconnectPeer', socket.id);
    
    for (const [sid, sockId] of Object.entries(streamBroadcasters))
      if (sockId === socket.id) delete streamBroadcasters[sid];
  });
  socket.on("disconnect", () => {
    socket.broadcast.emit("disconnectPeer", socket.id);
  });

 
});


app.use('/requests', friendRoutes);

app.get('/', async (req, res) => {
  if (!req.user) return res.render('home');

  const liveStreams = await LiveStream.find({ isLive: true }).populate('streamer');
  const allUsers    = await User.find({});

  res.render('dashboard', {
    name:  req.user.username,
    friends: req.user.friends,
    allUsers,
    liveStreams
  });
});
app.get('/go-live', async (req, res) => {
  if (!req.user) return res.redirect('/login');
  let existing = await LiveStream.findOne({ streamer: req.user._id, isLive: true });
  const streamId = existing ? existing.streamId : uuidv4();

  if (!existing) {
    await LiveStream.create({ streamId, streamer: req.user._id });
  }
  res.redirect(`/live/${streamId}`);
});
app.get('/live/:streamId', async (req, res) => {
  const stream = await LiveStream.findOne({ streamId: req.params.streamId, isLive: true })
                   .populate('streamer');
  if (!stream || stream.streamer._id.toString() !== req.user._id.toString())
    return res.status(403).send('Not your stream or stream ended');
  res.render('live', { stream });
});
app.get('/watch/:streamId', async (req, res) => {
  const stream = await LiveStream.findOne({ streamId: req.params.streamId, isLive: true })
                   .populate('streamer');
  if (!stream) return res.status(404).send('Stream not found');
  res.render('watch', { stream });
});
app.post('/end-stream', async (req, res) => {
  await LiveStream.findOneAndUpdate(
    { streamer: req.user._id, isLive: true },
    { isLive: false }
  );
  res.redirect('/');
});
app.get('/signup', (req, res) => {
  res.render('signup');
});

app.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const user = new User({ username, email, password });
    await user.save();
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.render('signup', { err });
  }
});

app.get('/login', (req, res) => {
  if (!req.user) return res.render('login');
  res.redirect('/');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.render('login', { error: 'Invalid credentials' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.render('login', { error: 'Invalid credentials' });

  const token = setUser(user);
  res.cookie('uid', token, { httpOnly: true });
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  res.clearCookie('uid');
  res.redirect('/login');
});

app.get('/signup-music', (req, res) => {
  res.render('music_signup');
});

app.post('/signup-music', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const musician = new music({ name, email, password, role: role || undefined });
    await musician.save();
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.render('music_signup', { err });
  }
});


app.get("/chat/:friendId", async (req, res) => {
  const friendId = req.params.friendId;
  const messages = await Message.find({
    $or: [
      { from: req.user._id, to: friendId },
      { from: friendId, to: req.user._id }
    ]
  }).sort({ timestamp: 1 }).populate('from');

  const friend = await User.findById(friendId);
  res.render("chat", {
    friend,
    messages,
    me: req.user._id
  });
});
app.get('/update-profile', async (req, res) => {
  if (!req.user) return res.redirect('/login');
  res.render('user_profile', { user: req.user });
});

app.post('/update-profile', async (req, res) => {
  const { genres, instruments, city, country } = req.body;

  await User.findByIdAndUpdate(req.user._id, {
    genres: Array.isArray(genres) ? genres : [genres],
    instruments: Array.isArray(instruments) ? instruments : [instruments],
    city,
    country
  });

  res.redirect('/');
});
app.get('/live', (req, res) => {
  if (!req.user) return res.redirect('/login');
  res.render('live', { user: req.user });
});
app.get('/watch', (req, res) => {
  if (!req.user) return res.redirect('/login');
  res.render('watch', { user: req.user });
});

const PORT = process.env.PORT || 8000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

