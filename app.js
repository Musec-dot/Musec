const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
require('dotenv').config();
const { v4: uuidv4 } = require('uuid');

const User = require('./user');
const music = require('./music');
const friendRoutes = require('./routes/friendRoutes');
const Message = require('./models/Message');
const LiveStream = require('./liveStream');
const Post = require('./models/Post');
const Comment = require('./models/Comment');
const Job = require('./models/Job');
const Application = require('./models/Application');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const userSocketMap = new Map();

// Middleware & Config
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads'))); // serve uploaded files
app.set('view engine', 'ejs');
app.set('views', path.resolve('./'));
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));

// MongoDB Connection
mongoose.connect('mongodb+srv://microsoftrishik:Kathikebab-14@musec.1atpodc.mongodb.net/', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('Connected to MongoDB Atlas'))
  .catch(err => console.error('MongoDB connection error:', err));

// JWT Auth
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

// Multer Setup
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});

const fileFilter = (req, file, cb) => {
  const allowed = /jpeg|jpg|png|gif|mp4|mov|mp3|wav|avi/;
  const ext = (path.extname(file.originalname) || '').toLowerCase().slice(1);
  if (allowed.test(ext)) {
    cb(null, true);
  } else {
    cb(new Error('Unsupported file type'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB max
});

// Routes
app.post('/new', upload.single('media'), async (req, res) => {
  if (!req.user) return res.redirect('/login');

  try {
    const { title } = req.body;
    let fileUrl = null;
    let fileType = null;

    if (req.file) {
      const mimeMain = req.file.mimetype.split('/')[0];
      if (['image', 'video', 'audio'].includes(mimeMain)) {
        fileType = mimeMain;
        fileUrl = '/uploads/' + req.file.filename;
      }
    }

    await Post.create({
      author: req.user._id,
      title,
      content: '',
      fileUrl,
      fileType
    });

    res.redirect('/');
  } catch (err) {
    console.error('Post upload error:', err);
    res.status(500).send('File upload failed');
  }
});

app.use('/requests', friendRoutes);

// Like/Unlike Post
app.post('/post/:postId/like', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  
  try {
    const post = await Post.findById(req.params.postId);
    if (!post) return res.status(404).json({ error: 'Post not found' });
    
    // Initialize likes array if it doesn't exist
    if (!post.likes) {
      post.likes = [];
    }
    
    const userId = req.user._id;
    const isLiked = post.likes.some(likeId => likeId.toString() === userId.toString());
    
    if (isLiked) {
      post.likes = post.likes.filter(likeId => likeId.toString() !== userId.toString());
    } else {
      post.likes.push(userId);
    }
    
    await post.save();
    res.json({ 
      success: true, 
      likesCount: post.likes.length, 
      isLiked: !isLiked 
    });
  } catch (err) {
    console.error('Like error:', err);
    res.status(500).json({ error: 'Failed to like post' });
  }
});

// Add Comment
app.post('/post/:postId/comment', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  
  try {
    const { content } = req.body;
    if (!content || !content.trim()) {
      return res.status(400).json({ error: 'Comment content is required' });
    }
    
    const post = await Post.findById(req.params.postId);
    if (!post) return res.status(404).json({ error: 'Post not found' });
    
    const comment = await Comment.create({
      post: req.params.postId,
      author: req.user._id,
      content: content.trim()
    });
    
    const commentWithAuthor = await Comment.findById(comment._id).populate('author', 'username profilePic');
    
    res.json({ 
      success: true, 
      comment: commentWithAuthor 
    });
  } catch (err) {
    console.error('Comment error:', err);
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

// Get Comments for a Post
app.get('/post/:postId/comments', async (req, res) => {
  try {
    const comments = await Comment.find({ post: req.params.postId })
      .populate('author', 'username profilePic')
      .sort({ createdAt: -1 });
    
    res.json({ comments });
  } catch (err) {
    console.error('Get comments error:', err);
    res.status(500).json({ error: 'Failed to get comments' });
  }
});
// Hirer Signup
app.post('/signup-hirer', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    const user = new User({ username, email, password, role: role || 'hirer' });
    await user.save();
    const token = setUser(user);
    res.cookie('uid', token, { httpOnly: true });
    res.redirect('/post-job');
  } catch (err) {
    console.error(err);
    res.render('home', { error: 'Signup failed. Email or username may already exist.' });
  }
});

// Job Posting Routes
app.get('/post-job', async (req, res) => {
  if (!req.user) return res.redirect('/login');
  if (req.user.role !== 'hirer') return res.redirect('/');
  res.render('post-job');
});

app.post('/post-job', async (req, res) => {
  if (!req.user) return res.redirect('/login');
  if (req.user.role !== 'hirer') return res.redirect('/');
  
  try {
    const { title, description, payment, location, genre, instrument } = req.body;
    await Job.create({
      title,
      description,
      payment,
      location,
      genre,
      instrument,
      hirer: req.user._id
    });
    res.redirect('/hirer/jobs');
  } catch (err) {
    console.error(err);
    res.render('post-job', { error: 'Failed to post job' });
  }
});

// View All Jobs (for musicians)
app.get('/jobs', async (req, res) => {
  // Redirect hirers to their jobs page
  if (req.user && req.user.role === 'hirer') {
    return res.redirect('/hirer/jobs');
  }
  
  const jobs = await Job.find({ status: 'open' })
    .populate('hirer', 'username')
    .sort({ createdAt: -1 });
  res.render('jobs', { jobs, user: req.user });
});

// Job Details
app.get('/jobs/:id', async (req, res) => {
  try {
    const job = await Job.findById(req.params.id)
      .populate('hirer', 'username')
      .populate('selectedMusician', 'username')
      .populate('selectedApplication');
    if (!job) return res.status(404).send('Job not found');
    res.render('job-details', { job, user: req.user });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Application Form
app.get('/form/:jobId', async (req, res) => {
  if (!req.user) return res.redirect('/login');
  try {
    const job = await Job.findById(req.params.jobId);
    if (!job) return res.status(404).send('Job not found');
    res.render('form', { job, user: req.user });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Submit Application
app.post('/apply/:jobId', async (req, res) => {
  if (!req.user) return res.redirect('/login');
  
  try {
    const job = await Job.findById(req.params.jobId);
    if (!job) return res.status(404).send('Job not found');
    
    // Check if already applied
    const existing = await Application.findOne({ job: req.params.jobId, musician: req.user._id });
    if (existing) {
      return res.render('form', { job, user: req.user, error: 'You have already applied for this job' });
    }
    
    await Application.create({
      job: req.params.jobId,
      musician: req.user._id,
      ...req.body
    });
    
    res.redirect('/jobs');
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to submit application');
  }
});

// Hirer's Jobs
app.get('/hirer/jobs', async (req, res) => {
  if (!req.user) return res.redirect('/login');
  if (req.user.role !== 'hirer') return res.redirect('/');
  
  const jobs = await Job.find({ hirer: req.user._id })
    .populate('selectedMusician', 'username')
    .sort({ createdAt: -1 });
  res.render('hirer-jobs', { jobs, user: req.user });
});

// View Applications for a Job
app.get('/applications/:jobId', async (req, res) => {
  if (!req.user) return res.redirect('/login');
  
  try {
    const job = await Job.findById(req.params.jobId).populate('hirer', 'username').populate('selectedApplication').populate('selectedMusician', 'username');
    if (!job) return res.status(404).send('Job not found');
    
    // Check if user is the hirer
    if (job.hirer._id.toString() !== req.user._id.toString()) {
      return res.status(403).send('Unauthorized');
    }
    
    const applications = await Application.find({ job: req.params.jobId })
      .populate('musician', 'username profilePic email')
      .sort({ createdAt: -1 });
    
    res.render('applications', { job, applications, user: req.user });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Select an Application
app.post('/applications/:applicationId/select', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  
  try {
    const application = await Application.findById(req.params.applicationId)
      .populate('job');
    
    if (!application) return res.status(404).json({ error: 'Application not found' });
    
    const job = await Job.findById(application.job._id);
    if (!job) return res.status(404).json({ error: 'Job not found' });
    
    // Check if user is the hirer
    if (job.hirer.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Check if job already has someone selected
    if (job.selectedApplication || job.selectedMusician) {
      return res.status(400).json({ error: 'This job already has a selected applicant' });
    }
    
    // Update all other applications for this job to 'rejected'
    await Application.updateMany(
      { job: job._id, _id: { $ne: application._id } },
      { status: 'rejected' }
    );
    
    // Mark this application as selected
    application.status = 'selected';
    await application.save();
    
    // Update job with selected application and musician
    job.selectedApplication = application._id;
    job.selectedMusician = application.musician;
    job.status = 'closed'; // Close the job
    await job.save();
    
    res.json({ success: true, message: 'Application selected successfully' });
  } catch (err) {
    console.error('Select application error:', err);
    res.status(500).json({ error: 'Failed to select application' });
  }
});
app.get('/msg', (req, res) => {
  if (!req.user) return res.redirect('/login');
  res.render('msg', {
    friends: req.user.friends,
    me: req.user._id.toString(),
    user: req.user
  });
});
app.get('/form',(req,res)=>{
  res.render('form'); 
})
async function renderDashboard(req, res) {
  if (!req.user) return res.render('home');

  const liveStreams = await LiveStream.find({ isLive: true }).populate('streamer');
  const allUsers = await User.find({});
  const unreadMessages = await Message.find({ to: req.user._id, seen: false });
  const posts = await Post.find({}).populate('author').sort({ createdAt: -1 });
  
  // Get comments for all posts and check if user liked each post
  const postsWithData = await Promise.all(posts.map(async (post) => {
    const comments = await Comment.find({ post: post._id })
      .populate('author', 'username profilePic')
      .sort({ createdAt: -1 })
      .limit(3); // Get latest 3 comments for preview
    
    const isLiked = post.likes && post.likes.length > 0 
      ? post.likes.some(likeId => likeId.toString() === req.user._id.toString())
      : false;
    
    return {
      ...post.toObject(),
      likes: post.likes || [],
      commentsCount: await Comment.countDocuments({ post: post._id }),
      recentComments: comments,
      isLiked
    };
  }));

  res.render('dashboard', {
    name: req.user.username,
    friends: req.user.friends,
    allUsers,
    liveStreams,
    user: req.user,
    posts: postsWithData,
    hasUnreadMessages: unreadMessages.length > 0
  });
}

app.get('/', renderDashboard);
app.get('/dashboard', renderDashboard);

// Explore Musicians
app.get('/explore-musicians', async (req, res) => {
  if (!req.user) return res.redirect('/');
  const allUsers = await User.find({});
  res.render('explore-musicians', {
    allUsers,
    user: req.user
  });
});

// Live Streams
app.get('/live-streams', async (req, res) => {
  if (!req.user) return res.redirect('/');
  const liveStreams = await LiveStream.find({ isLive: true }).populate('streamer');
  res.render('live-streams', {
    liveStreams,
    user: req.user
  });
});

// Chat
app.get("/messages/:friendId", async (req, res) => {
  const friendId = req.params.friendId;

  // Mark unseen messages as seen
  await Message.updateMany(
    { from: friendId, to: req.user._id, seen: false },
    { $set: { seen: true } }
  );

  // Fetch conversation
  const messages = await Message.find({
    $or: [
      { from: req.user._id, to: friendId },
      { from: friendId, to: req.user._id }
    ]
  })
    .sort({ timestamp: 1 })
    .populate("from");

  const friend = await User.findById(friendId);

  res.json({
    me: req.user._id.toString(),
    friend: {
      _id: friend._id,
      username: friend.username
    },
    messages
  });
});

// Auth
app.get('/signup', (req, res) => res.render('create_account'));
app.get('/signup/password', (req, res) => res.render('create_account_pass'));
app.get('/signup/name', (req, res) => res.render('name'));

app.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const user = new User({ username, email, password });
    await user.save();
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.render('create_account', { err });
  }
});

app.get('/login', (req, res) => {
  if (!req.user) return res.render('login');
  res.redirect('/');
});
app.get("/user/:id", async (req, res) => {
  try {
    const userId = req.params.id;
    
    // Get the specific user
    const user = await User.findById(userId);

    // Get that user's posts (same structure as dashboard posts)
    const posts = await Post.find({ author: userId })
      .populate("author")
      .sort({ createdAt: -1 });

    res.render("bio", {
      user,
      posts
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
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

app.get('/signup-music', (req, res) => res.render('music_signup'));

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

// Profile
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

// Live Stream
app.get('/go-live', async (req, res) => {
  if (!req.user) return res.redirect('/login');
  let existing = await LiveStream.findOne({ streamer: req.user._id, isLive: true });
  const streamId = existing ? existing.streamId : uuidv4();

  if (!existing) {
    await LiveStream.create({ streamId, streamer: req.user._id });
  }
  res.redirect(`/live/${streamId}`);
});

app.get('/live/:id', async (req, res) => {
  const stream = await LiveStream.findOne({ streamId: req.params.id });
  if (!stream) return res.status(404).send("Stream not found");
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

// Socket.IO
const streamBroadcasters = {};
io.on("connection", (socket) => {
  const userId = socket.handshake.query.userId;
  if (userId) userSocketMap.set(userId, socket.id);

  console.log("A user connected");

  socket.on("joinRoom", ({ userId, friendId }) => {
    const room = [userId, friendId].sort().join("_");
    socket.join(room);
  });

  socket.on('sendMessage', async ({ from, to, content }) => {
    const newMsg = await Message.create({ from, to, content });
    const room = [from, to].sort().join('_');
    io.to(room).emit('newMessage', newMsg);

    const recvSocketId = userSocketMap.get(to);
    if (recvSocketId) {
      io.to(recvSocketId).emit('notifyMessage');
    }
  });

  socket.on('broadcaster', ({ streamId }) => {
    streamBroadcasters[streamId] = socket.id;
    socket.join(streamId);
  });

  socket.on('watcher', ({ streamId }) => {
    const bId = streamBroadcasters[streamId];
    console.log('Watcher requesting stream:', streamId, 'Broadcaster ID:', bId, 'Watcher ID:', socket.id);
    if (bId) {
      socket.join(streamId); // Join the stream room for this watcher
      io.to(bId).emit('watcher', socket.id); // Notify broadcaster about new watcher
      console.log('Watcher', socket.id, 'joined stream', streamId, 'and notified broadcaster', bId);
    } else {
      console.log('No broadcaster found for stream:', streamId);
      socket.emit('noBroadcaster', { streamId });
    }
  });

  socket.on('offer', (id, desc) => io.to(id).emit('offer', socket.id, desc));
  socket.on('answer', (id, desc) => io.to(id).emit('answer', socket.id, desc));
  socket.on('candidate', (id, c) => io.to(id).emit('candidate', socket.id, c));

  socket.on('disconnect', () => {
    userSocketMap.delete(userId);
    socket.broadcast.emit('disconnectPeer', socket.id);
    for (const [sid, sockId] of Object.entries(streamBroadcasters))
      if (sockId === socket.id) delete streamBroadcasters[sid];
  });
});

// Start Server
const PORT = process.env.PORT || 8000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
