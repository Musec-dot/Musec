  const express = require('express')
  const bcrypt = require('bcryptjs')
  const User =require('./user')
  const friendRoutes = require('./routes/friendRoutes');
  const music = require('./music')
  const cookieParser = require('cookie-parser')
  const mongoose =require("mongoose")
  const app = express()
  const jwt = require('jsonwebtoken')
  const path=require('path')
  app.set('view engine',"ejs")
  app.set('views',path.resolve('./'))
  app.use(express.json())
  app.use(cookieParser())
  app.use(express.urlencoded({extended:false}))
  mongoose.connect('mongodb+srv://microsoftrishik:Kathikebab-14@musec.1atpodc.mongodb.net/', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log(' Connected to MongoDB Atlas'))
  .catch((err) => console.error(' MongoDB connection error:', err));
  const secret='rishik@123'
  function setUser(user){
    return jwt.sign({

      _id:user._id,
      email:user.email,
      role:user.role,
      username:user.username
    },secret)
  }
  function getUser(token) {
      if (!token){
          return null
      };
      try {
          return jwt.verify(token, secret);
      } catch (error) {
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

  return next();
}


  app.use(check)
  app.use('/requests', friendRoutes);
  app.get('/', async (req, res) => {
  if (!req.user) {
    return res.render('home');
  }

  const allUsers = await User.find({});
  
  console.log(req.user.friends); 
  
  res.render('dashboard', {
    name: req.user.username,
    allUsers,
    friends: req.user.friends 
  });
});

  app.get('/signup',(req,res)=>{
      res.render('signup')
  })
  app.post('/signup', async (req, res) => {
    try {
      const { username, email, password,} = req.body;
      const user = new User({ username, email, password });
      await user.save();
      res.redirect('/')
    } catch (err) {
      console.error(err);
      res.render('signup',{err:err})
    }
  });
  app.get('/login', (req, res) => {
      if (!req.user) {
          return res.render('login');
      }
      res.redirect('/');
  });
  app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
        return res.render('login', { error: 'Invalid Username or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
        return res.render('login', { error: 'Invalid Username or password' });
    }

    const token = setUser(user);
    console.log(token);

    res.cookie('uid', token, { httpOnly: true });
    return res.redirect('/');
});

  app.get('/logout', (req, res) => {
    res.clearCookie('uid');
    res.redirect('/login'); 
  });
  app.get('/signup-music',(req,res)=>{
      return res.render('music_signup')
  })
  app.post('/signup-music',async(req,res)=>{
  try {
      const { name, email, password, role } = req.body;
      const musician = new music({ name, email, password, role: role || undefined });
      await musician.save();
      res.redirect('/')
    } catch (err) {
      console.error(err);
      res.render('music_signup',{err:err})
    }
  })

  app.listen('8000',()=>{
  console.log('app running')
  })
