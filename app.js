const express = require('express')
const User =require('./user')
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
    role:user.role
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
function check(req,res,next){   
  
    const usid=req.cookies?.uid
    const user = getUser(usid)
    console.log(usid)
    req.user=user
    return next()

}
app.use(check)
app.get('/',(req,res)=>{
    if (!req.user){
        return res.redirect('/login')
    }
    res.render('home')
})
app.get('/signup',(req,res)=>{
    res.render('signup')
})
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const user = new User({ name, email, password, role: role || undefined });
    await user.save();
    res.redirect('/')
  } catch (err) {
    console.error(err);
    res.render('signin',{err:err})
  }
});
app.get('/login', (req, res) => {
    if (!req.user) {
        return res.render('login');
    }
    res.redirect('/');
});
app.post('/login',async (req,res)=>{
     const { email, password } = req.body;
    const user = await User.findOne({ email, password });

    if (!user) {
        return res.render('login', { error: 'Invalid Username or password' });
    }

    const token = setUser(user); 
    console.log(token);

    res.cookie('uid', token, { httpOnly: true }); 
    return res.redirect('/');
})
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
