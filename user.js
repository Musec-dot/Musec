const mongoose = require('mongoose')
const userSchema = new mongoose.Schema({
    role:{
        type:String,
        required:true,
        default:'NORMAL'

    }
    ,

    name:{
        type:String,
        required:true,
    },
    email:{
        type:String,
        required:true,
        unique:true,
    },
    password:{
        type:String,
        required:true
    }
},{timestamps:true})

const User=  mongoose.model('user',userSchema)
module.exports=User