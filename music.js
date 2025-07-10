const mongoose = require('mongoose')
const musicSchema = new mongoose.Schema({
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

const music=  mongoose.model('musician',musicSchema)
module.exports=music