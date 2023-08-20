const mongoose = require('mongoose');
const validator = require('validator');
const Schema = mongoose.Schema;


const UserSchema = new Schema({
    email: {
        required: true,
        type: String,
        unique: true,
        lowercase: true,
        validate: (value) => {
            if (!validator.isEmail(value)) {
                throw new Error('Invalid email address.');
            }
        }
    },
    fullName: {
        required: true,
        type: String,
    },
    username: {
        required: true,
        type: String,
        unique: true,
        lowercase: true,
        minlength: 3,
    },
    password: {
        type: String,
        minlength: 8,
    },
    avatar: String,
    githubId: Number,
    googleId: Number,
    backgroundImage: {
        type: String,
        default: 'https://thumbs.dreamstime.com/b/berlin-germany-jan-twitter-social-media-blue-bird-sign-logo-symbol-minimalist-design-painted-over-white-brick-wall-background-137526023.jpg',
    },
    bio: {
        type: String,
        default: null,
        maxlength:300,
    },
    location: {
        type: String,
        default: 'Bangalore'
    },
    website: {
        type: String,
        default: null,
    },
    joindate: {
        type: Date,
        default: new Date()
    },
    isVerified:{
        type:Boolean,
        default:false,
    }

})

const UserModel = mongoose.model('User', UserSchema);
module.exports = UserModel;