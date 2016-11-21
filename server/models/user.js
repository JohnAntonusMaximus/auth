const mongoose  = require('mongoose');
const Schema    = mongoose.Schema;
const bcrypt    = require('bcrypt-nodejs');


const userSchema  = new Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true
    },
    userID: {
        type: String,
        required: true
    }, 
    accountID: {
        type: String,
        required: true
    }
});

// On Save Hook, encrypt password (Before saving model, run this pre function)
userSchema.pre('save', function(next){
    // Get access to this particular user model instance that is being passed through
    const user = this; // user.email & user.password

    // Gen salt, then invoke callback (takes some time)
    bcrypt.genSalt(10, function(err, salt){
        if(err){ return next(err)};

        // hash (encrypt) our password using the salt
        bcrypt.hash(user.password, salt, null, function(err, hash){
            if(err){ return next(err) };

            // Overwrite plain text password with encrypted password
            user.password = hash;
            next();
        });
    });
});

userSchema.methods.comparePassword = function(candidatePassword, callback){
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch){
        if(err) {
            return callback(err);
        }
        callback(null, isMatch);
    });
};

userSchema.methods.createUserID = function(){
    var text = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    for( var i=0; i < 14; i++ )
        text += possible.charAt(Math.floor(Math.random() * possible.length));

    return "UID-" + text;
};

var UserClass = mongoose.model('user', userSchema);

module.exports = UserClass;