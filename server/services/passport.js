const passport      = require('passport');
const User          = require('../models/user');
const config        = require('../config');
const JWTStrategy   = require('passport-jwt').Strategy;
const ExtractJWT    = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// Create local strategy
const localOptions  = { usernameField: 'email' };
const localLogin    = new LocalStrategy(localOptions, function(email, password, done){
    // Verify email and password, call done with the user if correct, othersie call done(null, false)
    User.findOne({ email: email }, function(err, user){
        if(err) { 
            return done(err);
        }
        if(!user) { 
            return done(null, false);
        } 
        user.comparePassword(password, function(err, isMatch){
            if(err) { 
                return done(err)
            }
            if(!isMatch){
                return done(null, false);
            }
            return done(null, user);
        });
    });
});

// Set up options JWT strategy
const JWTOptions = {
    jwtFromRequest: ExtractJWT.fromHeader('authorization'),
    secretOrKey: config.secret
};

// Creat JWT Strategy
const JWTLogin = new JWTStrategy(JWTOptions, function(payload, done){
    // See if the userID and payload exists in our database
        User.findById(payload.sub, function(err, user){
            if(err){ return done(err, false); }
            if(user){
                done(null, user);
            } else {
                done(null, false);
            }
        });
    // If exists, call done with user, otherwise call done with an empty object
});


// Tell passport to use this strategy
passport.use(JWTLogin);
passport.use(localLogin);