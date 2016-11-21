const User      = require('../models/user');
const JWT       = require('jwt-simple');
const config    = require('../config');

function tokenForUser(user){
    const timestamp  = new Date().getTime();
    return JWT.encode({ sub: user.id, iat: timestamp, admin: true }, config.secret);
};

exports.signIn = function(req, res, next){
    // User has already had their email and password auth'd, just need to give them a token now
    res.send({ token: tokenForUser(req.user)});
};

exports.signUp = function(req,res,next){
    const email     = req.body.email;
    const password  = req.body.password;

    User.findOne({ email: email }, function(err, existingUser){
        if(err){ return next(err)};
        if(existingUser){
            return res.status(422).send({ error: 'User already exists.'});
        } else {
            const newUser = new User({email: email, password: password});
            newUser.save({ email: email, password: password } , function(err, result){
                if(err){ return next(err)};
                res.status(200).json({ token: tokenForUser(newUser)});
            });
        }
    });

};