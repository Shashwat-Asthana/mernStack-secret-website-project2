//jshint esversion:6

//for using Environment Variable for Securing the key and data in the code:
require('dotenv').config();


const bodyParser = require("body-parser");
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
//level 5
//1
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

//LEVEL 6--1
const GoogleStrategy = require('passport-google-oauth20').Strategy;

//LEVEL 6--3
const findOrCreate = require("mongoose-findorcreate");





const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

mongoose.connect("mongodb://127.0.0.1:27017/userDB", {useNewUrlParser: true})
    .then(() => {
        console.log("Successfully connected to the MongoDB server!");
    });
//level 5
// mongoose.set("useCreateIndex", true);

//level 5
//2
app.use(session({
    secret:"Our little secret.",
    resave: false,
    saveUninitialized: false,
}));

//level 5
//3
app.use(passport.initialize());
//4
app.use(passport.session());


//LEVEL 6--8
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

//level 5
//5
userSchema.plugin(passportLocalMongoose);

//LEVEL 6--4
userSchema.plugin(findOrCreate);

//to check the environment variable.
console.log(process.env.API_KEY);


const User = new mongoose.model("User",userSchema);

//level 5

//6
passport.use(User.createStrategy());
//LEVEL 6--6
passport.serializeUser(function(user, done){
    done(null, user.id);
});
//LEVEL 6--7
passport.deserializeUser(function(id, done) {
    User.findById(id)
        .then(function(user) {
            done(null, user);
        })
        .catch(function(err) {
            done(err);
        });
});


//LEVEL 6--2
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {//to make it run findorcreate we will import a npm package in it.
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
    res.render("home");
});

//LEVEL 6--4
app.get("/auth/google", 
    passport.authenticate("google", {scope:['profile']})
    
);

//LEVEL 6--5
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get("/login",function(req,res){
    res.render("login");
});

app.get("/register",function(req,res){
    res.render("register");
});



//13
app.get("/logout", function(req, res) {
    req.logout(function(err) {
        if (err) {
            console.error(err);
            return res.status(500).send("Error during logout");
        }
        console.log("Logout!");
        res.redirect("/");
    });
});

//updated
app.get("/submit", function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
   

});

app.get("/secrets", function(req,res){
    //level 5
    //10
    if(req.isAuthenticated()){
        User.find({"secret":{$ne: null}})
        .then((result) =>{
            res.render("secrets", {usersWithSecrets: result});
        })
    }else{
        res.redirect("/login");
    }
});






app.post("/register", function(req, res) {

    //level 5
    //9
    User.register({username: req.body.username}, req.body.password)
        .then(() =>{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        })
        .catch((err) =>{
            res.redirect("/register");
        });
});




app.post("/login", function(req, res) {

    //level 5
    //11
    const user = new User({
        username: req.body.username,
        passport: req.body.password
    });

    //12

    req.login(user, function(err) {
        if (err) {
            console.error(err);
            return res.status(500).send("Error during login");
        }

        passport.authenticate("local")(req, res, function() {
            res.redirect("/secrets");
        });
    });
});

//updated
app.post("/submit", function(req,res){
    const submittedSecret = req.body.secret;

    // console.log(req.user.id);

    User.findById(req.user.id)
        .then((result) =>{
            result.secret = submittedSecret;
            result.save()
                .then(()=>{
                    res.redirect("/secrets");
                });
        })
        .catch((err)=>{
            console.log(err);
        });

});



app.listen(3000, function(){
    console.log("Successfully Started the Server!");
});