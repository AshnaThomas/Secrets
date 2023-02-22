require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");

// Removing level-2 mongoose-encryption and using hashing method level-3 instead
// const encrypt = require("mongoose-encryption");

// Removing hashing with sha3_512 level-3 to use bcrypt method level-4 instead
// const sha3_512 = require("js-sha3").sha3_512;

// Removing Level-4 Salting and hashing using bcrypt to Level-5 Cookies and sessions using passport
// const bcrypt = require("bcrypt");
// const saltRounds = 10;

const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

// Added while doing Level-6 Oauth authentication
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set("view engine","ejs");

app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
  secret:"learningislikethemostimportantthing4me.",
  resave:false,
  saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.set("strictQuery", false);
mongoose.connect("mongodb://localhost:27017/secretDB",{useNewUrlParser:true});

const userSchema = new mongoose.Schema({
  email:String,
  password:String,
  googleId:String,
  secret:String
});

// Removing level-2 mongoose-encryption and using hashing method level-3 instead
// userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name });
    });
  });

  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

// Added while Level-6 Oauth using google
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile","email"] }));

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
});

app.get("/login",function(req,res){
  res.render("login");
});

app.get("/register",function(req,res){
  res.render("register");
});

// Added this section while using passport
app.get("/secrets",function(req,res){
  if(req.isAuthenticated()){
    User.find({"secret":{$ne:null}},function(err,foundUser){
      if(err){
        console.log(err);
      }
      else{
        res.render("secrets",{userWithSecrets:foundUser});
      }
    });
  }
  else{
    res.redirect("/login");
  }
});

app.get("/logout",function(req,res){
  res.render("home");
});

app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }
});

app.post("/register",function(req,res){

  // Removing hashing with sha3_512 level-3 to use bcrypt method level-4 instead
  // const passHash = sha3_512(req.body.password);

  // Removing Level-4 Salting and hashing using bcrypt to Level-5 Cookies and sessions using passport

  // bcrypt.hash(req.body.password,saltRounds,function(err,hash){
  //   const newUser = new User({
  //     email:req.body.username,
  //     password:hash
  //   });
  //   newUser.save(function(err){
  //     if(!err){
  //       res.render("secrets");
  //     }
  //     else{
  //       console.log(err);
  //     }
  //   });
  // });

  User.register({username:req.body.username},req.body.password,function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }
    else{
      passport.authenticate("local")(req,res,function(){
      res.redirect("/secrets");
      });
    }
  });
});

app.post("/login",function(req,res){

  // Removing Level-4 Salting and hashing using bcrypt to Level-5 Cookies and sessions using passport
  // User.findOne({email:req.body.username},function(err,foundUser){
  //     if(err){
  //       console.log(err);
  //     }
  //     else{
  //       if(foundUser){

          // Removing hashing with sha3_512 level-3 to use bcrypt method level-4 instead
          // if(foundUser.password === sha3_512(req.body.password)){

          // Removing Level-4 Salting and hashing using bcrypt to Level-5 Cookies and sessions using passport
          // bcrypt.compare(req.body.password,foundUser.password,function(err,result){
          //   if(result === true){
          //     res.render("secrets");
          //   }
          //   else{
          //     res.render("Incorrect Password");
          //   }
          // });
    //     }
    //   }
    // });

  // Added for Level-5 passport authentication
  const user = new User({
    username:req.body.username,
    password:req.body.password
  });

  req.login(user,function(err){
    if(err){
      console.log(err);
    }
    else{
        passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/submit",function(req,res){
  const submittedSecret = req.body.secret;

  User.findById(req.user.id,function(err,foundUser){
    if(err){
      console.log(err);
    }
    else{
      foundUser.secret = submittedSecret;
      foundUser.save(function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(3000,function(){
  console.log("Server started at port 3000");
});
