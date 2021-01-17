//jshint esversion:6

//' Get Secrets from local environment var.
require("dotenv").config();

//' Get required modules
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

//' Google OAuth
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");


//' Initialize app
const app = express();

//' Config 'app' to use EJS as view engine, public folder & bodyParser for parsing.
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
    extended: true
}));

//' Use session with few config.
app.use(session({
    secret: process.env.SOME_LONG_UNGUESSABLE_STRING,
    resave: true,
    saveUninitialized: false
}));

//' Initalize passport
app.use(passport.initialize());
app.use(passport.session());


//' Connect to MongoDB, create new schema and model
mongoose.connect(process.env.MONGODB_URL + "userDB",{
    useNewUrlParser: true,
    useUnifiedTopology: true   
});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

//' Use to hash/salt encryption to data using passport
userSchema.plugin(passportLocalMongoose);
//' Google OAuth using passport
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

//' Local Strategy to auth user by userame & password
passport.use(User.createStrategy());

//' Use  Serialize & Deserialize with session
//' Serialize : serialize user identification into the cookie
//' Deserialize : descover message inside cookie. Like, who the user is ? OR user identification
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });


//' Google OAuth strategy using passport
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:8234/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    //'console.log("User Data: "+ profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


//' ROUTES
app.get("/", (req, res)=>{
    res.render("home");
});

//' Google OAuth Route using passport
app.get("/auth/google", 
    passport.authenticate("google", { scope: ["profile"] })
);

//' Route to redirect authenticated user after Google OAuth
app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });



app.get("/login", (req, res)=>{
    res.render("login");
});


app.get("/register", (req, res)=>{
    res.render("register");
});


app.get("/logout", (req, res)=>{
    //' Logout user using passport
    req.logout();

    res.redirect("/");
});


app.get("/secrets", (req, res)=>{
    //' Anyone can see anonymous secrets
    User.find({"secret": {$ne : null}}, (err, foundUsers)=>{
        if(err){
            console.log("Error: "+ err);
        }
        else{
            if(foundUsers){                
                let isPublicRequest = true;

                if(req.isAuthenticated()){
                    isPublicRequest = false;
                }
                res.render("secrets", {userWithSecrets: foundUsers, public: isPublicRequest}); 
            }
        }
    });
});


app.get("/submit", (req, res)=>{
    //' Only authenticated user allow to access
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
});

app.post("/submit", (req, res)=>{
    const userSecret = req.body.secret;
    // console.log("Cookie user data stored: "+ req.user);
    const loggedUserId = req.user.id;

    User.findById(loggedUserId, (err, foundUser)=>{
        if(err){
            console.log("Error: "+ err);
        }
        else{
            if(foundUser){
                foundUser.secret = userSecret;
                foundUser.save(()=>{
                    res.redirect("/secrets");
                });
            }
        }
    });
});






app.post("/register", (req, res)=>{
    const userName = req.body.username;
    const passWord = req.body.password;

    //' Register new user with passport
    User.register({username: userName}, passWord, (err, user)=>{
        if(err){
            console.log("Error: "+err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req, res, ()=>{
                res.redirect("/secrets");
            });
        }
    });

});

app.post("/login", (req, res)=>{
    const userName = req.body.username;
    const passWord = req.body.password;

    const user = new User({
        username: userName,
        password: passWord
    });

    //' Check for authenticated user by passport
    req.login(user, (err)=>{
        if(!err){
            passport.authenticate("local")(req, res, ()=>{
                res.redirect("/secrets");
            });
        }
        else{
            console.log("Error: " + err);
        }
    });


});





//' Sever config
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>{
    console.log("Server started on port: " + PORT);
});