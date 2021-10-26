#!/usr/bin/env node

require('dotenv').config();

const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');
var { graphqlHTTP } = require('express-graphql');
var { buildSchema } = require('graphql');
const { readFileSync } = require('fs');

app.use(express.static('public'));

app.use('/api', graphqlHTTP({
  schema: buildSchema(readFileSync('./graphql.schema', 'utf8')),
  rootValue: require('./graphqlRoot.js'),
  graphiql: (process.env.NODE_ENV !== 'PROD')
}));

const users = [];

passport.use(new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
  const user = users.find(user => user.email === email);
  if(user == null){
    return done(null, false, {message: 'No user with that email'});
  }
  if(bcrypt.compareSync(password, user.password)){
    return done(null, user);
  } else {
    return done(null, false, {message: 'Password incorrect'});
  }
}));
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, users.find(user => user.id === id)));

app.set('view-engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));

app.get('/', checkAuthenticated, (req, res) => {
  res.render('index.ejs', { email: req.user.email });
});

app.get('/login', checkNotAuthenticated, (req, res) => {
  console.log(users);
  res.render('login.ejs');
});

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}));

app.get('/register', checkNotAuthenticated, (req, res) => {
  res.render('register.ejs');
});

app.post('/register', checkNotAuthenticated, (req, res) => {
  bcrypt.hash(req.body.password, 10).then(hashedPassword => {
    users.push({
      id: Date.now().toString(),
      email: req.body.email,
      password: hashedPassword
    });
    res.redirect('/login');
  });
});

app.delete('/logout', (req, res) => {
  req.logOut();
  res.redirect('/login');
});

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return res.redirect('/');
  next();
}

app.listen(3000);
