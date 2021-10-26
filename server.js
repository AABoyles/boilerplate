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

const knex = require('knex')({
  client: 'sqlite3',
  connection: {
    filename: process.env.SQLITE_DB_PATH
  }
});

app.use(express.static('public'));

app.use('/api', graphqlHTTP({
  schema: buildSchema(readFileSync('./graphql.schema', 'utf8')),
  rootValue: require('./graphqlRoot.js'),
  graphiql: (process.env.NODE_ENV !== 'PROD')
}));

passport.use(new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
  knex
    .first('*')
    .from('users')
    .where('email', email)
    .then(user => {
      if(!user) return done(null, false, {message: 'Sorry, your username or password is incorrect.'});
      if(bcrypt.compareSync(password, user.passwd)){
        return done(null, user);
      } else {
        return done(null, false, {message: 'Sorry, your username or password is incorrect.'});
      }
    });
}));

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser((id, done) => {
  knex
    .first('*')
    .from('users')
    .where('id', id)
    .then(user => done(null, user));
});

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
  knex
    .first('*')
    .from('users')
    .where('email', req.body.email)
    .then(user => {
      if(user){
        req.flash('error', 'Sorry, you cannot register that email.');
        res.redirect(301, '/register');
      } else {
        bcrypt.hash(req.body.password, 10).then(hashedPassword => {
          knex
            .insert({
              id: Date.now(),
              name: "Tony",
              email: req.body.email,
              passwd: hashedPassword
            })
            .into('users')
            .then(() => res.redirect('/login'));
        });
      }
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
