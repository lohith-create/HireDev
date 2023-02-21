let users = [
    { id: 1, username: 'admin', password: 'admin', role: 'admin' },
    { id: 2, username: 'client', password: 'client', role: 'client' },
    { id: 3, username: 'developer', password: 'developer', role: 'developer' }
  ];
  const passport = require('passport');
  const LocalStrategy = require('passport-local').Strategy;
  
  passport.use(new LocalStrategy(
    function (username, password, done) {
      let user = users.find(u => u.username === username && u.password === password);
      if (!user) {
        return done(null, false, { message: 'Invalid username or password' });
      }
      return done(null, user);
    }
  ));
  passport.serializeUser(function (user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function (id, done) {
    let user = users.find(u => u.id === id);
    done(null, user);
  });
  const express = require('express');
  const session = require('express-session');
  const bodyParser = require('body-parser');
  const flash = require('connect-flash');
  
  const app = express();
  
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false
  }));
  app.use(flash());
  app.use(passport.initialize());
  app.use(passport.session());
  
  app.get('/login', (req, res) => {
    res.render('login', { message: req.flash('error') });
  });
  
  app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
  }));
  app.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/');
  });
  function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.redirect('/login');
  }
  
  app.get('/', isAuthenticated, (req, res) => {
    res.send(`Welcome, ${req.user.username}!`);
  });
  app.get('/admin/developers', isAuthenticated, (req, res) => {
    if (req.user.role !== 'admin') {
      res.sendStatus(403); // Forbidden
      return;
    }
  
    
  
})