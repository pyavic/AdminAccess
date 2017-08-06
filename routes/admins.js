var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

var Admin = require('../models/user');

// Register
router.get('/register', function(req, res){
	res.render('register');
});

// Login
router.get('/login', function(req, res){
	res.render('login');
});

// Register Admin
router.post('/register', function(req, res){
	var name = req.body.name;
	var username = req.body.username;
	var password = req.body.password;
	var password2 = req.body.password2;

	// Validation
	req.checkBody('name', 'Name is required').notEmpty();
	req.checkBody('username', 'username is required').notEmpty();
	req.checkBody('password', 'Password is required').notEmpty();
	req.checkBody('password2', 'Passwords do not match').equals(req.body.password);

	var errors = req.validationErrors();

	if(errors){
		res.render('register',{
			errors:errors
		});
	} else {
		var newAdmin = new Admin({
			name: name,
			username: username,
			password: password
		});

		Admin.createUser(newAdmin, function(err, admin){
			if(err) throw err;
			console.log(admin);
		});

		req.flash('success_msg', 'You are registered and can now login');

		res.redirect('/adminarea/login');
	}
});

passport.use(new LocalStrategy(
  function(username, password, done) {
   Admin.getUserByUsername(username, function(err, admin){
   	if(err) throw err;
   	if(!admin){
   		return done(null, false, {message: 'Unknown Admin'});
   	}

   	Admin.comparePassword(password, admin.password, function(err, isMatch){
   		if(err) throw err;
   		if(isMatch){
   			return done(null, admin);
   		} else {
   			return done(null, false, {message: 'Invalid password'});
   		}
   	});
   });
  }));

passport.serializeUser(function(admin, done) {
  done(null, admin.id);
});

passport.deserializeUser(function(id, done) {
  Admin.getUserById(id, function(err, admin) {
    done(err, admin);
  });
});

router.post('/login',
  passport.authenticate('local', {successRedirect:'/', failureRedirect:'/adminarea/login',failureFlash: true}),
  function(req, res) {
    res.redirect('/');
  });

router.get('/logout', function(req, res){
	req.logout();

	req.flash('success_msg', 'You are logged out');

	res.redirect('/adminarea/login');
});

module.exports = router;
