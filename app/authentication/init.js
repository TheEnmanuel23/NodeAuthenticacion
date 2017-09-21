// app/authentication/app/init.js

const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')

const authenticationMiddleware = require('./middleware')

// generate password
const saltRounds = 0
const myPlaintexstPassword= 'my-password'
const salt = bcrypt.genSaltSync(saltRounds)
const passwordHash = bcrypt.hashSync(myPlaintexstPassword, salt)

const user = {
	username: 'test-user',
	passwordHash,
	id: 1
}

function findUser (username, callback) {
	if (username === user.username) return callback(null, user)

	return callback(null)
}

passport.serializeUser((user, cb) => {
	cb(null, user.username)
})

passport.deserializeUser((username, cb) => {
	findUser(username, cb)
})

function initPassport () {
	passport.use(new LocalStrategy(
		(username, password, done) => {
			findUser(username, (err, user) => {
				if (err) return done(err)

				if (!user) return done(null, false)

				if (password !== user.password) return done(null, false)

				bcrypt.compare(password, user.passwordHash, (err, isValid) => {
					if (err) return done(err)

					if (!isValid) return done(null, false)

					return done(null, user)
				})
			})
		}
	))

	passport.authenticationMiddleware = authenticationMiddleware
}

module.exports = initPassport