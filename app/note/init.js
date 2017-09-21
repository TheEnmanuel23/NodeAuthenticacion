// app/note/init.js

const passport = require('passport')

function initUser (app) {
	app.get('/notes/:id', passport.authenticationMiddleware(), (req,es) => {
		res.render('note/overview', {
			id: req.params.id
		})
	})
}

module.exports = initUser