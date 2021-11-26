const express = require('express');
const path = require('path');
const cookieSession = require('cookie-session');
const bcrypt = require('bcrypt');
const dbcon = require('./database');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(express.urlencoded({ extended: false }));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(cookieSession({
    name: 'session',
    keys: ['key1', 'key2'],
    maxAge: 3600 * 1000 // 1hr
}))

//MIDDLEWARE
const ifnotlogin = (req, res, next) => {
    if (!req.session.login) {
        return res.render('login-regis');
    }
    next();
}

const iflogin = (req, res, next) => {
    if (req.session.login) {
        return res.render('home');
    }
    next();
}

app.get('/', ifnotlogin, (req, res) => {
    dbcon.execute("SELECT name FROM users WHERE id =?", [req.session.userID])
        .then(([rows]) => {
            res.render('home', {
                name: rows[0].name
            })
        })
});

//regis
app.post('/regis', iflogin, [
    body('user_email', 'Invalid email address!').isEmail().custom((value) => {
        return dbcon.execute('SELECT email FROM users WHERE email=?', [value])
            .then(([rows]) => {
                if (rows.length > 0) {
                    return Promise.reject('This E-mail already in use');
                }
                return true;
            });
    }),
    body('user_name', 'Username is Empty').trim().not().isEmpty(),
    body('user_pass', 'minimum length 6 characters').trim().isLength({ min: 6 }),
],
    (req, res, next) => {
        const validation_result = validationResult(req);
        const { user_name, user_pass, user_email } = req.body;
        if (validation_result.isEmpty()) {
            bcrypt.hash(user_pass, 12).then((hash_pass) => {
                dbcon.execute("INSERT INTO users(name,email,password) VALUES(?,?,?)", [user_name, user_email, hash_pass])
                    .then(result => {
                        res.send('Created success, Now you can <a href="/">Login</a>');
                    }).catch(err => {
                        if (err) throw err;
                    });
            })
                .catch(err => {
                    if (err) throw err;
                })
        }
        else {
            let allErrors = validation_result.errors.map((error) => {
                return error.msg;
            });
            res.render('login-regis', {
                regis_error: allErrors,
                old_data: req.body
            });
        }
    });

//login
app.post('/login', iflogin, [
    body('user_email').custom((value) => {
        return dbcon.execute('SELECT email FROM users WHERE email=?', [value])
            .then(([rows]) => {
                if (rows.length == 1) {
                    return true;
                }
                return Promise.reject('Invalid Email Address');
            });
    }),
    body('user_pass', 'Password is empty').trim().not().isEmpty(),
], (req, res) => {
    const validation_result = validationResult(req);
    const { user_pass, user_email } = req.body;
    if (validation_result.isEmpty()) {
        dbcon.execute("SELECT * FROM users WHERE email=?", [user_email])
            .then(([rows]) => {
                bcrypt.compare(user_pass, rows[0].password).then(compare_result => {
                    if (compare_result === true) {
                        req.session.login = true;
                        req.session.userID = rows[0].id;
                        res.redirect('/')
                    }
                    else {
                        res.render('login-regis', {
                            login_errors: ['Invalid Password']
                        });
                    }
                })
                    .catch(err => {
                        if (err) throw err;
                    });
            }).catch(err => {
                if (err) throw err;
            });
    }
    else {
        let allErrors = validation_result.errors.map((error) => {
            return error.msg;
        });
        res.render('login-regis', {
            login_errors: allErrors
        });
    }
});

//logout
app.get('/logout', (req, res) => {
    req.session = null;
    res.redirect('/');
});

app.listen(3000, () => console.log("serverok"));