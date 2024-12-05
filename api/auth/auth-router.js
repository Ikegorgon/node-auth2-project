const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const bcrpyt = require('bcryptjs')
const User = require('../users/users-model')
const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require("../secrets"); // use this secret!

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  const { username, password } = req.body
  const { role_name } = req
  const hash = bcrpyt.hashSync(password, 8)
  User.add({username, password: hash, role_name})
    .then(user => {
      res.status(201).json(user)
    })
    .catch(next)
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  if (bcrpyt.compareSync(req.body.password, req.user.password)) {
    const token = jwt.sign(
      {subject: req.user.user_id, role_name: req.user.role_name, username: req.user.username}, 
      JWT_SECRET, 
      {expiresIn: '1d'}
    )
    res.json({ message: `${req.user.username} is back!`, token})
  } else {
    next({status: 401, message: 'Invalid Credentials'})
  }
});

module.exports = router;
