const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../secrets"); // use this secret!

const Users = require("../users/users-model");
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");

router.post("/register", validateRoleName, async (req, res, next) => {
  //   /**
  //     [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

  //     response:
  //     status 201
  //     {
  //       "user"_id: 3,
  //       "username": "anna",
  //       "role_name": "angel"
  //     }
  //    */

  try {
    const { username, password, role_name } = req.body;
    const user = await Users.findBy(username);

    if (user.username === username) {
      return res.status(409).json({
        message: "Username is already taken",
      });
    }

    const newUser = await Users.add({
      username,
      password: await bcrypt.hash(
        password,
        parseInt(process.env.BCRYPT_TIME_COMPLEXITY)
      ),
      role_name,
    });
    res.status(201).json(newUser);
  } catch (err) {
    next(err);
  }
});

router.post("/login", checkUsernameExists, async (req, res, next) => {
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

  try {
    const { username, password } = req.body;
    const user = await Users.findBy(username);
    const passwordValid = await bcrypt.compare(password, user.password);

    if (!passwordValid) {
      return res.status(401).json({
        message: "Invalid Credentials",
      });
    }

    const userToken = await Users.findById(user.user_id);
    const token = jwt.sign(
      {
        subject: user.user.id,
        username: user.username,
        role_name: userToken.role_name,
        expiresIn: "24h",
      },
      JWT_SECRET
    );

    res.cookie("token", token);
    res.status(200).json({
      message: `${user.username} is back!`,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
