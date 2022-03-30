const express = require('express');
const router = express.Router();
const userRepository = require('../models/user-repository');
const { passwordsAreEqual } = require('../security/crypto');
const { generateAuthToken } = require('../security/auth');
const { body } = require('express-validator');
const { validateBody } = require('./validation/route.validator');

router.post(
  '/login',
  body('firstName').notEmpty(),
  body('password').notEmpty(),
  (req, res) => {
    validateBody(req);

    const { firstName, password } = req.body;

    const user = userRepository.getUserByFirstName(firstName);
    if (!user || !(user && passwordsAreEqual(password, user.password))) {
      res.status(401).send('Unauthorized');

      return;
    }

    const token = generateAuthToken(user.id, user.firstName, user.roles);

    res.json({ token });
  }
);

exports.initializeRoutes = () => router;
