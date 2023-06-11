const Joi = require("joi");
const User = require("../models/user");
const bcrypt = require("bcryptjs");
const UserDTO = require("../dto/user");
const JWTService = require("../services/JWTService");
const RefreshToken = require("../models/token");

const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,25}$/;

const authController = {
  async register(req, res, next) {
    // 1. validate user input
    const userRegisterSchema = Joi.object({
      username: Joi.string().min(5).max(30).required(),
      name: Joi.string().max(30).required(),
      email: Joi.string().email().required(),
      password: Joi.string().pattern(passwordPattern).required(),
      confirmPassword: Joi.ref("password"),
    });

    const { error } = userRegisterSchema.validate(req.body);
    // 2. if error in validation -> return error via middleware
    if (error) {
      return next(error);
    }

    // 3. if email or password already registered -> return an error
    const { username, name, email, password } = req.body;
    try {
      const emailInUse = await User.exists({ email });
      const usernameInUse = await User.exists({ username });

      if (emailInUse) {
        const error = {
          status: 409,
          message: "Email is already in use try another email!",
        };
        return next(error);
      }

      if (usernameInUse) {
        const error = {
          status: 409,
          message: "UserName is already in use try another username!",
        };
        return next(error);
      }
    } catch (error) {
      return next(error);
    }
    // 4. password hash
    const hashedPassword = await bcrypt.hash(password, 10);
    // 5. store user in db
    let accessToken;
    let refreshToken;
    let user;
    try {
      const userToRegister = new User({
        username,
        email,
        name,
        password: hashedPassword,
      });

      user = await userToRegister.save();

      // token generation
      accessToken = JWTService.signAccessToken({ _id: user._id }, "30m");

      refreshToken = JWTService.signRefreshToken({ _id: user._id }, "60m");
    } catch (error) {
      return next(error);
    }

    // store refresh Token in db
    await JWTService.storeRefreshToken(refreshToken, user._id);

    // send Tokens in cookie
    res.cookie("accessToken", accessToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });

    res.cookie("refreshToken", refreshToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });
    //dto
    const userDTO = new UserDTO(user);
    // 6. respond send
    return res.status(201).json({ user: userDTO, auth: true });
  },
  async login(req, res, next) {
    // 1. validate user input
    const userLoginSchema = Joi.object({
      username: Joi.string().min(5).max(30).required(),
      password: Joi.string().pattern(passwordPattern),
    });
    const { error } = userLoginSchema.validate(req.body);
    // 2. if validation error, return error
    if (error) {
      return next(error);
    }

    const { username, password } = req.body;
    // 3. match username and password
    let user;
    try {
      // match username
      user = await User.findOne({ username });

      if (!user) {
        const error = {
          status: 401,
          message: "Invalid username",
        };
        return next(error);
      }

      // match password
      // req.body.password -> hash -> match

      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        const error = {
          status: 401,
          message: "Invalid password",
        };
        return next(error);
      }
    } catch (error) {
      return next(error);
    }

    // token generation
    const accessToken = JWTService.signAccessToken({ _id: user._id }, "30m");

    const refreshToken = JWTService.signRefreshToken({ _id: user._id }, "60m");

    // store refresh Token in db
    await JWTService.storeRefreshToken(refreshToken, user._id);

    // update refresh token in db
    try {
      await RefreshToken.updateOne(
        {
          _id: user._id,
        },
        { token: refreshToken },
        { upsert: true }
      );
    } catch (error) {
      return next(error);
    }

    // send cookie
    res.cookie("accessToken", accessToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });

    res.cookie("refreshToken", refreshToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });
    //dto
    const userDTO = new UserDTO(user);
    // 4. return response
    return res.status(200).json({ user: userDTO, auth: true });
  },
  async logout(req, res, next) {
    // 1. delete refresh token from db
    const { refreshToken } = req.cookies;
    try {
      RefreshToken.deleteOne({ token: refreshToken });
    } catch (error) {
      return next(error);
    }
    // delete cookies
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    // 2. response
    res.status(200).json({ user: null, auth: false });
  },
  async refresh(req, res, next) {
    // 1. get refreshToken from cookies
    // 2. verify refreshToken
    // 3. generate new tokens
    // 4. update db, return response

    const originalRefreshToken = req.cookies.refreshToken;

    let id;
    try {
      id = JWTService.verifyRefreshToken(originalRefreshToken)._id;
    } catch (e) {
      const error = {
        status: 401,
        message: "Unanuthorized",
      };

      return next(error);
    }
    try {
      const match = RefreshToken.findOne({
        _id: id,
        token: originalRefreshToken,
      });

      if (!match) {
        const error = {
          status: 401,
          message: "Unauthorized",
        };
        return next(error);
      }
    } catch (e) {
      return next(error);
    }

    try {
      const accessToken = JWTService.signAccessToken({ _id: id }, "30m");
      const refreshToken = JWTService.signRefreshToken({ _id: id }, "60m");

      RefreshToken.updateOne({ _id: id }, { token: refreshToken });

      res.cookie("accessToken", accessToken, {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true,
      });
      res.cookie("refreshToken", refreshToken, {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true,
      });
    } catch (e) {
      return next(error);
    }

    const user = await User.findOne({ _id: id });

    const userDto = new UserDTO(user);

    return res.status(200).json({ user: userDto, auth: true });
  },
};

module.exports = authController;
