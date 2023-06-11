const jwt = require("jsonwebtoken");
const {ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET} = require('../config/index')
const RefeshToken = require('../models/token')
class JWTService {
  // sign access Token
  static signAccessToken(payload, expiryTime) {
    return jwt.sign(payload, ACCESS_TOKEN_SECRET, { expiresIn: expiryTime });
  }
  // sign refresh Token
  static signRefreshToken(payload, expiryTime) {
    return jwt.sign(payload, REFRESH_TOKEN_SECRET, { expiresIn: expiryTime });
  }
  // verify access Token
  static verifyAccessToken(token){
    return jwt.verify(token, ACCESS_TOKEN_SECRET)
  }
  // verfy refresh Token
  static verifyRefreshToken(token){
    return jwt.verify(token, REFRESH_TOKEN_SECRET)
  }
  // store refresh Token
  static async storeRefreshToken(token, userId){
    try{
        const newToken = new RefeshToken({
            token: token,
            userId: userId
        });
        // store in db
        await newToken.save();
    }
    catch(error){
        console.log(error);
    }
  }
}

module.exports = JWTService;
