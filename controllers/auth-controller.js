const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken')
const db = require("../models/db");

exports.register = async (req, res, next) => {
        const {  user_name, password, email } = req.body;
        try {
        if (!( email  && user_name && password )) {
            return next(new Error('Fulfill all inputs'));
        }
        
        const hashedPassword = await bcrypt.hash(password, 8);
        console.log(hashedPassword);

        const data = {
                user_name,
                password : hashedPassword,
                email
            };
        
        const rs = await db.user.create({ data })
        console.log(rs)

        res.json({msg: 'Register successful'})
    } catch (err) {
        next(err);
    }
};

exports.login = async (req, res, next) => {
    const {user_name, password} = req.body
    try {
  
      if( !(user_name.trim() && password.trim()) ) {
        throw new Error('username or password must not blank')
      }
 
      const user = await db.user.findFirstOrThrow({ where : { user_name }})

      const pwOk = await bcrypt.compare(password, user.password)
      if(!pwOk) {
        throw new Error('invalid login')
      }

      const payload = { id: user.id }
      const token = jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: '30d'
      })
      console.log(token)
      res.json({token : token})
    }catch(err) {
      next(err)
    }
  };

exports.getme = async (req, res, next) => { 
      res.json(user);

  };