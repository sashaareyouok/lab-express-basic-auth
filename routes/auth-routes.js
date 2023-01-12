const router = require('express').Router()
const bcrypt = require ('bcryptjs')
const User = require('../models/User.model')
const saltRounds = 10 //

router.get('/SignUPage', (req,res)=>{
  res.render('signUpuser/authSignup')
}) //route to the sign up page


router.post('SignUPage', (req,res)=>{
    console.log(req.body)

    const {email,password} = req.body// destructuring OBJ

    //doing bcrypting
    bcrypt
    .genSalt(saltRounds)
    .then((salt)=>{
        console.log("Salt:", salt)
        return bcrypt.hash(password,salt)
        // hash is encrypting password (password, salt)

    })

    .then(hashedPassword =>{
        console.log("Hash:", hashedPassword)

        User.create({
            email: email,
            passwordHash: hashedPassword
        })
    })

    .catch(error =>{
        console.log(error)
    })

})

module.exports = router
