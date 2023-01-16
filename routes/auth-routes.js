const router = require('express').Router()
const bcrypt = require ('bcryptjs')
const User = require('../models/User.model')
const saltRounds = 10 // how many routes bcrypt run the salt
const mongoose = require ('mongoose')

// require auth middleware
const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');  



router.get('/SignUPage', (req,res)=>{
  res.render('signup/signup')
}) //route to the sign up page



router.post('SignUPage', (req,res)=>{
    console.log(req.body)

    const {email,password} = req.body// destructuring OBJ to conv reason 

//checking if all plasses filled

if(!email || !password){
    res.render('signup/signup', {errorMessage: "Fill all blank plases"})
return
}//new

const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
if (!regex.test(password)) {
    res
      .status(500)// spesific
      .render('signup/signup', { errorMessage: 'Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.' });
    return;
  }//new 


    //doing bcrypting for sign in for password
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

    .then(()=>{
        res.redirect("/profile")
    })// redirect to a profile page after signup

    .catch(error =>{
        console.log(error)

      //additional errors

        if (error instanceof mongoose.Error.ValidationError) {
            res.status(500).render('signup/signup', { errorMessage: error.message });

        } else if (error.code === 11000) { // error type 11000 in console
                res.status(500).render('signup/signup', // more spesific but = res.render - res.status 500
                { errorMessage: 'Username and email need to be unique. Either username or email is already used.'
                });

        } else {
           next(error) // going to next 
        }
     
    });
})

    

//new route for login 
router.get('/login',(req,res)=>{
    res.render("user/login")
})


// route for user profile after signup / login 
router.get('/profile', isLoggedIn, (req,res)=>{
    res.render('user/userP', {UserInSession: req.user.session.currentUser})
})

//middleware function for security 

router.post('/login',(req,res)=>{ // look in "post" for route, post trevel from client to the server inside req.body
    console.log('SESSION =====> ', req.session) //cokies staff 
    console.log(req.body) 

    const{email,password} = req.body //destracturing object, keys from <form> from req.body object - login.hbs

// check password and email filled in form on webS (1 step) ->

if(email === " " || !password) {

    res.render('user/login', {errorMessage: 'Plese enter email and password'})
    return
}  
// second step -> checking if email is registraited already 

User.findOne({email:email}) 

.then(user => { // can be any word, we store in user line 95

    console.log(user)

    if (!user) {
      res.render('user/login', { errorMessage: 'Email is not registered. Try other email.' });
      return;
    } else if (bcryptjs.compareSync(password, user.passwordHash)) {
        
        // compsreSync() used to compare user's password with hashed that stored in bd. 

        req.session.currentUser = user; // this storing user inside the session, i can you it in all my routes

        res.redirect('/profile')

    } else {
      res.render('user/login', { errorMessage: 'Incorrect password.' });
    }
  })
  .catch(error => next(error));


});

//logout route
router.post('/logout', (req, res, next) => {
    req.session.destroy(err => {
      if (err) next(err);
      res.redirect('/');
    });
  });



module.exports = router
