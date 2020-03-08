//===========================================================================================================//
//========================   START OF DEPENDENCIES                     ======================================//
//===========================================================================================================//
const config = require('./config')
const express = require('express');
const cors = require('cors');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const bodyParser = require("body-parser");

const jwt = require('jsonwebtoken');
const passport = require("passport");
const passportJWT = require("passport-jwt");
//===========================================================================================================//
//========================   END OF DEPENDENCIES                      =======================================//
//===========================================================================================================//

//===========================================================================================================//
//========================   START OF JWT AUTHENTICATION SETUP        =======================================//
//===========================================================================================================//


var ExtractJwt = passportJWT.ExtractJwt;
var JwtStrategy = passportJWT.Strategy;

var jwtOptions = {}
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme('JWT');
jwtOptions.secretOrKey = 'wehavetokeepthisasecret';

var strategy = new JwtStrategy(jwtOptions, async (jwt_payload, next) =>
{


    // console.log('payload received', jwt_payload);
    // usually this would be a database call:
    var user = await checkUserById(jwt_payload.id)            //users[_.findIndex(users, { id: jwt_payload.id })];
    if (user[0])
    {
        next(null, user[0]);
    } else
    {
        next({ error: "Unauthorized" }, false);
    }
});

passport.use(strategy);

//===========================================================================================================//
//========================   END OF JWT AUTHENTICATION SETUP        =========================================//
//===========================================================================================================//


const app = express();

app.use(cors());
app.use(passport.initialize());

// parse application/x-www-form-urlencoded
// for easier testing with Postman or plain HTML forms
app.use(bodyParser.urlencoded({
    extended: true
}));

// parse application/json
app.use(bodyParser.json())

const SELECT_ALL_RX_DATA = 'SELECT * FROM data_rx';

const connection = mysql.createConnection(config.config.mysql);

connection.connect(err =>
{
    if (err)
    {
        return err;
    }
});

//===========================================================================================================//
//========================   START OF SERVER REQUESTS            ============================================//
//===========================================================================================================//

//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//
app.get('/', (req, res) =>
{
    res.send("Server is up and running")
})
//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//

//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//
app.post('/registeruser', async (req, res) =>
{
    if (req.body.email && req.body.password && req.body.name)
    {

        var user = await checkUserByEmail(req.body.email)

        if (user.length !== 0)
        {
            res.status(500).send({ error: "Email already in use" });
            return
        }
        var name = req.body.name;
        var email = req.body.email;
        var password = req.body.password;
        var address = req.body.address ? req.body.address : "";
        var tele = req.body.tele ? req.body.tele : "";
        var mobi = req.body.mobi ? req.body.mobi : "";
        var gst = req.body.gst ? req.body.gst : "";
        var id = makeId(16);

        const salt = await bcrypt.genSalt()
        const hashedpassword = await bcrypt.hash(password, salt)

        var VALUES = [[id, 1, name, email, hashedpassword, address, tele, mobi, gst]]

        //--------------------------------------------------------------//
        try
        {
            await insertRowClientAuth(VALUES)
            res.status(200).send({ message: "User successfully added" });
        }
        catch (error)
        {
            res.status(500).send({ error: "Ooops, Couldn't create new user" });
        }
        //--------------------------------------------------------------//
    }
    else
    {
        res.send({ error: "Fill in required fields" });
    }
})
//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//


//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//
app.post("/login", async (req, res) =>
{
    if (req.body.email && req.body.password)
    {
        var email = req.body.email;
        var password = req.body.password;


        try
        {
            var user = await checkUserByEmail(email)
            if (!user)
            {
                res.status(401).end({ error: "Error Occured" });
            }
            if (await checkHash(password, user[0].password_hash))
            {
                // from now on we'll identify the user by the id and the id is the only personalized value that goes into our token
                var payload = { id: user[0].user_id };
                var token = jwt.sign(payload, jwtOptions.secretOrKey);
                res.json({ message: "ok", token: token });
            } else
            {
                res.status(401).send({ error: "passwords did not match" });
            }
        }
        catch (error)
        {
            res.status(401).send({ error: "Invalid credentials" });
        }
    }
});
//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//
app.get("/dashboard", passport.authenticate('jwt', { session: false }), (req, res) =>
{

    res.json({message : "Success! You can not see this without a token"});
});
//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//
app.post("/getcurrentuser",  passport.authenticate('jwt', { session: false }),  async (req, res) =>
{
    var headerToken = req.headers.authorization;
    var token = jwt.decode(headerToken.substring(4), jwtOptions.secretOrKey);

    try
    {
        var user = await checkUserById(token.id);
        res.json({
            status: 1,
            name: user[0].name,
            address: user[0].address,
            tele: user[0].tele,
            mobi: user[0].mobi,
            email: user[0].email,
        });
    }
     catch (error)
    {
        res.send({ error:   error  });
    }

})
//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//

//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//
app.post("/getcurrentappid",  passport.authenticate('jwt', { session: false }),  async (req, res) =>
{
    var headerToken = req.headers.authorization;
    var token = jwt.decode(headerToken.substring(4), jwtOptions.secretOrKey);

    try
    {
        var appIdList = await getAppIdListFromClientId(token.id);
        res.json({
            appIdList : appIdList,
        })
        
    }
     catch (error)
    {
        res.send({ error:   error  });
    }

})
//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//

//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//
app.post("/getapplicationfromappid",  passport.authenticate('jwt', { session: false }),  async (req, res) =>
{
    
    var appId = req.body.appId;

    try
    {
        var applicationList = await getApplicationFromAppId(appId);
        res.json({
            applicationList : applicationList,
        })
        
    }
     catch (error)
    {
        res.send({ error:   error  });
    }

})
//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//

//===========================================================================================================//
//========================   END OF SERVER REQUESTS           ==============================================//
//===========================================================================================================//


//===========================================================================================================//
//========================   START OF DATABASE QUERIES        ===============================================//
//===========================================================================================================//

//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//
insertRowClientAuth = (VALUES) =>
{
    return new Promise((resolve, reject) =>
    {

        connection.query(`INSERT INTO clients_auth ( user_id, status, name, email, password_hash, address, tele, mobi, gst) VALUES ?`, [VALUES], (err, results) =>
        {

            if (err)
            {
                reject(new Error('Ooops, Couldn\'t create new user'));
            }
            else
            {

                resolve(results);
            }
        })
    })
}
//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//

//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//
checkUserByEmail = (email) =>
{
    return new Promise((resolve, reject) =>
    {
        connection.query(`SELECT * FROM clients_auth WHERE email = "` + email + `"`, (err, results) =>
        {
            if (err)
            {
                reject(new Error('Ooops, something broke!'));
            }
            else
            {
                resolve(results);
            }
        })
    })
}
//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//


//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//
checkUserById = (id) =>
{
    return new Promise((resolve, reject) =>
    {

        connection.query(`SELECT * FROM clients_auth WHERE user_id = "` + id + `"`, (err, results) =>
        {
            if (err)
            {
                reject(new Error('Ooops, something broke!'));
            }
            else
            {
                resolve(results);
            }
        })
    })
}
//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//

//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//
getAppIdListFromClientId = (id) =>
{
    return new Promise((resolve, reject) =>
    {

        connection.query(`SELECT * FROM applications_manager WHERE client_id = "` + id + `"`, (err, results) =>
        {
            if (err)
            {
                reject(new Error('Ooops, something broke!'));
            }
            else
            {
                resolve(results);
            }
        })
    })
}
//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//

//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//
getApplicationFromAppId = (id) =>
{
    return new Promise((resolve, reject) =>
    {

        connection.query(`SELECT * FROM applications WHERE app_id = "` + id + `"`, (err, results) =>
        {
            if (err)
            {
                reject(new Error('Ooops, something broke!'));
            }
            else
            {
                resolve(results);
            }
        })
    })
}
//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//

//===========================================================================================================//
//========================   END OF DATABASE QUERIES        =================================================//
//===========================================================================================================//


//===========================================================================================================//
//========================   START OF HELPER FUNCTIONS      =================================================//
//===========================================================================================================//



//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//
makeId = (length) =>
{

    var result = '';
    var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var charactersLength = characters.length;
    for (var i = 0; i < length; i++)
    {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}
//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//

//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//
checkHash = (userInput, hash) =>
{
    return new Promise((resolve, reject) =>
    {
        bcrypt.compare(userInput, hash, (err, res) =>
        {

            if (res)
            {
                resolve(res)
            } else
            {
                reject(new Error('Ooops, They don\'t match'))
            }
        });
    });

}
//-------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------//

//===========================================================================================================//
//========================   END OF HELPER FUNCTIONS      ===================================================//
//===========================================================================================================//






createHash = async () =>
{
    const salt = await bcrypt.genSalt()
    const hashedpassword = await bcrypt.hash("12345", salt)

}




app.get('/rx_data', (req, res) =>
{
    connection.query(SELECT_ALL_RX_DATA, (err, results) =>
    {
        if (err)
        {
            return res.send(err)
        }
        else
        {
            return res.json({
                data: results
            })
        }
    })
})



//=====================================================================================//
//=====================================================================================//
app.listen(4000, () =>
{
    console.log('rx data server listening on port 4000')
})



// https://jonathanmh.com/express-passport-json-web-token-jwt-authentication-beginners/
// https://owasp.org/www-project-cheat-sheets/cheatsheets/Password_Storage_Cheat_Sheet.html#legacy-algorithms
// https://www.pluralsight.com/guides/submit-form-react-without-jquery-ajax

//get the last index of the rx_data
//get app id and device id from client id
//get services {appications} from app id
//
//ui send the email and password and compare here in the database and send ok responce if it match

// *     res.send(new Buffer('wahoo'));
// *     res.send({ some: 'json' });
// *     res.send('<p>some html</p>');
// *     res.send(404, 'Sorry, cant find that');
// *     res.send(404);

//CHECKS
//Check if email already exist when registering