require("dotenv").config() // allows us to access out environment variables in the .env file
const jwt = require("jsonwebtoken") // to create a web token for the cookie
const marked = require("marked") // for markdown language in the post's content
const sanitizeHTML = require("sanitize-html") // to prevent html tags on the post content
const bcrypt = require("bcrypt") // to encrypt passwords
const cookieParser = require("cookie-parser") // to parse the cookie
const express = require("express")  // get the express package
const db = require("better-sqlite3")("ourApp.db")   // get the better-sqlite3 package and name it
db.pragma("journal_mode = WAL")  // this will just improve the speed of the database
const app = express()               // create an instance of express

// database setup here

// we spell out the database structure
const createTables = db.transaction(() => {
    db.prepare(
        `
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL)    
    `
    ).run()

    db.prepare(
        `
    CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    title STRING NOT NULL,
    body TEXT NOT NULL,
    authorid INTEGER,
    FOREIGN KEY (authorid) REFERENCES users (id)
    )
    `
    ).run()
})

createTables()
// note: we can view sqlite tables via sqlitebrowser.org
// database setup ends here


app.set("view engine", "ejs")       // handles the template engine for our HTML
app.use(express.urlencoded({ extended: false })) // allows us to access the val the the users typed in just by req.body
app.use(express.static("public"))
app.use(cookieParser())

app.use(function (req, res, next) {   // this is a middleware where we can do anytthing with the req and res and the next function
    // make our markdown function available for the post's content
    res.locals.filterUserHTML = function (content) {
        return sanitizeHTML(marked.parse(content), { // 1:  | 2: config object
            allowedTags: ["p", "br", "ul", "li", "ol", "strong", "i", "em", "h1", "h2"],
            allowedAttributes: {}
        })
    }


    res.locals.errors = []            // its like getting in the middle of a request


    // try to decode incoming cookie
    try {
        const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
        req.user = decoded
    } catch (err) {
        req.user = false
    }

    res.locals.user = req.user
    console.log(req.user)


    next()                             // so for example you go to home tinatawag muna to then after nung next it can continue on the request 
})                                     // here everytime a req and res life cycle begins, we start errors as an empty array


app.get("/", (req, res) => {        // /-root of domain
    if (req.user) {
        const postsStatement = db.prepare("SELECT * FROM posts WHERE authorid = ? ORDER BY createdDate DESC")
        const posts = postsStatement.all(req.user.userid) // get all posts with the specified user id
        return res.render("dashboard", { posts })  // if logged-in
    }
    res.render("homepage")          // it gives us access to a request and a response
})

app.get("/login", (req, res) => {
    res.render("login")
})

app.get("/logout", (req, res) => {
    res.clearCookie("ourSimpleApp")
    res.redirect("/")
})

app.post("/login", (req, res) => {
    let errors = [] // we need to set this up globally kasi for example we are at home page u haven't even submitted the form yet

    // input validation
    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.password = ""

    if (req.body.username.trim() == "") errors = ["Invalid Credentials"]
    if (req.body.password == "") errors = ["Invalid Credentials"]

    if (errors.length) {
        return res.render("login", { errors })
    }

    // Find the user
    const userInQuestionStatement = db.prepare("SELECT * FROM users WHERE USERNAME = ?")
    const userInQuestion = userInQuestionStatement.get(req.body.username)

    // if user not found in the db
    if (!userInQuestion) {
        errors = ["Invalid Credentials"]
        return res.render("login", { errors })
    }

    const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password)
    if (!matchOrNot) {
        errors = ["Invalid Credentials"]
        return res.render("login", { errors })
    }

    // give cookie
    // log the user in by giving them a cookie
    // parameter 1: an obnject where we encode here any data we want |   Parameter 2: our secret value to enable us to verify that we are the ones that made the secure value
    const ourTokenValue = jwt.sign({ exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, userid: userInQuestion.id, username: userInQuestion.username }, process.env.JWTSECRET)

    // parameter 1: name  |  parameter 2: string that uniquely identifies a user |  parameter 3: configuration obj
    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,  // this makes it so that client side Javascript cannot access cookies in browser, they will just be automatically be sent with every request
        secure: true, // it will only send cookies if it is a https connection
        sameSite: "strict", // with this we dont' havve to worry about cross-site forgery attacks
        maxAge: 1000 * 60 * 60 * 24, // how long a cookie is good for (in ms)
    })

    res.redirect("/")
})

// another middleware - to allow create-post for logged in users only
// this is done since u can do /create-post on the URNL to view the page
function mustBeLoggedIn(req, res, next) {
    if (req.user) {
        return next()
    }
    return res.redirect("/")
}

// When Express processes the route, it automatically calls mustBeLoggedIn and passes the req, res, and next parameters to it
app.get("/create-post", mustBeLoggedIn, (req, res) => {
    res.render("create-post")
})

function sharedPostValidation(req) {
    const errors = []

    if (typeof req.body.title !== "string") req.body.title = ""
    if (typeof req.body.body !== "string") req.body.body = ""

    // trim - sanitize of strip out html - to avoid users to add script tags on the body
    req.body.title = sanitizeHTML(req.body.title.trim(), { allowedTags: [], allowedAttributes: [] })
    req.body.body = sanitizeHTML(req.body.body.trim(), { allowedTags: [], allowedAttributes: [] })

    if (!req.body.title) errors.push("You must provide a title")
    if (!req.body.body) errors.push("You must provide a body")

    return errors
}

app.get("/edit-post/:id", mustBeLoggedIn, (req, res) => {
    // try to look up the post in question
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)

    // to avoid getting an error when a user typed a id number on the URL that does not exist
    if (!post) {
        return res.redirect("/")
    }


    // if you're not the author, redirect to homepage
    if (post.authorid !== req.user.userid) {
        return res.redirect("/")
    }

    // otherwise, render the edit post template
    res.render("edit-post", { post })
})

app.post("/edit-post/:id", mustBeLoggedIn, (req, res) => {
    // try to look up the post in question
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)

    // to avoid getting an error when a user typed a id number on the URL that does not exist
    if (!post) {
        return res.redirect("/")
    }


    // if you're not the author, redirect to homepage
    if (post.authorid !== req.user.userid) {
        return res.redirect("/")
    }

    const errors = sharedPostValidation(req)

    if (errors.length) {
        return res.render("edit-post", { errors })
    }

    const updateStatement = db.prepare("UPDATE posts SET title = ?, body = ? WHERE id = ?")
    updateStatement.run(req.body.title, req.body.body, req.params.id)

    res.redirect(`/post/${req.params.id}`)
})

app.post("/delete-post/:id", mustBeLoggedIn, (req, res) => {
    // try to look up the post in question
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)

    // to avoid getting an error when a user typed a id number on the URL that does not exist
    if (!post) {
        return res.redirect("/")
    }


    // if you're not the author, redirect to homepage
    if (post.authorid !== req.user.userid) {
        return res.redirect("/")
    }

    const deleteStatement = db.prepare("DELETE FROM posts WHERE id = ?")
    deleteStatement.run(req.params.id)

    res.redirect("/")
})

app.get("/post/:id", mustBeLoggedIn, (req, res) => {
    const statement = db.prepare("SELECT posts.*, username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id = ?")
    const post = statement.get(req.params.id) // to get something from the URL we use params

    if (!post) {
        return res.redirect("/")
    }

    const isAuthor = post.authorid === req.user.userid

    res.render("single-post", { post, isAuthor })
})

app.post("/create-post", mustBeLoggedIn, (req, res) => {
    const errors = sharedPostValidation(req)

    if (errors.length) {
        return res.render("create-post", { errors })
    }

    // save into database
    const ourStatement = db.prepare("INSERT INTO posts (title, body, authorid, createdDate) VALUES (?, ?, ?, ?)")
    const result = ourStatement.run(req.body.title, req.body.body, req.user.userid, new Date().toISOString())

    // redirect them to view the newly created post
    const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID = ?")
    const realPost = getPostStatement.get(result.lastInsertRowid)

    res.redirect(`/post/${realPost.id}`)
})

app.post("/register", (req, res) => {   // when someone sends a post request to this URL
    const errors = [] // we need to set this up globally kasi for example we are at home page u haven't even submitted the form yet

    // input validation
    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.password = ""

    // trim any whitespace on the username
    req.body.username = req.body.username.trim()

    // if there's no username
    if (!req.body.username) errors.push("Username is required")
    if (req.body.username && req.body.username.length < 3) errors.push("Username must be at least 3 characters")
    if (req.body.username && req.body.username.length > 11) errors.push("Username must be at most 10 characters")
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username must only contain letters and numbers")

    // check if username already exists
    const usernameStatement = db.prepare("SELECT * FROM users WHERE username = ?")
    const usernameCheck = usernameStatement.get(req.body.username)

    if (usernameCheck) errors.push("That username is already taken")

    // if password is empty
    if (!req.body.password) errors.push("Password is required")
    if (req.body.password && req.body.password.length < 3) errors.push("Password must be at least 3 characters")

    // to use the errors in our front-end
    if (errors.length) { // if it is not empty
        return res.render("homepage", { errors })  // we give it our errors variable so we can access the errors in our front end
    }

    // save the new user into a database - note this will not run if we have errors
    const salt = bcrypt.genSaltSync(10) // 10 passes of hashing the password
    req.body.password = bcrypt.hashSync(req.body.password, salt)

    const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)") // we set a dynamic value '?', the sqlite prepares a sql statement for us
    const result = ourStatement.run(req.body.username, req.body.password) // then we run it and fill it with the 2 arguments

    const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const ourUser = lookupStatement.get(result.lastInsertRowid)

    // log the user in by giving them a cookie
    // parameter 1: an obnject where we encode here any data we want |   Parameter 2: our secret value to enable us to verify that we are the ones that made the secure value
    const ourTokenValue = jwt.sign({ exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, userid: ourUser.id, username: ourUser.username }, process.env.JWTSECRET)

    // parameter 1: name  |  parameter 2: string that uniquely identifies a user |  parameter 3: configuration obj
    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,  // this makes it so that client side Javascript cannot access cookies in browser, they will just be automatically be sent with every request
        secure: true, // it will only send cookies if it is a https connection
        sameSite: "strict", // with this we dont' havve to worry about cross-site forgery attacks
        maxAge: 1000 * 60 * 60 * 24, // how long a cookie is good for (in ms)
    })

    res.redirect("/")
})

app.listen(3000)                    // tell our app to listen on port 3000