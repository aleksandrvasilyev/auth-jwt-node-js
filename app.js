import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import expressEjsLayouts from "express-ejs-layouts";
import { hash, compare } from "bcrypt";
import jsonwebtoken from "jsonwebtoken";
import fs from "fs";

const app = express();

const SECRET = "H6AIgu0wsGCH2mC6ypyRubiPoPSpV4t1";
const PORT = process.env.PORT || 3003;

// Get the directory name
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.set("view engine", "ejs"); // set up view engine to ejs
app.set("layout", "./layouts/main"); // set up layout to main.ejs

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(expressEjsLayouts);

// setup static folder
app.use(express.static(path.join(__dirname, "public")));

const usersDatabase = JSON.parse(fs.readFileSync("./users.json", "utf-8"));

// index page
app.get("/", function (req, res) {
  res.render("index", { usersDatabase });
  // res.send(usersDatabase);
});

// show registration form
app.get("/registration", function (req, res) {
  res.render("registration");
});

// show login form
app.get("/login", function (req, res) {
  res.render("login");
});

// register new user
app.post("/registration", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const passwordConfirm = req.body.password_confirm;

  if (!isValidUser(username, password, passwordConfirm)) {
    res.status(400).send("Invalid User Data").end();
    return;
  }

  if (findUser(username)) {
    res.status(400).send("User already exists").end();
    return;
  }

  const hashedPassword = await hash(password, 12);

  usersDatabase.push({ username, password: hashedPassword });
  fs.writeFileSync("users.json", JSON.stringify(usersDatabase, null, 2));

  res.status(201).send({ username }).end();
});

// login user
app.post("/login", async (req, res) => {
  // 1. get login details from the body
  const { username, password } = req.body;

  // 2. check if user exists
  const user = findUser(username);

  if (!user) {
    res.status(404).send("User not found").end();
    return;
  }

  // 3. check if password is correct
  const isPasswordCorrect = await compare(password, user.password);

  if (!isPasswordCorrect) {
    res.status(400).send("Invalid credentials").end();
    return;
  }

  const token = jsonwebtoken.sign({ username }, SECRET);

  res.status(200).send({ token }).end();
});

const isValidUser = (username, password, password_confirm) => {
  if (
    !username ||
    !password ||
    !password_confirm ||
    password !== password_confirm
  ) {
    return false;
  }

  return true;
};

app.get("/profile", (req, res) => {
  // 1. Get session ID from request
  const token = getToken(req);

  try {
    const decodedUser = jsonwebtoken.verify(token, SECRET);
    res.send();
  } catch (error) {
    console.log("Token verification failed. Error: ", error.message);
    res.send(400);
  }
});

// logout - delete session
app.post("/logout", (req, res) => {
  // 1. Get token from request
  const token = getToken(req);

  try {
    const decodedUser = jsonwebtoken.verify(token, SECRET);
    res.send("logout");

    // need to do delete token on frontend
  } catch (error) {
    console.log("Token verification failed. Error: ", error.message);
  }
});

const findUser = (username) => {
  const user = usersDatabase.find((user) => user.username === username);
  return user;
};

const getToken = (req) => {
  const authorizationHeader = req.headers["authorization"];

  if (!authorizationHeader) {
    return null;
  }

  const token = authorizationHeader.replace("Bearer ", "").trim();
  return token;
};

app.listen(PORT, () => {
  console.log(`App started on port ${PORT}`);
});
