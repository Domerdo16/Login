require("dotenv").config()
const express = require("express")
const path = require("path")
const cookieParser = require("cookie-parser")
const jwt = require("jsonwebtoken")
const SECRET_KEY = process.env.SECRET_KEY
const UsersComponent = require("./UsersComponent")
const usersComponent = new UsersComponent("./state.json")
const nodemailer = require("nodemailer")
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
})
transporter.verify((error, success) => {
  if (error) {
    console.error("Errore nella configurazione di Gmail SMTP:", error)
  } else {
    console.log("Gmail SMTP configurato correttamente!")
  }
})

const os = require("os");
function getLocalIPAddress() {
  const interfaces = os.networkInterfaces()
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === "IPv4" && !iface.internal) {
        return iface.address;
      }
    }
  }
  return "localhost"; // Fallback su localhost
}
const localIP = getLocalIPAddress()

function authenticateToken(req, res, next) {
  const token = req.cookies.token
  if (!token) return res.redirect("/login")

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.redirect("/login")
    req.user = user
    next()
  })
}

const app = new express()
const PORT = process.env.PORT



app.use(express.urlencoded({ extended: true }))
app.use(express.static("public"))
app.use(cookieParser())



app.get("/api/user", authenticateToken, (req, res) => {
  res.json({ email: req.user.email })
})

app.get("/", authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, "./public/home.html"))
})



app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "./public/login.html"))
})

app.post("/login", async (req, res) => {
  const email = req.body.email
  const password = req.body.password

  const user = usersComponent.getUser(email)

  if (!user) {
    return res.status(401).sendFile(path.join(__dirname, "./public/email-not-registered.html"))
  }

  const isPasswordValid = await usersComponent.login(email, password)

  if (isPasswordValid) {
    const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: "1h" })
    res.cookie("token", token, { httpOnly: true })
    res.redirect("/")
  } else {
    res.status(401).sendFile(path.join(__dirname, "./public/incorrect-password.html"))
  }
})



app.get("/forgot-password", (req, res) => {
  res.sendFile(path.join(__dirname, "./public/forgot-password.html"))
})

app.post("/forgot-password", async (req, res) => {
  const email = req.body.email
  const user = usersComponent.getUser(email)

  if (!user) {
    return res.sendFile(path.join(__dirname, "./public/email-not-found.html"))
  }

  const resetToken = jwt.sign({ email: email }, SECRET_KEY, { expiresIn: "15m" })
  const resetLink = `http://${localIP}:${PORT}/reset-password?token=${resetToken}`

  const mailOptions = {
    from: "panepene14@gmail.com",
    to: email,
    subject: "Recupero Password",
    html: `
      <h1>Recupero Password</h1>
      <p>Clicca sul link qui sotto per resettare la tua password:</p>
      <a href="${resetLink}">Resetta la tua password</a>
      <p>Il link scadrà in 15 minuti.</p>
    `
  }

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Errore nell'invio dell'email:", error)
      res.status(500).send("Errore nell'invio dell'email.")
    } else {
      console.log("Email inviata con successo:", info.response)
      res.sendFile(path.join(__dirname, "./public/check-email.html"))
    }
  })
})



app.get("/reset-password", (req, res) => {
  const token = req.query.token

  console.log("Token ricevuto:", token)

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      console.error("Errore nella verifica del token:", err.message)
      return res.sendFile(path.join(__dirname, "./public/invalid-link.html"))
    }

    res.sendFile(path.join(__dirname, "./public/reset-password.html"))
  })
})

app.post("/reset-password", async (req, res) => {
  const token = req.body.token
  const newPassword = req.body.newPassword

  jwt.verify(token, SECRET_KEY, async (err, decoded) => {
    if (err) {
      console.error("Errore nella verifica del token:", err.message)
      return res.sendFile(path.join(__dirname, "./public/invalid-link.html"))
    }

    const email = decoded.email
    console.log("Email decodificata:", email)

    try {
      await usersComponent.updatePassword(email, newPassword)
      console.log("Password aggiornata con successo per:", email)
      res.sendFile(path.join(__dirname, "./public/password-updated.html"))
    } catch (updateError) {
      console.error("Errore durante l'aggiornamento della password:", updateError)
      res.status(500).send("Errore durante l'aggiornamento della password.")
    }
  })
})



app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "./public/signup.html"))
})

app.post("/signup", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  if (usersComponent.getUser(email)) {
    return res.redirect("/signup?error=email_in_use");
  } else {
    await usersComponent.create(email, password)
    const token = jwt.sign({ email: email }, SECRET_KEY, { expiresIn: "1h" })
    res.cookie("token", token, { httpOnly: true });
    res.redirect("/");
  }
});



app.post("/logout", (req, res) => {
  res.clearCookie("token")
  res.redirect("/login")
})



app.use((req, res) => {
  res.sendFile(path.join(__dirname, "./public/404.html"))
})

app.listen(PORT, () => console.log("Server listening on port", PORT))