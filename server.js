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
  return "localhost";
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

  if (user && await usersComponent.login(email, password)) {
    if (!usersComponent.isUserVerified(email)) {
      return res.redirect("/login?error=Email non verificata. Controlla la tua email per il link di verifica.")
    }

    const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: "1h" })
    res.cookie("token", token, { httpOnly: true })
    res.redirect("/")
  } else {
    res.redirect("/login?error=Email o password errate.")
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
  const email = req.body.email
  const password = req.body.password

  if (usersComponent.getUser(email)) {
    return res.redirect("/signup?error=Email già registrata.")
  } else {
    const verificationToken = jwt.sign({ email: email }, SECRET_KEY, { expiresIn: "1h" })
    const verificationLink = `http://${localIP}:${PORT}/verify-email?token=${verificationToken}`

    const mailOptions = {
      from: "panepene14@gmail.com",
      to: email,
      subject: "Verifica il tuo account",
      html: `
        <h1>Verifica il tuo account</h1>
        <p>Clicca sul link qui sotto per verificare il tuo account:</p>
        <a href="${verificationLink}">Verifica il tuo account</a>
        <p>Il link scadrà in 1 ora.</p>
      `
    }

    transporter.sendMail(mailOptions, async (error, info) => {
      if (error) {
        console.error("Errore nell'invio dell'email di verifica:", error)
        res.status(500).send("Errore nell'invio dell'email di verifica.")
      } else {
        console.log("Email di verifica inviata con successo:", info.response)
        await usersComponent.create(email, password)
        res.sendFile(path.join(__dirname, "./public/check-email.html"))
      }
    })
  }
})



app.get("/verify-email", async (req, res) => {
  const token = req.query.token

  jwt.verify(token, SECRET_KEY, async (err, decoded) => {
    if (err) {
      console.error("Errore nella verifica del token:", err.message)
      return res.sendFile(path.join(__dirname, "./public/invalid-link.html"))
    }

    const email = decoded.email
    const user = usersComponent.getUser(email)

    if (user && user.isVerified) {
      return res.sendFile(path.join(__dirname, "./public/email-already-verified.html"))
    }

    try {
      usersComponent.verifyUser(email)
      console.log("Email verificata:", email)
      res.sendFile(path.join(__dirname, "./public/email-verified.html"))
    } catch (updateError) {
      console.error("Errore durante la verifica dell'email:", updateError)
      res.status(500).send("Errore durante la verifica dell'email.")
    }
  })
})



app.post("/logout", (req, res) => {
  res.clearCookie("token")
  res.redirect("/login")
})



app.use((req, res) => {
  res.sendFile(path.join(__dirname, "./public/404.html"))
})

app.listen(PORT, () => console.log("Server listening on port", PORT))