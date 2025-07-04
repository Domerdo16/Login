const fs = require("fs")
const bcrypt = require("bcrypt")

class UsersComponent {
  constructor(statePath) {
    this.users = {}
    this.statePath = statePath
    try {
      this.users = JSON.parse(fs.readFileSync(statePath, "utf-8"))
    } catch(err) {
      console.log(err.message)
      this.serialize()
    }
  }

  serialize() {
    fs.writeFileSync(this.statePath, JSON.stringify(this.users, null, 2))
  }

  getUser(email) {
    return this.users[email]
  }

  async create(email, password) {
    const hash = await bcrypt.hash(password, 10)
    this.users[email] = {
      email,
      hash,
      isVerified: false
    }

    this.serialize()
  }

  async login(email, password) {
    const user = this.users[email]
    if (!user) {
      return null
    }

    if (await bcrypt.compare(password, user.hash)) {
      return user
    } else {
      return null
    }
  }

  async updatePassword(email, newPassword) {
  const user = this.getUser(email)
  if (user) {
    const hashedPassword = await bcrypt.hash(newPassword, 10)
    user.hash = hashedPassword
    this.serialize()
  }
  }
  
  verifyUser(email) {
  const user = this.getUser(email)
  if (user) {
    user.isVerified = true
    this.serialize()
  }
  }

  isUserVerified(email) {
  const user = this.getUser(email);
  return user ? user.isVerified : false
  }
}

module.exports = UsersComponent