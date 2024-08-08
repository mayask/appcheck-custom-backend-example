const fs = require('fs')

require('dotenv-safe').config();

const express = require('express')
const { initializeApp, applicationDefault } = require('firebase-admin/app')
const { getAppCheck } = require("firebase-admin/app-check")

const app = express()
const port = 3000
const firebaseApp = initializeApp()

app.get('/', (req, res) => {
  fs.readFile(__dirname + '/index.html', 'utf8', (err, text) => {
    res.send(text)
  })
})

const appCheckVerification = (verifyOptions) => async (req, res, next) => {
  const appCheckToken = req.header("X-Firebase-AppCheck");

  if (!appCheckToken) {
    res.status(401);
    return next("Unauthorized");
  }

  try {
    const appCheckClaims = await getAppCheck().verifyToken(appCheckToken, verifyOptions)

    if (appCheckClaims.alreadyConsumed) {
      res.status(401)
      return next('Token already consumed')
    }

    return next();
  } catch (err) {
    console.log(err)
    res.status(401);
    return next("Unauthorized");
  }
}

app.get('/endpoint1', [appCheckVerification({ consume: false })], (req, res) => {
  res.send('GET /endpoint1 is protected by Firebase AppCheck')
})

app.get('/endpoint2', [appCheckVerification({ consume: true })], (req, res) => {
  res.send('GET /endpoint2 is protected against replay attacks by Firebase AppCheck')
})

app.listen(port, () => {
  console.log(`App listening on port ${port}`)
})