const express = require("express");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const serviceAccount = JSON.parse(
  Buffer.from(process.env.FIREBASE_ADMIN_CREDENTIALS_BASE64, 'base64').toString('utf8')
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.post("/sign_in_with_apple", async (req, res) => {
  try {
    const { id_token } = req.body;
    if (!id_token) {
      return res.status(400).json({ error: "Missing id_token" });
    }

    const decoded = jwt.decode(id_token, { complete: true });
    if (!decoded) {
      return res.status(400).json({ error: "Invalid id_token" });
    }

    const appleSub = decoded.payload.sub;
    const email = decoded.payload.email;
    const firebaseUid = `apple:${appleSub}`;

    await admin.auth().updateUser(firebaseUid, {
      email: email,
    }).catch(async (error) => {
      if (error.code === 'auth/user-not-found') {
        await admin.auth().createUser({
          uid: firebaseUid,
          email: email,
        });
      } else {
        throw error;
      }
    });

    const customToken = await admin.auth().createCustomToken(firebaseUid);
    return res.json({ customToken });
  } catch (error) {
    console.error("Error during Apple sign-in:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/", (req, res) => {
  res.send(`
    <html>
      <body>
        <h2>登入成功，請返回 App</h2>
        <script>
          setTimeout(() => {
            window.location.href = "signinwithapple://callback";
          }, 500);
        </script>
      </body>
    </html>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Apple Sign-In server listening on port ${PORT}`);
});
