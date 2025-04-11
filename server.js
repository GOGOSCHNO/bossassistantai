require('dotenv').config();
const express = require('express');
const multer = require("multer");
const bodyParser = require('body-parser');
const cors = require('cors');
const nodemailer = require("nodemailer");
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const OpenAI = require("openai");
const { MongoClient } = require('mongodb');
const twilio = require('twilio');
const axios = require('axios');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// 📌 Configuration de multer pour gérer l'upload sans stockage sur Heroku
const storage = multer.memoryStorage(); // Stocker temporairement en mémoire
const upload = multer({ storage: storage });

// Configuration OpenAI
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Exemple de token stocké en variable d'env (ou config)
const token = process.env.WHATSAPP_CLOUD_API_TOKEN || "TON_TOKEN_PERMANENT";
const whatsappPhoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID || "TON_PHONE_NUMBER_ID";

// Configuration MongoDB
const mongoUri = process.env.MONGODB_URI;
if (!mongoUri) {
    console.error("❌ Erreur : MONGODB_URI n'est pas défini dans les variables d'environnement.");
    process.exit(1);
}

let db;  // Variable pour stocker la connexion à MongoDB

async function connectToMongoDB() {
  try {
    const mongoClient = new MongoClient(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true });
    await mongoClient.connect();
    db = mongoClient.db('chatbotDB');
    console.log("✅ Connecté à MongoDB avec succès !");
  } catch (err) {
    console.error("❌ Erreur lors de la connexion à MongoDB :", err);
    process.exit(1);
  }
}

// Appel de la connexion MongoDB
connectToMongoDB();

// Middleware
const allowedOrigins = [
  "https://assistantai.site",
  "https://www.assistantai.site"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.json()); // parse le JSON entrant de Meta
app.use(express.static("public"));

app.use(session({
  secret: process.env.JWT_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// Exportation de `db` pour pouvoir l'utiliser ailleurs
module.exports = { db };

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
},
async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    const name = profile.displayName;

    const existingUser = await db.collection('users').findOne({ email });

    if (!existingUser) {
      // Génère un nom de collection unique, ex : threads_1700000000000
      const threadsCollection = "threads_" + Date.now();

      await db.collection('users').insertOne({
        email,
        name,
        googleId: profile.id,
        threadsCollection,
        hasAssistant: false // utile pour afficher un message conditionnel plus tard
      });
    }

    return done(null, { email, name });
  } catch (err) {
    console.error("Erreur OAuth Google :", err);
    return done(err, null);
  }
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

let calendar;

// 📌 Configurer Nodemailer pour l’envoi des emails
const transporter = nodemailer.createTransport({
    host: "smtpout.secureserver.net", // SMTP de GoDaddy
    port: 465, // Port sécurisé SSL
    secure: true, // SSL activé
    auth: {
        user: "assistantai@assistantai.site", // Ton adresse email GoDaddy
        pass: process.env.EMAIL_PASS // Mot de passe stocké en variable d'environnement
    }
});

// 📌 Vérifier la connexion SMTP
transporter.verify(function(error, success) {
    if (error) {
        console.error("Erreur SMTP :", error);
    } else {
        console.log("✅ SMTP prêt à envoyer des emails !");
    }
});

// Fonction pour récupérer ou créer un thread
async function getOrCreateThreadId(userNumber) {
  try {
    const collection = db.collection('threads');
    let thread = await collection.findOne({ userNumber });
    if (!thread) {
      const threadResponse = await openai.beta.threads.create();
      const threadId = threadResponse.id;

      await collection.insertOne({ userNumber, threadId, responses: [] });
      return threadId;
    }
    return thread.threadId;
  } catch (error) {
    console.error('Erreur lors de la récupération ou création du thread:', error);
    throw error;
  }
}

// Fonction pour interagir avec OpenAI
async function interactWithAssistant(userMessage, userNumber) {
    if (!userMessage || userMessage.trim() === "") {
      throw new Error("Le contenu du message utilisateur est vide ou manquant.");
    }
  
    try {
      const threadId = await getOrCreateThreadId(userNumber);
      const currentDateTime = new Date().toLocaleString('es-ES', { timeZone: 'America/Bogota' });
  
      // Envoi du message utilisateur à OpenAI
      await openai.beta.threads.messages.create(threadId, {
        role: "user",
        content: `Mensaje del cliente: "${userMessage}". Nota: El número WhatsApp del cliente es ${userNumber}. Fecha y hora del mensaje: ${currentDateTime}`
      });
  
      // Création d'un nouveau "run" pour générer la réponse
      const runResponse = await openai.beta.threads.runs.create(threadId, {
        assistant_id: "asst_CWMnVSuxZscjzCB2KngUXn5I" // Remplace par ton assistant_id
      });
  
      const runId = runResponse.id;
      // Attente de la fin du run ou d'un éventuel function calling
      const messages = await pollForCompletion(threadId, runId);
  
      console.log("📩 Messages reçus de l'assistant :", messages);
  
      // Sauvegarde des messages et du thread dans MongoDB
      if (messages) {
        const collection = db.collection('threads');
        await collection.updateOne(
          { userNumber },
          {
            $set: { threadId },
            $push: {
              responses: {
                userMessage,
                assistantResponse: {
                  text: messages.text,
                  note: messages.note // ✅ ici on stocke la note !
                },
                timestamp: new Date()
              }
            }
          },
          { upsert: true }
        );
      }
  
      return messages;
    } catch (error) {
      console.error("❌ Erreur lors de l'interaction avec l'assistant:", error);
      throw error;
    }
  }  

// Vérification du statut d'un run
async function pollForCompletion(threadId, runId) {
  return new Promise((resolve, reject) => {
    const interval = 2000;
    const timeoutLimit = 80000;
    let elapsedTime = 0;

    const checkRun = async () => {
      try {
        const runStatus = await openai.beta.threads.runs.retrieve(threadId, runId);
        console.log(`📊 Estado del run: ${runStatus.status}`);

        if (runStatus.status === 'completed') {
          const messages = await fetchThreadMessages(threadId);
          console.log("📩 Réponse finale de l'assistant:", messages);
          resolve(messages);
          return;
        }

        if (runStatus.status === 'requires_action' &&
            runStatus.required_action?.submit_tool_outputs?.tool_calls) {
          const toolCalls = runStatus.required_action.submit_tool_outputs.tool_calls;

          for (const toolCall of toolCalls) {
            let params;
            try {
              params = JSON.parse(toolCall.function.arguments);
            } catch (error) {
              console.error("❌ Erreur en parsant les arguments JSON:", error);
              reject(error);
              return;
            }

            if (toolCall.function.name === "get_image_url") {
              console.log("🖼️ Demande d'URL image reçue:", params);
              const imageUrl = await getImageUrl(params.imageCode);

              const toolOutputs = [{
                tool_call_id: toolCall.id,
                output: JSON.stringify({ imageUrl })
              }];

              await openai.beta.threads.runs.submitToolOutputs(threadId, runId, {
                tool_outputs: toolOutputs
              });

              setTimeout(checkRun, 500);
              return;
            } else {
              console.warn(`⚠️ Fonction non gérée (hors MVP): ${toolCall.function.name}`);
              setTimeout(checkRun, 500);
              return;
            }
          }
        } else {
          elapsedTime += interval;
          if (elapsedTime >= timeoutLimit) {
            console.error("⏳ Timeout (80s), annulation du run...");
            await openai.beta.threads.runs.cancel(threadId, runId);
            reject(new Error("Run annulé après 80s sans réponse."));
            return;
          }

          setTimeout(checkRun, interval);
        }

      } catch (error) {
        console.error("Erreur dans pollForCompletion:", error);
        reject(error);
      }
    };

    checkRun();
  });
}

// Récupérer les messages d'un thread
async function fetchThreadMessages(threadId) {
  try {
    const messagesResponse = await openai.beta.threads.messages.list(threadId);
    const messages = messagesResponse.data.filter(msg => msg.role === 'assistant');

    const latestMessage = messages[0];
    let textContent = latestMessage.content
      .filter(c => c.type === 'text')
      .map(c => c.text.value)
      .join(" ");

    // Extraction des URLs Markdown du texte
    const markdownUrlRegex = /!\[.*?\]\((https?:\/\/[^\s)]+)\)/g;
    let match;
    const markdownImageUrls = [];

    while ((match = markdownUrlRegex.exec(textContent)) !== null) {
      markdownImageUrls.push(match[1]);
    }

    // Nettoyage des URL markdown du texte
    textContent = textContent.replace(markdownUrlRegex, '').trim();

    // Suppression des références internes 【XX:XX†nomfichier.json】
    textContent = textContent.replace(/【\d+:\d+†[^\]]+】/g, '').trim();

    // ➕ Détection et extraction de la nota interna
    let summaryNote = null;
    let statusNote = null;

    const noteStart = textContent.indexOf('--- Nota interna ---');
    if (noteStart !== -1) {
      const noteContent = textContent.slice(noteStart).replace(/[-]+/g, '').trim();

      const resumenMatch = noteContent.match(/Resumen\s*:\s*(.+)/i);
      const estadoMatch = noteContent.match(/Estado\s*:\s*(.+)/i);

      summaryNote = resumenMatch ? resumenMatch[1].trim() : null;
      statusNote = estadoMatch ? estadoMatch[1].trim() : null;

      // Supprimer la note du texte envoyé au client
      textContent = textContent.slice(0, noteStart).trim();
    }

    // ➕ Conversion Markdown OpenAI → Markdown WhatsApp
    function convertMarkdownToWhatsApp(text) {
      return text
        .replace(/\*\*(.*?)\*\*/g, '*$1*')          // Gras
        .replace(/\*(.*?)\*/g, '_$1_')              // Italique
        .replace(/~~(.*?)~~/g, '~$1~')              // Barré
        .replace(/!\[.*?\]\((.*?)\)/g, '')          // Images
        .replace(/\[(.*?)\]\((.*?)\)/g, '$1 : $2')  // Liens
        .replace(/^>\s?(.*)/gm, '$1')               // Citations
        .replace(/^(\d+)\.\s/gm, '- ')              // Listes
        .trim();
    }

    // Application de la conversion Markdown
    textContent = convertMarkdownToWhatsApp(textContent);

    // Récupération des images issues du Function Calling
    const toolMessages = messagesResponse.data.filter(msg => msg.role === 'tool');
    const toolImageUrls = toolMessages
      .map(msg => {
        try {
          return JSON.parse(msg.content[0].text.value).imageUrl;
        } catch {
          return null;
        }
      })
      .filter(url => url != null);

    const images = [...markdownImageUrls, ...toolImageUrls];

    // ✅ Retour complet avec note extraite
    return {
      text: textContent,
      images: images,
      note: {
        summary: summaryNote,
        status: statusNote
      }
    };

  } catch (error) {
    console.error("Erreur lors de la récupération des messages du thread:", error);
    return {
      text: "",
      images: [],
      note: null
    };
  }
}

app.post('/whatsapp', async (req, res) => {
  console.log('Requête reçue :', JSON.stringify(req.body, null, 2));

  try {
    // 1) Vérifier la structure du body : Meta envoie { object, entry: [...] }
    if (
      !req.body.entry ||
      !req.body.entry[0].changes ||
      !req.body.entry[0].changes[0].value.messages
    ) {
      return res.status(200).send('Aucun message entrant.');
    }

    const value = req.body.entry[0].changes[0].value;
    const message = value.messages[0];
    const from = message.from;
    const phoneNumberId = value.metadata.phone_number_id;

    // 2) Déterminer le type de message et extraire le texte
    let userMessage = '';
    if (message.type === 'text' && message.text.body) {
      userMessage = message.text.body.trim();
    } else if (message.type === 'image') {
      userMessage = "Cliente envió una imagen.";
    } else if (message.type === 'audio') {
      userMessage = "Cliente envió un audio.";
    } else {
      userMessage = "Cliente envió un type de message non géré.";
    }

    if (!userMessage) {
      return res.status(200).send('Message vide ou non géré.');
    }

    // 3) Envoyer le message à l'assistant
    const response = await interactWithAssistant(userMessage, from);

    // 3) Récupération de la réponse
    const { text, images } = response;

    // 4) Répondre à l'utilisateur via l’API WhatsApp Cloud
    const apiUrl = `https://graph.facebook.com/v16.0/${phoneNumberId}/messages`;
    const headers = {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    };

    // Envoi du texte si disponible
    if (text) {
      await axios.post(
        apiUrl,
        {
          messaging_product: 'whatsapp',
          to: from,
          text: { body: text },
        },
        { headers }
      );
    }

    // Envoi des images récupérées via function calling
    if (images && images.length > 0) {
      for (const url of images) {
        if (url) {
          await axios.post(
            apiUrl,
            {
              messaging_product: 'whatsapp',
              to: from,
              type: 'image',
              image: { link: url },
            },
            { headers }
        );
        }
      }
    }

    res.status(200).send('Message envoyé avec succès');
  } catch (error) {
    console.error("Erreur lors du traitement du message WhatsApp:", error);
    res.status(500).json({ error: "Erreur interne." });
  }
});

app.post('/api/inscription', upload.single("archivo"), async (req, res) => {
    try {
        const data = req.body;
        const archivo = req.file;

        console.log("📥 Datos recibidos del formulario:", data);

        // 📌 Verificación de campos obligatorios
        if (!data.email || !data.whatsapp || !data.nombre_comercio) {
            console.error("❌ Error: ¡Faltan datos obligatorios!");
            return res.status(400).json({ error: "El correo electrónico, el número de WhatsApp y el nombre del negocio son obligatorios." });
        }

        console.log("📧 Intentando enviar correo a:", data.email);

        // 📌 Guardar la solicitud en la base de datos
        const trialRequests = db.collection("trial_requests");
        await trialRequests.insertOne({
            ...data,
            archivoNombre: archivo ? archivo.originalname : null,
            estado: "pendiente",
            created_at: new Date()
        });

        // 📌 Construcción del resumen de inscripción
        const resumenInscripcion = `
            <p><strong>📌 Nombre del negocio:</strong> ${data.nombre_comercio}</p>
            <p><strong>📞 WhatsApp:</strong> ${data.whatsapp}</p>
            <p><strong>📧 Correo electrónico:</strong> ${data.email}</p>
            <p><strong>🏢 Sector:</strong> ${data.sector || "No especificado"}</p>
            <p><strong>🛍️ Productos/Servicios:</strong> ${data.productosServicios || "No especificado"}</p>
            <p><strong>🎯 Objetivo:</strong> ${data.objetivo || "No especificado"}</p>
            <p><strong>📝 Mensaje adicional:</strong> ${data.mensajeAdicional || "No especificado"}</p>
        `;

        // 📌 Configurar el correo con archivo adjunto (si lo hay)
        const mailOptions = {
            from: `"AssistantAI" <assistantai@assistantai.site>`,
            to: [data.email, "assistantai@assistantai.site"],
            subject: "Tu prueba gratuita está en proceso 🚀",
            html: `<p>Hola, <strong>${data.nombre_comercio}</strong>!</p>
                   <p>Gracias por registrarte en AssistantAI. Estamos preparando tu asistente personalizado.</p>
                   <h3>📄 Resumen de tu inscripción:</h3>
                   ${resumenInscripcion}`,
            attachments: archivo ? [{
                filename: archivo.originalname,
                content: archivo.buffer
            }] : []
        };

        // 📌 Enviar el correo electrónico
        await transporter.sendMail(mailOptions);
        console.log("✅ ¡Correo enviado con éxito!");

        // 📌 Envío del mensaje a WhatsApp usando el nuevo modelo "teste"
        const apiUrl = `https://graph.facebook.com/v18.0/${process.env.WHATSAPP_PHONE_NUMBER_ID}/messages`;
        const headers = {
            "Authorization": `Bearer ${process.env.WHATSAPP_CLOUD_API_TOKEN}`,
            "Content-Type": "application/json"
        };

        const messageData = {
            messaging_product: "whatsapp",
            recipient_type: "individual",
            to: data.whatsapp,
            type: "template",
            template: {
                name: "teste",
                language: {
                    policy: "deterministic",
                    code: "es"
                },
                components: [
                    {
                        type: "body",
                        parameters: [
                            { type: "text", text: data.nombre_comercio }, // {{1}}
                            { type: "text", text: data.email }            // {{2}}
                        ]
                    }
                ]
            }
        };

        console.log("📤 Datos enviados a Meta:", JSON.stringify(messageData, null, 2));

        const response = await axios.post(apiUrl, messageData, { headers });
        console.log("✅ ¡Mensaje de WhatsApp enviado con éxito!");

        res.status(200).json({ message: "¡Inscripción procesada con éxito y mensaje de WhatsApp enviado!" });

    } catch (error) {
        console.error("❌ Error al procesar la inscripción:", error);
        res.status(500).json({ error: "Error interno al procesar la inscripción." });
    }
});

app.get('/whatsapp', (req, res) => {
  // Récupère les paramètres que Meta envoie
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  // Compare le token reçu avec celui que vous avez défini dans Meta for Developers
  if (mode === 'subscribe' && token === 'myVerifyToken123') {
    console.log('WEBHOOK_VERIFIED');
    // Renvoyer challenge pour confirmer la vérification
    res.status(200).send(challenge);
  } else {
    // Token ou mode invalide
    res.sendStatus(403);
  }
});

// Endpoint de vérification
app.get('/', (req, res) => {
  res.send('Le serveur est opérationnel !');
});

// Lancer le serveur
app.listen(PORT, () => {
  console.log(`Le serveur fonctionne sur le port ${PORT}`);
});
// 🔗 Route de départ : redirige vers l’écran Google
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// 🔁 Route de retour (callback) depuis Google
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login.html' }),
  (req, res) => {
    // Générer un token JWT et le stocker dans un cookie HTTP-only
    const token = jwt.sign(
      { email: req.user.email, name: req.user.name }, // ajoute name ici
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: true,      // ⚠️ à désactiver si tu testes en HTTP local
      sameSite: 'None'
    });

    // Rediriger vers la page privée
    res.redirect("https://assistantai.site"); // à adapter selon ta page d’accueil après connexion
  }
);
app.get('/api/me', async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "No autenticado" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await db.collection('users').findOne({ email: decoded.email });

    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    res.json({ name: user.name, email: user.email });
  } catch (err) {
    console.error("Error en /api/me", err);
    res.status(403).json({ error: "Token inválido" });
  }
});
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "Todos los campos son obligatorios." });
  }

  try {
    const existingUser = await db.collection("users").findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: "Este correo ya está registrado." });
    }

    // Tu peux ici ajouter un hash du mot de passe avec bcrypt si tu veux
    await db.collection("users").insertOne({
      name,
      email,
      password, // ⚠️ pas sécurisé, à remplacer par un hash plus tard
      threadsCollection: "threads_" + Date.now(),
      hasAssistant: false
    });

    // Génère un token comme pour Google
    const token = jwt.sign({ email, name }, process.env.JWT_SECRET, {
      expiresIn: '7d'
    });

    res.status(201).json({
      message: "Usuario creado con éxito",
      token  // 👈 on renvoie le token au frontend
    });
  } catch (err) {
    console.error("❌ Error en /api/signup:", err);
    res.status(500).json({ error: "Error del servidor." });
  }
});
app.post("/api/set-cookie", (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: "Token manquant" });
  }

  res.cookie("token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "None"
  });

  res.status(200).json({ message: "Cookie configurado con éxito" });
});
app.post('/api/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: true,
    sameSite: 'None'
  });
  res.status(200).json({ message: "Sesión cerrada" });
});

app.get("/api/mes-conversations", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Non authentifié" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await db.collection("users").findOne({ email: decoded.email });

    if (!user || !user.threadsCollection) {
      return res.status(404).json({ error: "Utilisateur sans assistant ou collection non définie." });
    }

    const clientThreads = db.collection(user.threadsCollection);
    const conversations = await clientThreads.find({}).sort({ "responses.timestamp": -1 }).toArray();

    res.json({ conversations });
  } catch (err) {
    console.error("Erreur dans /api/mes-conversations:", err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

