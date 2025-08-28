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
const { google } = require('googleapis');
const { v4: uuidv4 } = require('uuid');
const { ObjectId } = require('mongodb');
const crypto = require('crypto');
const querystring = require('querystring');
const encryptionKey = Buffer.from(process.env.ENCRYPTION_KEY, 'base64'); // ENV: base64 d'une clé 32 bytes
const ivLength = 12;

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

const activeRuns = new Map(); // userNumber -> { threadId, runId }
const locks = new Map(); // userNumber -> bool
const messageQueue = new Map(); // userNumber -> array

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
  await db.collection('processedMessages').createIndex(
    { createdAt: 1 },
    { expireAfterSeconds: 86400 } // 86400 secondes = 24 heures
  );
  console.log("🧹 Index TTL activé sur processedMessages (expiration après 24h).");
}

// Appel de la connexion MongoDB
connectToMongoDB();

// Middleware
const allowedOrigins = new Set([
  'https://comercioai.site',
  'https://www.comercioai.site',
  'https://bossassistantai-439c88409c33.herokuapp.com',
  // (facultatif si tu ouvres des dialogues/iframes FB dans ton domaine)
  'https://www.facebook.com',
  'https://facebook.com'
]);

async function handleMessage(userMessage, userNumber) {
  if (!messageQueue.has(userNumber)) messageQueue.set(userNumber, []);
  messageQueue.get(userNumber).push(userMessage);
  console.log(`🧾 Message ajouté à la file pour ${userNumber} : "${userMessage}"`);

  if (locks.get(userNumber)) return;

  locks.set(userNumber, true);
  console.log(`🔒 Lock activé pour ${userNumber}`);

  try {
    const initialQueue = [...messageQueue.get(userNumber)];
    console.log(`📚 File initiale de ${userNumber} :`, initialQueue);
    messageQueue.set(userNumber, []); // vider temporairement

    const combinedMessage = initialQueue.join(". ");
    const { threadId, runId } = await interactWithAssistant(combinedMessage, userNumber);
    console.log(`🧠 Assistant appelé avec : "${combinedMessage}"`);
    console.log(`📎 threadId = ${threadId}, runId = ${runId}`);
    activeRuns.set(userNumber, { threadId, runId });

    // Vérifier si de nouveaux messages sont arrivés pendant le run
    const newMessages = messageQueue.get(userNumber) || [];
    if (newMessages.length > 0) {
      console.log("⚠️ Réponse ignorée car nouveaux messages après envoi.");
      messageQueue.set(userNumber, [...initialQueue, ...newMessages]);
      locks.set(userNumber, false);
      return await handleMessage("", userNumber);
    }

    const messages = await pollForCompletion(threadId, runId);
    console.log(`📬 Envoi de la réponse finale à WhatsApp pour ${userNumber}`);
    await sendResponseToWhatsApp(messages, userNumber);

    // Enregistrement dynamique de la réponse de l’assistant
    await db.collection('threads').updateOne(
      { userNumber },
      {
        $push: {
          responses: {
            assistantResponse: {
              text: messages.text,
              note: {
                summary: messages.note?.summary || null,
                status: messages.note?.status || null
              },
              timestamp: new Date()
            }
          }
        },
        $set: { threadId }
      }
    );
    console.log("🗃️ Réponse de l’assistant enregistrée dans MongoDB pour", userNumber);
  } catch (error) {
    console.error("❌ Erreur dans handleMessage :", error);
  } finally {
    console.log(`🔓 Lock libéré pour ${userNumber}`);
    locks.set(userNumber, false);

    const remaining = messageQueue.get(userNumber) || [];
    if (remaining.length > 0) {
      const next = remaining.shift();
      messageQueue.set(userNumber, [next, ...remaining]);
      await handleMessage("", userNumber);
      console.log(`➡️ Message restant détecté, relance de handleMessage() pour ${userNumber}`);
    }
  }
}

app.use(cors({
  origin: (origin, cb) => {
    // A) Aucun Origin (ex: appels serveur/Graph, curl, same-origin) -> OK
    if (!origin) return cb(null, true);
    // B) Origin autorisée -> OK
    if (allowedOrigins.has(origin)) return cb(null, true);
    // C) Non autorisée -> on BLOQUE sans lever d'exception (sinon 500)
    console.warn('CORS blocked origin:', origin);
    return cb(null, false);
  },
  credentials: true
}));

// (optionnel mais propre pour les préflight)
app.options('*', cors());

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
        user: "contact@comercioai.site", // Ton adresse email GoDaddy
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
  const existing = await db.collection("threads").findOne({ userNumber });

  // Si un thread OpenAI est déjà associé
  if (existing && existing.threadId && existing.threadId !== "na") {
    return existing.threadId;
  }

  // Sinon, on crée un nouveau thread sur OpenAI
  const thread = await openai.beta.threads.create();
  const newThreadId = thread.id;

  // On met à jour MongoDB avec le vrai threadId
  await db.collection("threads").updateOne(
    { userNumber },
    { $set: { threadId: newThreadId } }
  );

  return newThreadId;
}

// Fonction pour interagir avec OpenAI
async function interactWithAssistant(userMessage, userNumber) {
  try {
    const threadId = await getOrCreateThreadId(userNumber);
    const dateISO = new Date().toLocaleDateString('sv-SE', { timeZone: 'America/Bogota' });
    const heure = new Date().toLocaleTimeString('es-ES', { timeZone: 'America/Bogota' });

    // 💬 Envoi du message utilisateur
    await openai.beta.threads.messages.create(threadId, {
      role: "user",
      content: `Mensaje del cliente: "${userMessage}". Nota: El número WhatsApp del cliente es ${userNumber}. Fecha actual: ${dateISO} Hora actual: ${heure}`
    });
    console.log(`✉️ Message utilisateur ajouté au thread ${threadId}`);

    // ▶️ Création d’un nouveau run
    const runResponse = await openai.beta.threads.runs.create(threadId, {
      assistant_id: "asst_CWMnVSuxZscjzCB2KngUXn5I"
    });
    const runId = runResponse.id;
    console.log(`▶️ Run lancé : runId = ${runId}`);

    // ⏳ Attente de la complétion
    const messages = await pollForCompletion(threadId, runId);

    return { threadId, runId, messages };
  } catch (error) {
    console.error("❌ Erreur dans interactWithAssistant:", error);
    throw error;
  }
}
async function initGoogleCalendarClient() {
    try {
      const serviceAccountJson = process.env.SERVICE_ACCOUNT_KEY; 
      if (!serviceAccountJson) {
        console.error("SERVICE_ACCOUNT_KEY n'est pas défini en variable d'env.");
        return;
      }
      const key = JSON.parse(serviceAccountJson);
      console.log("Compte de service :", key.client_email);
  
      const client = new google.auth.JWT(
        key.client_email,
        null,
        key.private_key,
        ['https://www.googleapis.com/auth/calendar']
      );
      
      await client.authorize();
      calendar = google.calendar({ version: 'v3', auth: client });
      console.log('✅ Client Google Calendar initialisé');
    } catch (error) {
      console.error("❌ Erreur d'init du client Google Calendar :", error);
    }
  }

async function startCalendar() {
  await initGoogleCalendarClient();  // on attend l'init
  if (calendar) {
    try {
      const res = await calendar.calendarList.list();
      console.log('\n📅 Agendas disponibles :');
      (res.data.items || []).forEach(cal => {
        console.log(`- ID: ${cal.id}, Summary: ${cal.summary}`);
      });
    } catch (err) {
      console.error("❌ Erreur lors de la récupération des agendas :", err);
    }
  }
}
  // Appeler une seule fois :
  startCalendar();

  async function createAppointment(params) {
    // Vérifier si le client Google Calendar est déjà initialisé
    if (!calendar) {
      try {
        const serviceAccountJson = process.env.SERVICE_ACCOUNT_KEY;
        if (!serviceAccountJson) {
          console.error("SERVICE_ACCOUNT_KEY n'est pas défini en variable d'env.");
          return { success: false, message: "Service account non configuré." };
        }
        const key = JSON.parse(serviceAccountJson);
        console.log("Compte de service :", key.client_email);
  
        // Création du client JWT
        const client = new google.auth.JWT(
          key.client_email,
          null,
          key.private_key,
          ['https://www.googleapis.com/auth/calendar']
        );
  
        // Authentification
        await client.authorize();
  
        // Initialisation du client Calendar et affectation à la variable globale
        calendar = google.calendar({ version: 'v3', auth: client });
        console.log('✅ Client Google Calendar initialisé dans createAppointment');
      } catch (error) {
        console.error("❌ Erreur lors de l'initialisation de Google Calendar :", error);
        return { success: false, message: "Erreur d'initialisation de Calendar" };
      }
    }
  
    // À partir d'ici, calendar est garanti d'être défini.
    try {
      // Définir l'événement à créer
      const event = {
        summary: `Cita de ${params.customerName}`,
        description: `Téléphone: ${params.phoneNumber}\nService: ${params.service}`,
        start: {
          dateTime: `${params.date}T${params.startTime}:00`, // Ajout des secondes si besoin
          timeZone: 'America/Bogota',
        },
        end: {
          dateTime: `${params.date}T${params.endTime}:00`,
          timeZone: 'America/Bogota',
        },
      };  
  
      // Insertion de l'événement dans l'agenda de diegodfr75@gmail.com
      const calendarRes = await calendar.events.insert({
        calendarId: params.calendarId,
        resource: event,
      });
  
      const eventId = calendarRes.data.id;
      console.log('Événement créé sur Google Calendar, eventId =', eventId);
  
      // Insertion en base de données (MongoDB) avec l'eventId
      await db.collection('appointments').insertOne({
        customerName: params.customerName,
        phoneNumber: params.phoneNumber,
        date: params.date,
        startTime: params.startTime,
        endTime: params.endTime,
        service: params.service,
        googleEventId: eventId
      });
  
      return { success: true, message: 'Cita creada en Calendar y Mongo', eventId };
    } catch (error) {
      console.error("Erreur lors de la création de l'événement :", error);
      return { success: false, message: 'No se pudo crear la cita.' };
    }
  }
// Vérification du statut d'un run
async function pollForCompletion(threadId, runId, userNumber) {
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

        if (
          runStatus.status === 'requires_action' &&
          runStatus.required_action?.submit_tool_outputs?.tool_calls
        ) {
          const toolCalls = runStatus.required_action.submit_tool_outputs.tool_calls;
          const toolOutputs = [];

          for (const toolCall of toolCalls) {
            const { function: fn, id } = toolCall;
            let params;

            try {
              params = JSON.parse(fn.arguments);
            } catch (error) {
              console.error("❌ Erreur en parsant les arguments JSON:", error);
              reject(error);
              return;
            }

            switch (fn.name) {
              case "getAppointments": {
                if (!calendar) {
                  await initGoogleCalendarClient(); // au cas où non initialisé
                }
              
                try {
                  const startOfDay = `${params.date}T00:00:00-05:00`; // Bogota timezone
                  const endOfDay = `${params.date}T23:59:59-05:00`;
              
                  const res = await calendar.events.list({
                    calendarId: params.calendarId,
                    timeMin: new Date(startOfDay).toISOString(),
                    timeMax: new Date(endOfDay).toISOString(),
                    singleEvents: true,
                    orderBy: 'startTime',
                  });
              
                  const appointments = res.data.items.map(event => ({
                    start: event.start.dateTime,
                    end: event.end.dateTime,
                    summary: event.summary,
                  }));
              
                  toolOutputs.push({
                    tool_call_id: id,
                    output: JSON.stringify(appointments),
                  });
                } catch (error) {
                  console.error("❌ Erreur lors de la récupération des RDV Google Calendar :", error);
                  toolOutputs.push({
                    tool_call_id: id,
                    output: JSON.stringify({ error: "Erreur Google Calendar" }),
                  });
                }
                break;
              }

              case "cancelAppointment": {
                const wasDeleted = await cancelAppointment(params.phoneNumber);

                toolOutputs.push({
                  tool_call_id: id,
                  output: JSON.stringify({
                    success: wasDeleted,
                    message: wasDeleted
                      ? "La cita ha sido cancelada."
                      : "No se encontró ninguna cita para ese número."
                  })
                });
                break;
              }

              case "createAppointment": {
                const result = await createAppointment(params);

                toolOutputs.push({
                  tool_call_id: id,
                  output: JSON.stringify({
                    success: result.success,
                    message: result.message
                  })
                });
                break;
              }

              case "get_image_url": {
                console.log("🖼️ Demande d'URL image reçue:", params);
                const imageUrl = await getImageUrl(params.imageCode);

                toolOutputs.push({
                  tool_call_id: id,
                  output: JSON.stringify({ imageUrl })
                });
                break;
              }

              case "notificar_comerciante": {
                console.log("📣 Function calling détectée : notificar_comerciante");
                const { estado, numero_cliente } = params;
                await enviarAlertaComerciante(estado, numero_cliente);
                toolOutputs.push({
                  tool_call_id: id,
                  output: JSON.stringify({ success: true })
                });
                break;
              }
              default:
                console.warn(`⚠️ Fonction inconnue (non gérée) : ${fn.name}`);
            }
          }

          if (toolOutputs.length > 0) {
            await openai.beta.threads.runs.submitToolOutputs(threadId, runId, {
              tool_outputs: toolOutputs
            });
          }

          setTimeout(checkRun, 500);
          return;
        }

        elapsedTime += interval;
        if (elapsedTime >= timeoutLimit) {
          console.error("⏳ Timeout (80s), annulation du run...");
          await openai.beta.threads.runs.cancel(threadId, runId);
          reject(new Error("Run annulé après 80s sans réponse."));
          return;
        }

        setTimeout(checkRun, interval);

      } catch (error) {
        console.error("Erreur dans pollForCompletion:", error);
        reject(error);
      }
    };

    checkRun();
  });
}

async function enviarAlertaComerciante(estado, numeroCliente) {
  const numeroComerciante = "573009016472"; // numéro fixe
  const apiUrl = `https://graph.facebook.com/v18.0/${process.env.WHATSAPP_PHONE_NUMBER_ID}/messages`;
  const headers = {
    Authorization: `Bearer ${process.env.WHATSAPP_CLOUD_API_TOKEN}`,
    "Content-Type": "application/json"
  };

  const messageData = {
    messaging_product: "whatsapp",
    recipient_type: "individual",
    to: numeroComerciante,
    type: "template",
    template: {
      name: "confirmacion",  // le modèle que tu as validé
      language: {
        policy: "deterministic",
        code: "es"
      },
      components: [
        {
          type: "body",
          parameters: [
            { type: "text", text: estado },        // correspond à {{1}}
            { type: "text", text: numeroCliente }  // correspond à {{2}}
          ]
        }
      ]
    }
  };

  try {
    await axios.post(apiUrl, messageData, { headers });
    console.log("✅ Alerta enviada al comerciante:", numeroComerciante);
  } catch (err) {
    console.error("❌ Error al enviar alerta al comerciante:", err.response?.data || err.message);
  }
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

    // --- Extraction des URLs d'image dans le texte (jpg, png, webp, etc)
    const imageUrlRegex = /https?:\/\/[^\s)]+?\.(?:png|jpg|jpeg|webp|gif)/gi;
    let imageUrls = [];
    let match;
    while ((match = imageUrlRegex.exec(textContent)) !== null) {
      imageUrls.push(match[0]);
    }
    // Nettoyage du texte : on retire les URLs brutes et préfixes "Imagen:"
    imageUrls.forEach(url => {
      textContent = textContent.replace(new RegExp(`(Imagen:?\\s*)?${url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'g'), '');
    });
    textContent = textContent.replace(/\n{2,}/g, '\n').trim();

    // Suppression des références internes 【XX:XX†nomfichier.json】
    textContent = textContent.replace(/【\d+:\d+†[^\]]+】/g, '').trim();

    // Extraction et suppression des URLs directes (hors Markdown)
    const plainUrlRegex = /(https?:\/\/[^\s]+)/g;
    const imageExtensions = /\.(png|jpg|jpeg|webp|gif)$/i;
    let plainMatch;
    const plainImageUrls = [];
    while ((plainMatch = plainUrlRegex.exec(textContent)) !== null) {
      // Optionnel : ne prendre que les images
      if (imageExtensions.test(plainMatch[1])) {
        plainImageUrls.push(plainMatch[1]);
        // Supprime cette URL du texte à envoyer
        textContent = textContent.replace(plainMatch[1], '').replace(/\s\s+/g, ' ').trim();
      }
    }

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

    // ➕ Conversion Markdown OpenAI → Markdown WhatsApp (optionnel, adapte si tu veux)
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
    textContent = convertMarkdownToWhatsApp(textContent);

    // Extraction d’images issues du Function Calling (par sécurité, utile si jamais assistant les place là)
    // Récupération de toutes les URLs d'images issues du Function Calling (JSON)
    const toolMessages = messagesResponse.data.filter(msg => msg.role === 'tool');
    const toolImageUrls = [];
    for (const msg of toolMessages) {
      const value = msg.content?.[0]?.text?.value;
      if (value) {
        try {
          // On attend {"imageUrl": "url"}
          const obj = JSON.parse(value);
          if (obj.imageUrl && obj.imageUrl.startsWith('http')) {
            toolImageUrls.push(obj.imageUrl);
          }
        } catch (e) {
          // Si ce n’est pas du JSON (rare), on tente de récupérer direct une url brute
          if (typeof value === "string" && value.startsWith('http')) {
            toolImageUrls.push(value);
          }
        }
      }
    }

    // ➡️ On fusionne toutes les URLs extraites (texte + function calling), sans doublon
    const images = Array.from(new Set([
      ...imageUrls,
      ...plainImageUrls,
      ...toolImageUrls
    ]));

    console.log("🖼️ Images extraites dans fetchThreadMessages:", images);

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

async function getImageUrl(imageCode) {
  try {
    const image = await db.collection("images").findOne({ _id: imageCode });

    if (image && image.url) {
      console.log(`✅ URL trouvée pour le code "${imageCode}" : ${image.url}`);
    } else {
      console.warn(`⚠️ Aucune URL trouvée pour le code "${imageCode}".`);
    }

    return image ? image.url : null;
  } catch (error) {
    console.error("❌ Erreur récupération URL image:", error);
    return null;
  }
}

async function sendResponseToWhatsApp(response, userNumber) {
  const { text, images } = response;
  console.log("📤 Envoi WhatsApp : texte =", text, "images =", images);
  const apiUrl = `https://graph.facebook.com/v16.0/${whatsappPhoneNumberId}/messages`;
  const headers = {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  };

  if (text) {
    const payloadText = {
      messaging_product: 'whatsapp',
      to: userNumber,
      text: { body: text },
    };

    console.log("📦 Payload TEXT vers WhatsApp :", JSON.stringify(payloadText, null, 2));
    console.log("🌍 URL POST utilisée :", apiUrl);

    await axios.post(apiUrl, payloadText, { headers });
  }

  if (images && images.length > 0) {
    for (const url of images) {
      if (url) {
        const payloadImage = {
          messaging_product: 'whatsapp',
          to: userNumber,
          type: 'image',
          image: { link: url },
        };

        console.log("📦 Payload IMAGE vers WhatsApp :", JSON.stringify(payloadImage, null, 2));
        console.log("🌍 URL POST utilisée :", apiUrl);

        await axios.post(apiUrl, payloadImage, { headers });
      }
    }
  }
}


async function sendConsentRequest(userNumber) {
  try {
    const payload = {
      messaging_product: "whatsapp",
      to: userNumber,
      type: "interactive",
      interactive: {
        type: "button",
        body: {
          text: "👋 ¡Hola! Antes de continuar, necesitamos tu autorización para procesar tus datos (como nombre, número y citas) a través de este canal WhatsApp API. Solo los usaremos para ayudarte.\n\nConsulta nuestra política: comercioai.site/politica-de-privacidad"
        },
        action: {
          buttons: [
            {
              type: "reply",
              reply: {
                id: "consent_si",
                title: "✅ Sí, acepto"
              }
            },
            {
              type: "reply",
              reply: {
                id: "consent_no",
                title: "❌ No, gracias"
              }
            }
          ]
        }
      }
    };

    console.log("📤 Envoi du message de consentement à :", userNumber);
    console.log("📦 Payload envoyé :", JSON.stringify(payload, null, 2));

    const response = await fetch(
      `https://graph.facebook.com/v19.0/${process.env.WHATSAPP_PHONE_NUMBER_ID}/messages`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.WHATSAPP_CLOUD_API_TOKEN}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("❌ Erreur API WhatsApp :", response.status, data);
    } else {
      console.log("✅ Message de consentement envoyé avec succès :", data);

      // 💾 Enregistrement assistantResponse dans MongoDB
      await db.collection('threads').updateOne(
        { userNumber },
        {
          $setOnInsert: {
            threadId: 'na',
            consent: false
          },
          $set: {
            consentAskedAt: new Date()
          },
          $push: {
            responses: {
              assistantResponse: {
                text: payload.interactive.body.text,
                timestamp: new Date()
              }
            }
          }
        },
        { upsert: true }
      );
    }
  } catch (err) {
    console.error("❌ Exception dans sendConsentRequest :", err);
  }
}

async function currentUser(req){
  const t = req.cookies?.token; if(!t) throw new Error('No autenticado');
  const d = jwt.verify(t, process.env.JWT_SECRET);
  const u = await db.collection('users').findOne({ email: d.email });
  if(!u) throw new Error('Usuario no encontrado'); return u;
}
function isE164(s){ return /^\+[1-9]\d{7,14}$/.test(String(s||'').trim()); }

function signState(payload){
  const raw = JSON.stringify(payload);
  const sig = crypto.createHmac('sha256', process.env.APP_SECRET).update(raw).digest('hex');
  return Buffer.from(JSON.stringify({ raw, sig })).toString('base64url');
}
async function verifyState(b64){
  const parsed = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
  const { raw, sig } = parsed || {};
  const exp = crypto.createHmac('sha256', process.env.APP_SECRET).update(raw).digest('hex');
  if(sig !== exp) throw new Error('state inválido');
  return JSON.parse(raw);
}
function encrypt(text) {
  const iv = crypto.randomBytes(ivLength);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return iv.toString('hex') + ':' + encrypted + ':' + authTag;
}

function decrypt(token) {
  const [ivHex, encryptedHex, authTagHex] = token.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const encrypted = Buffer.from(encryptedHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, null, 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Helper currentUser (déjà existant, mais rappel pour cohérence)
async function currentUser(req) {
  const token = req.cookies.token;
  if (!token) throw new Error('No autenticado');
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const user = await db.collection('users').findOne({ email: decoded.email });
  if (!user) throw new Error('Usuario no encontrado');
  return user;
}
function getErrorMessage(err) {
  const metaError = err.response?.data?.error;
  if (metaError) {
    switch (metaError.code) {
      case 100: return 'Parámetro inválido o faltante. Verifica los datos enviados.';
      case 131009: return 'Código de verificación inválido o expirado.';
      case 131021: return 'Rate limit alcanzado. Espera unos minutos e intenta de nuevo.';
      case 190: return 'Access token expirado o inválido. Reconecta via Embedded Signup.';
      case 200: return 'Permisos insuficientes. Verifica los scopes en la app Meta.';
      default: return metaError.message || 'Error desconocido de Meta.';
    }
  }
  return err.message || 'Error interno del servidor.';
}
app.post('/whatsapp', async (req, res) => {
  try {
    const entry = req.body.entry?.[0]?.changes?.[0]?.value?.messages?.[0];
    if (!entry) return res.sendStatus(200);

    const message = entry;
    console.log("📨 Message reçu :", JSON.stringify(message, null, 2));
    console.log("🔍 Type de message :", message.type);

    const userNumber = message.from;
    const messageId = message.id;

    // 🔄 Vérifier si le message a déjà été traité
    const alreadyProcessed = await db.collection('processedMessages').findOne({ messageId });
    if (alreadyProcessed) {
      console.log("⚠️ Message déjà traité, on ignore :", messageId);
      return res.status(200).send("Message déjà traité.");
    }
    await db.collection('processedMessages').insertOne({ messageId, createdAt: new Date() });

    // 🧠 Cas 1 : Réponse à un bouton interactif (consentement)
    if (message.type === 'interactive' && message.interactive?.type === 'button_reply') {
      const payload = message.interactive.button_reply.id;
      const title = message.interactive.button_reply.title;

      console.log("🔘 Réponse bouton reçue - payload:", payload, "| titre:", title);

      if (payload === 'consent_si' || payload === 'consent_no') {
        // 💾 Enregistrer la réponse utilisateur dans MongoDB
        await db.collection('threads').updateOne(
          { userNumber },
          {
            $push: {
              responses: {
                userMessage: title,
                timestamp: new Date()
              }
            }
          }
        );
      
        if (payload === 'consent_si') {
          await db.collection('threads').updateOne(
            { userNumber },
            { $set: { consent: true, consentAt: new Date() } }
          );
          await sendResponseToWhatsApp(
            { text: "✅ ¡Gracias por aceptar! Ahora puedes usar nuestro asistente." },
            userNumber
          );
        }
      
        if (payload === 'consent_no') {
          await sendResponseToWhatsApp(
            { text: "Entendido 😊 No procesaremos tus datos. Escríbenos si cambias de opinión." },
            userNumber
          );
        }
      
        return res.sendStatus(200);
      }
    }

    // 🧠 Cas 2 : Message utilisateur standard
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

    // 🗃️ Enregistrement du message utilisateur
    await db.collection('threads').updateOne(
      { userNumber },
      {
        $setOnInsert: {
          threadId: 'na',
          consent: false
        },
        $push: {
          responses: {
            userMessage,
            timestamp: new Date()
          }
        }
      },
      { upsert: true }
    );
    console.log("🗃️ Message utilisateur enregistré pour", userNumber);

    // 🔍 Vérifier le consentement
    const thread = await db.collection('threads').findOne({ userNumber });
    if (!thread.consent) {
      await sendConsentRequest(userNumber);
      return res.sendStatus(200);
    }

    // ✅ assistant_id défini en dur ici
    const assistantId = "asst_CWMnVSuxZscjzCB2KngUXn5I";

    // 🔎 Recherche du user correspondant à cet assistant_id
    const user = await db.collection('users').findOne({ assistant_id: assistantId });

    if (!user || user.autoReplyEnabled === false) {
      console.log("⏹️ Assistant désactivé pour ce compte.");
      return res.sendStatus(200);
    }

    // ▶️ Traitement normal si assistant activé
    await handleMessage(userMessage, userNumber);

    res.sendStatus(200);
  } catch (error) {
    console.error("❌ Erreur dans /whatsapp :", error);
    res.sendStatus(500);
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
            from: `"ComercioAI" <contact@comercioai.site>`,
            to: [data.email, "contact@comercioai.site"],
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
                name: "confirmacion",
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
    res.redirect("https://www.comercioai.site"); // à adapter selon ta page d’accueil après connexion
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
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email y contraseña requeridos." });
  }

  try {
    const user = await db.collection("users").findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "Usuario no encontrado." });
    }

    // ⚠️ Comparaison simple (à remplacer par bcrypt plus tard)
    if (user.password !== password) {
      return res.status(401).json({ error: "Contraseña incorrecta." });
    }

    const token = jwt.sign({ email: user.email, name: user.name }, process.env.JWT_SECRET, {
      expiresIn: "7d"
    });

    res.status(200).json({ token });

  } catch (err) {
    console.error("❌ Error en /api/login:", err);
    res.status(500).json({ error: "Error del servidor." });
  }
});

app.get('/api/appointments', async (req, res) => {
  const phone = req.query.phone;
  if (!phone) return res.status(400).json({ error: "Numéro manquant" });

  const appt = await db.collection("appointments").findOne({ phoneNumber: phone });
  if (!appt) return res.json({});

  res.json({
    name: appt.customerName,
    date: appt.date,
    startTime: appt.startTime
  });
});
app.post("/api/crear-asistente", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "No autenticado" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const email = decoded.email;
    const user = await db.collection("users").findOne({ email });

    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    if (user.hasAssistant) {
      return res.status(400).json({ error: "Este usuario ya tiene un asistente." });
    }

    // Créer assistant OpenAI
    const assistant = await openai.beta.assistants.create({
      name: `Asistente de ${user.name}`,
      instructions: "Responde como asistente comercial por WhatsApp.",
      model: "gpt-4o"
    });

    // Générer nom de collection threads
    const threadsCollection = "threads_" + Date.now();
    await db.createCollection(threadsCollection);

    // Mettre à jour le document utilisateur
    await db.collection("users").updateOne(
      { email },
      {
        $set: {
          assistant_id: assistant.id,
          hasAssistant: true,
          threadsCollection
        }
      }
    );

    // ✅ Rediriger vers page de config (optionnelle)
    res.status(200).json({ message: "Asistente creado", assistantId: assistant.id });
  } catch (err) {
    console.error("❌ Error en /api/crear-asistente:", err);
    res.status(500).json({ error: "Error interno" });
  }
});

app.post('/api/configurar-instrucciones', async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "No autenticado" });

  const { instructions, rawData } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await db.collection("users").findOne({ email: decoded.email });

    if (!user || !user.assistant_id) {
      return res.status(404).json({ error: "Asistente no encontrado para este usuario." });
    }

    const assistantId = user.assistant_id;

    // 1. Mise à jour des instructions système
    await openai.beta.assistants.update(assistantId, { instructions });

    // 2. Enregistrement des données brutes en base
    await db.collection("users").updateOne(
      { email: decoded.email },
      {
        $set: {
          configuracion_asistente: rawData,
          updatedAt: new Date()
        }
      }
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Erreur lors de la mise à jour de l'assistant :", err);
    res.status(500).json({ error: "Erreur interne" });
  }
});

app.get("/api/formulario", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "No autenticado" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const email = decoded.email;

    const doc = await db.collection("form_data").findOne({ email });

    if (!doc) {
      return res.status(404).json({ error: "No se encontraron datos del formulario" });
    }

    res.json({ rawData: doc.rawData || {} });
  } catch (err) {
    console.error("❌ Error en /api/formulario:", err);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});
app.post("/api/enviar-recordatorio", async (req, res) => {
  const { nombre, fecha, hora, numero } = req.body;

  if (!nombre || !fecha || !hora || !numero) {
    return res.status(400).json({ error: "Faltan datos obligatorios." });
  }

  const apiUrl = `https://graph.facebook.com/v18.0/${process.env.WHATSAPP_PHONE_NUMBER_ID}/messages`;
  const headers = {
    Authorization: `Bearer ${process.env.WHATSAPP_CLOUD_API_TOKEN}`,
    "Content-Type": "application/json"
  };

  const messageData = {
    messaging_product: "whatsapp",
    recipient_type: "individual",
    to: numero,
    type: "template",
    template: {
      name: "recordatorio", // ✅ Ton modèle Meta validé
      language: {
        policy: "deterministic",
        code: "es"
      },
      components: [
        {
          type: "body",
          parameters: [
            { type: "text", text: nombre }, // {{1}}
            { type: "text", text: fecha },  // {{2}}
            { type: "text", text: hora },   // {{3}}
            { type: "text", text: " " }      // {{4}} = vide
          ]
        }
      ]
    }
  };

  try {
    await axios.post(apiUrl, messageData, { headers });
    console.log(`✅ Recordatorio enviado a ${numero}`);
    res.status(200).json({ success: true });
  } catch (err) {
    console.error("❌ Error al enviar recordatorio:", err.response?.data || err.message);
    res.status(500).json({ error: "Error al enviar recordatorio." });
  }
});
app.get("/api/auto-reply-status", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "No autenticado" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await db.collection("users").findOne({ email: decoded.email });

    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    res.json({ autoReplyEnabled: user.autoReplyEnabled !== false }); // true par défaut
  } catch (err) {
    res.status(500).json({ error: "Error interno" });
  }
});

app.post("/api/auto-reply-toggle", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "No autenticado" });

  const { autoReplyEnabled } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await db.collection("users").findOne({ email: decoded.email });

    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    await db.collection("users").updateOne(
      { email: decoded.email },
      { $set: { autoReplyEnabled: !!autoReplyEnabled } }
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Error al actualizar autoReplyEnabled:", err);
    res.status(500).json({ error: "Error interno" });
  }
});
app.post("/api/enviar-mensaje-manual", async (req, res) => {
  const { numero, mensaje } = req.body;

  if (!numero || !mensaje) {
    return res.status(400).json({ error: "Número y mensaje requeridos." });
  }

  const apiUrl = `https://graph.facebook.com/v16.0/${process.env.WHATSAPP_PHONE_NUMBER_ID}/messages`;
  const headers = {
    Authorization: `Bearer ${process.env.WHATSAPP_CLOUD_API_TOKEN}`,
    "Content-Type": "application/json"
  };

  const payload = {
    messaging_product: "whatsapp",
    to: numero,
    type: "text",
    text: { body: mensaje }
  };

  try {
    // 1. 🟢 Envoi WhatsApp
    await axios.post(apiUrl, payload, { headers });
    console.log(`✅ Mensaje manual enviado a ${numero}`);

    // 2. 🗃️ Enregistrement MongoDB
    await db.collection("threads").updateOne(
      { userNumber: numero },
      {
        $push: {
          responses: {
            adminResponse: {
              text: mensaje,
              timestamp: new Date()
            }
          }
        },
        $setOnInsert: { threadId: "na" }
      },
      { upsert: true }
    );
    console.log("🗃️ Mensaje del comerciante guardado en MongoDB para", numero);

    res.status(200).json({ success: true });
  } catch (err) {
    console.error("❌ Error al enviar mensaje manual:", err.response?.data || err.message);
    res.status(500).json({ error: "Error al enviar mensaje manual." });
  }
});

app.get('/api/mis-citas', async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "No autenticado" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await db.collection("users").findOne({ email: decoded.email });

    if (!user || !user.appointmentsCollection) {
      return res.status(404).json({ error: "appointmentsCollection no definido para este usuario." });
    }

    const collectionName = user.appointmentsCollection;
    const citas = await db.collection(collectionName).find({}).toArray();

    res.json(citas);
  } catch (err) {
    console.error("❌ Error en /api/mis-citas:", err);
    res.status(500).json({ error: "Error interno del servidor." });
  }
});
app.post('/api/eliminar-cita', async (req, res) => {
  const { citaId } = req.body;
  if (!citaId) return res.status(400).send("ID manquant");

  try {
    const result = await db.collection('appointments').deleteOne({ _id: new ObjectId(citaId) });
    if (result.deletedCount === 1) {
      res.sendStatus(200);
    } else {
      res.status(404).send("Cita non trouvée");
    }
  } catch (err) {
    console.error("Erreur suppression:", err);
    res.status(500).send("Erreur serveur");
  }
});
app.post("/api/editar-cita", async (req, res) => {
  const { _id, date, startTime, endTime, customerName, phoneNumber, service } = req.body;
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "No autenticado" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await db.collection("users").findOne({ email: decoded.email });

    if (!user || !user.appointmentsCollection) {
      return res.status(404).json({ error: "appointmentsCollection no definido." });
    }

    const collection = db.collection(user.appointmentsCollection);

    await collection.updateOne(
      { _id: new ObjectId(_id) },
      {
        $set: {
          date,
          startTime,
          endTime,
          customerName,
          phoneNumber,
          service
        }
      }
    );

    res.json({ success: true });
  } catch (err) {
    console.error("❌ Error al editar cita:", err);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// GET /api/whatsapp/number/draft
app.get('/api/whatsapp/number/draft', async (req,res)=>{
  try{
    const u = await currentUser(req);
    const draft = u.whatsappDraft || null;
    res.json(draft || {});
  }catch(e){
    const code = e.message==='No autenticado'?401:500;
    res.status(code).json({ error: e.message });
  }
});

// POST /api/whatsapp/number/draft  { waNumber }
app.post('/api/whatsapp/number/draft', async (req,res)=>{
  try{
    const u = await currentUser(req);
    const waNumber = String(req.body?.waNumber||'').trim();
    if(!isE164(waNumber)) return res.status(400).json({ error:'Formato E.164 inválido' });

    const now = new Date();
    await db.collection('users').updateOne(
      { _id: u._id },
      { $set: { 'whatsappDraft.waNumber': waNumber, 'whatsappDraft.updatedAt': now },
        $setOnInsert: { 'whatsappDraft.createdAt': now } }
    );
    res.json({ ok:true, waNumber });
  }catch(e){
    const code = e.message==='No autenticado'?401:500;
    res.status(code).json({ error: e.message });
  }
});

// (Opcional) POST /api/whatsapp/number/clear
app.post('/api/whatsapp/number/clear', async (req,res)=>{
  try{
    const u = await currentUser(req);
    await db.collection('users').updateOne(
      { _id: u._id }, { $unset: { whatsappDraft: '' } }
    );
    res.json({ ok:true });
  }catch(e){
    const code = e.message==='No autenticado'?401:500;
    res.status(code).json({ error: e.message });
  }
});
app.get('/api/whatsapp/embedded/start', async (req,res)=>{
  try{
    const u = await currentUser(req); // helper que tu as déjà
    const state = signState({ email: u.email, ts: Date.now() });

    // scopes minimaux pour ESU & gestion business/WABA (ajuste si Meta t’en demande d’autres)
    const scope = [
      'business_management',
      'whatsapp_business_management',
      'whatsapp_business_messaging'
    ].join(',');

    const url = 'https://www.facebook.com/v20.0/dialog/oauth?' + querystring.stringify({
      client_id: process.env.APP_ID,
      redirect_uri: process.env.ESU_REDIRECT_URI,
      state,
      response_type: 'code',
      scope
    });

    res.json({ url });
  }catch(e){
    res.status(401).json({ error: 'No autenticado' });
  }
});

app.get('/api/whatsapp/status', async (req, res) => {
  try {
    const u = await currentUser(req); // ton helper JWT
    const w = u.whatsapp || {};
    res.json({
      connected: !!w.connected,
      mode: w.mode || null,
      phoneNumberIdMasked: w.phoneNumberId ? '••••' + String(w.phoneNumberId).slice(-6) : null,
      wabaId: w.wabaId || null,
      businessId: w.businessId || null,
      waNumber: w.waNumber || null,
      tokenMasked: w.accessToken ? '••••' + String(w.accessToken).slice(-4) : null,
      connectedAt: w.connectedAt || null
    });
  } catch (e) {
    res.status(401).json({ error: 'No autenticado' });
  }
});

// 📌 Callback de l’Embedded Signup
app.get('/api/whatsapp/embedded/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.status(400).send('Faltan parámetros');

    // Vérifie le state signé (email du user, ts, etc.)
    const s = await verifyState(state);

    // 1) code -> user access_token
    const tokenRes = await fetch(
      `https://graph.facebook.com/v20.0/oauth/access_token?` +
      querystring.stringify({
        client_id: process.env.APP_ID,
        client_secret: process.env.APP_SECRET,
        redirect_uri: process.env.ESU_REDIRECT_URI,
        code
      })
    );
    const tokenBody = await tokenRes.json();
    if (!tokenRes.ok) {
      console.error('Token exchange failed:', tokenBody);
      return res.redirect('/conectar-whatsapp.html?esu=error');
    }
    const userToken = tokenBody.access_token;

    // 2) Récupère les Business accessibles pour l’utilisateur
    const meRes = await fetch(
      `https://graph.facebook.com/v20.0/me?fields=businesses{id,name}&access_token=${encodeURIComponent(userToken)}`
    );
    const me = await meRes.json();
    if (!meRes.ok) {
      console.error('Graph /me failed:', me);
      return res.redirect('/conectar-whatsapp.html?esu=error');
    }
    const businesses = me.businesses?.data || [];
    if (businesses.length === 0) {
      console.warn('Aucun Business accessible pour ce compte.');
      // On sauve quand même le token, et on redirige: l’UI pourra afficher “WABA non trouvé”
      const u0 = await db.collection('users').findOne({ email: s.email });
      if (u0) {
        await db.collection('users').updateOne(
          { _id: u0._id },
          { $set: {
              whatsapp: {
                connected: false,
                mode: 'produccion',
                wabaId: null,
                businessId: null,
                phoneNumberId: null,
                waNumber: null,
                accessToken: userToken,
                connectedAt: new Date()
              }
            } }
        );
      }
      return res.redirect('/conectar-whatsapp.html?esu=ok');
    }

    // 3) Lis les WABA + numéros du premier Business (ou applique ta logique de sélection)
    const biz = businesses[0];
    const bizFields = 'owned_whatsapp_business_accounts{id,name,phone_numbers{id,display_phone_number,verified_name}}';
    const bizRes = await fetch(
      `https://graph.facebook.com/v20.0/${biz.id}?fields=${encodeURIComponent(bizFields)}&access_token=${encodeURIComponent(userToken)}`
    );
    const bizData = await bizRes.json();
    if (!bizRes.ok) {
      console.error('Graph business failed:', bizData);
      return res.redirect('/conectar-whatsapp.html?esu=error');
    }

    const wabas = bizData.owned_whatsapp_business_accounts?.data || [];
    const waba = wabas[0] || null;
    // (selon l’API, phone_numbers est souvent un edge paginé .data)
    const phone = waba?.phone_numbers?.data?.[0] || waba?.phone_numbers?.[0] || null;

    // 4) Sauvegarde dans users.whatsapp
    const u = await db.collection('users').findOne({ email: s.email });
    if (!u) return res.redirect('/conectar-whatsapp.html?esu=error');

    await db.collection('users').updateOne(
      { _id: u._id },
      { $set: {
          whatsapp: {
            connected: !!(waba && phone),
            mode: 'produccion',
            wabaId: waba?.id || null,
            businessId: biz.id,
            phoneNumberId: phone?.id || null,
            waNumber: phone?.display_phone_number || null,
            accessToken: encrypt(userToken), // Chiffrer ici
            connectedAt: new Date()
          }
        } }
    );

    // 5) Redirige vers la page de connexion WhatsApp
    return res.redirect('/conectar-whatsapp.html?esu=ok');
  } catch (e) {
    console.error('❌ ESU callback error:', e);
    return res.redirect('/conectar-whatsapp.html?esu=error');
  }
});
// POST /api/whatsapp/number/request-code
app.post('/api/whatsapp/number/request-code', async (req, res) => {
  try {
    const user = await currentUser(req);
    const { code_method = 'SMS', locale = 'es_ES' } = req.body; // Par défaut SMS, es_ES pour espagnol
    const { wabaId } = user.whatsapp || {};
    if (!wabaId) return res.status(400).json({ error: 'WABA no configurado' });

    // Utiliser un numéro draft si pas de phoneNumberId
    const phoneNumberId = user.whatsapp.phoneNumberId || null;
    if (!phoneNumberId) return res.status(400).json({ error: 'Número de teléfono no disponible. Usa /api/whatsapp/number/draft primero.' });

    const accessToken = decrypt(user.whatsapp.accessToken); // Déchiffrer

    const apiUrl = `https://graph.facebook.com/v20.0/${phoneNumberId}/request_code`;
    const response = await axios.post(apiUrl, { code_method, language: locale }, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (response.data.success) {
      // Pas de champs supplémentaires à persister typiquement ici
      res.json({ success: true, message: 'Código solicitado exitosamente' });
    } else {
      throw new Error('Respuesta inesperada de Meta');
    }
  } catch (err) {
    console.error('Error en request-code:', err.response?.data || err.message);
    const errorMsg = getErrorMessage(err);
    res.status(err.response?.status || 500).json({ error: errorMsg });
  }
});

// POST /api/whatsapp/number/verify-code
app.post('/api/whatsapp/number/verify-code', async (req, res) => {
  try {
    const user = await currentUser(req);
    const { code } = req.body;
    if (!code || code.length !== 6) return res.status(400).json({ error: 'Código de 6 dígitos requerido' });

    const phoneNumberId = user.whatsapp.phoneNumberId || null;
    if (!phoneNumberId) return res.status(400).json({ error: 'Número de teléfono no disponible' });

    const accessToken = decrypt(user.whatsapp.accessToken);

    const apiUrl = `https://graph.facebook.com/v20.0/${phoneNumberId}/verify_code`;
    const response = await axios.post(apiUrl, { code }, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (response.data.success) {
      // Pas de champs supplémentaires ici
      res.json({ success: true, message: 'Código verificado exitosamente' });
    } else {
      throw new Error('Respuesta inesperada de Meta');
    }
  } catch (err) {
    console.error('Error en verify-code:', err.response?.data || err.message);
    const errorMsg = getErrorMessage(err);
    res.status(err.response?.status || 500).json({ error: errorMsg });
  }
});

// POST /api/whatsapp/number/register
app.post('/api/whatsapp/number/register', async (req, res) => {
  try {
    const user = await currentUser(req);
    const { messaging_product = 'whatsapp', pin } = req.body; // PIN optionnel si requis par Meta

    const phoneNumberId = user.whatsapp.phoneNumberId || null;
    if (!phoneNumberId) return res.status(400).json({ error: 'Número de teléfono no disponible' });

    const accessToken = decrypt(user.whatsapp.accessToken);

    const payload = { messaging_product };
    if (pin) payload.pin = pin; // Si Meta demande un PIN pour l'enregistrement

    const apiUrl = `https://graph.facebook.com/v20.0/${phoneNumberId}/register`;
    const response = await axios.post(apiUrl, payload, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (response.data.success) {
      // Mettre à jour connected: true et persister champs supplémentaires si renvoyés (ex: verified_name)
      const updateFields = { 'whatsapp.connected': true };
      if (response.data.verified_name) updateFields['whatsapp.verified_name'] = response.data.verified_name;
      if (response.data.quality_rating) updateFields['whatsapp.quality_rating'] = response.data.quality_rating;

      await db.collection('users').updateOne(
        { _id: user._id },
        { $set: updateFields }
      );

      res.json({ success: true, message: 'Número registrado exitosamente', data: response.data });
    } else {
      throw new Error('Respuesta inesperada de Meta');
    }
  } catch (err) {
    console.error('Error en register:', err.response?.data || err.message);
    const errorMsg = getErrorMessage(err);
    res.status(err.response?.status || 500).json({ error: errorMsg });
  }
});

// POST /api/whatsapp/test (smoke test d’envoi)
app.post('/api/whatsapp/test', async (req, res) => {
  try {
    const user = await currentUser(req);
    const { to } = req.body; // Numéro destinataire (ex: +573001234567)
    if (!to) return res.status(400).json({ error: 'Número destinatario requerido' });

    const { phoneNumberId, connected } = user.whatsapp || {};
    if (!connected || !phoneNumberId) return res.status(400).json({ error: 'WhatsApp no conectado' });

    const accessToken = decrypt(user.whatsapp.accessToken);

    const apiUrl = `https://graph.facebook.com/v20.0/${phoneNumberId}/messages`;
    const payload = {
      messaging_product: 'whatsapp',
      to,
      type: 'text',
      text: { body: 'Hola from ComercioAI! Esto es un test.' }
    };

    const response = await axios.post(apiUrl, payload, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (response.data.messages?.[0]?.id) {
      res.json({ success: true, message: 'Mensaje de test enviado', messageId: response.data.messages[0].id });
    } else {
      throw new Error('Respuesta inesperada de Meta');
    }
  } catch (err) {
    console.error('Error en test send:', err.response?.data || err.message);
    const errorMsg = getErrorMessage(err);
    res.status(err.response?.status || 500).json({ error: errorMsg });
  }
});
