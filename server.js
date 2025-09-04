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

// Vérification du statut d'un run
async function pollForCompletion(threadId, runId) {
  return new Promise((resolve, reject) => {
    const interval = 2000;           // 2s
    const timeoutLimit = 80000;      // 80s
    let elapsedTime = 0;

    const checkRun = async () => {
      try {
        const runStatus = await openai.beta.threads.runs.retrieve(threadId, runId);
        console.log(`📊 Run status: ${runStatus.status}`);

        // ✅ Terminé → on polit et on renvoie
        if (runStatus.status === 'completed') {
          const messages = await fetchThreadMessages(threadId);
          return resolve(messages);
        }

        // 🔧 Tool calls demandés
        if (runStatus.status === 'requires_action' &&
            runStatus.required_action?.submit_tool_outputs?.tool_calls?.length) {
          const toolCalls = runStatus.required_action.submit_tool_outputs.tool_calls;
          const tool_outputs = [];

          for (const { id, function: fn } of toolCalls) {
            let params;
            try {
              params = JSON.parse(fn.arguments || "{}");
            } catch (e) {
              console.error("❌ Tool args parse error:", e);
              return reject(e);
            }

            if (fn.name === "getAppointments") {
            }

            else if (fn.name === "createAppointment") {
              
            }

          }

          if (tool_outputs.length > 0) {
            await openai.beta.threads.runs.submitToolOutputs(threadId, runId, { tool_outputs });
          }

          // Reboucle rapidement après soumission
          return setTimeout(checkRun, 500);
        }

        // ⏳ Timeout de sécurité
        elapsedTime += interval;
        if (elapsedTime >= timeoutLimit) {
          console.error("⏳ Timeout 80s → cancel run");
          await openai.beta.threads.runs.cancel(threadId, runId);
          return reject(new Error("Run timed out"));
        }

        // ↻ Continue de poller
        return setTimeout(checkRun, interval);

      } catch (err) {
        console.error("❌ pollForCompletion error:", err);
        return reject(err);
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

function isE164(s){ return /^\+[1-9]\d{7,14}$/.test(String(s||'').trim()); }

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

function maskTail(str, tail = 4) {
  if (!str) return '';
  const s = String(str);
  return '•'.repeat(Math.max(0, s.length - tail)) + s.slice(-tail);
}

// 🔹 Résoudre le tenant (commerçant) à partir du phone_number_id
async function getTenantByPhoneNumberId(phoneNumberId) {
  if (!phoneNumberId) return null;
  return await db.collection('users').findOne(
    { "whatsapp.phoneNumberId": phoneNumberId },
    {
      projection: {
        name: 1,
        email: 1,
        assistant_id: 1,
        threadsCollection: 1,
        whatsapp: 1,
        configuracion_asistente: 1,
      }
    }
  );
}

// 🔹 Idempotence
async function isDuplicateMessage(messageId) {
  if (!messageId) return false;
  const found = await db.collection('processedMessages').findOne({ messageId });
  return !!found;
}
async function markMessageProcessed(messageId) {
  if (!messageId) return;
  await db.collection('processedMessages').insertOne({ messageId, createdAt: new Date() });
}

// 🔹 Normalisation minimale (texte + bouton; image/audio gardés pour itération suivante)
function normalizeIncoming(raw) {
  const base = {
    id: raw?.id,
    from: raw?.from,                    // numéro du client final (e.g. "5730…")
    timestamp: raw?.timestamp,
    type: raw?.type,
    text: null,
    interactive: null,
    attachments: null,                  // future-proof
  };

  if (raw?.type === 'text') {
    base.text = raw?.text?.body ?? '';
  } else if (raw?.type === 'interactive' && raw?.interactive?.type === 'button_reply') {
    base.interactive = {
      kind: 'button_reply',
      id: raw?.interactive?.button_reply?.id,
      title: raw?.interactive?.button_reply?.title,
    };
  } else if (raw?.type === 'image') {
    base.attachments = { kind: 'image', payload: raw?.image };
  } else if (raw?.type === 'audio') {
    base.attachments = { kind: 'audio', payload: raw?.audio };
  }

  return base;
}

app.get('/whatsapp', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  const VERIFY_TOKEN = process.env.META_VERIFY_TOKEN;

  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('✅ Webhook vérifié');
    return res.status(200).send(challenge);
  }
  console.log('❌ Webhook verification failed');
  return res.sendStatus(403);
});


/**
 * POST /whatsapp
 * Réception des événements WhatsApp (multi-tenant)
 *
 * Étapes:
 * 1) Extraire le message et metadata
 * 2) Résoudre le tenant via metadata.phone_number_id
 * 3) Idempotence
 * 4) Normaliser le message
 * 5) Appeler la logique existante handleMessage(message, context)
 */
app.post('/whatsapp', async (req, res) => {
  try {
    // 1) Extraire la notification
    const change = req.body?.entry?.[0]?.changes?.[0]?.value;
    const message = change?.messages?.[0];
    const metadata = change?.metadata;

    // ⚠️ Répondre vite à Meta
    res.status(200).send('OK');

    if (!message) {
      console.log('ℹ️ Aucun message dans le payload');
      return;
    }

    const phoneNumberId = metadata?.phone_number_id;
    const displayPhone = metadata?.display_phone_number;

    console.log('📨 Inbound', {
      messageId: message?.id,
      type: message?.type,
      from: message?.from,
      phoneNumberId,
      displayPhone
    });

    // 2) Résoudre le tenant
    const tenant = await getTenantByPhoneNumberId(phoneNumberId);
    if (!tenant) {
      console.error('🚫 Tenant introuvable pour phone_number_id:', phoneNumberId);
      return;
    }

    // 3) Idempotence
    const msgId = message.id;
    if (await isDuplicateMessage(msgId)) {
      console.log('⚠️ Déjà traité, on ignore:', msgId);
      return;
    }
    await markMessageProcessed(msgId);

    // 4) Normaliser
    const normalized = normalizeIncoming(message);

    // 5) Contexte multi-tenant passé à ta logique existante (handleMessage)
    const context = {
      // Identité tenant
      tenantId: tenant._id?.toString?.() ?? null,
      tenantName: tenant.name,

      // Assistant & threads du tenant
      assistantId: tenant.assistant_id,               // utilisé plus tard par interactWithAssistant
      threadsCollection: tenant.threadsCollection,     // utilisé plus tard par getOrCreateThreadId

      // WABA du tenant (pour l’envoi sortant vers le bon numéro)
      whatsapp: {
        phoneNumberId: tenant.whatsapp?.phoneNumberId,
        accessToken: tenant.whatsapp?.accessToken,     // ⚠️ ne jamais logguer en clair
        wabaId: tenant.whatsapp?.wabaId,
      },

      // Pour logs/traçabilité
      correlation: {
        phoneNumberId,
        messageId: normalized.id,
        customerNumber: normalized.from,
        receivedAt: new Date().toISOString(),
      },

      // Configs d’assistant éventuelles (textes, consentement, etc.)
      config: tenant.configuracion_asistente || {},
    };

    // 👇 On garde ton flux tel quel: handleMessage -> interactWithAssistant -> pollForCompletion -> sendResponseToWhatsApp
    await handleMessage(normalized, context);

  } catch (err) {
    // On a déjà renvoyé 200 à Meta; log local
    console.error('💥 Erreur /whatsapp:', err?.stack || err?.message || err);
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

    // 0) Vérif de l’état (si tu stockes email dans state)
    const s = await verifyState(state); // { email, ts, ... }
    if (!s?.email) return res.status(400).send('Estado inválido');

    // 1) Échange code -> access_token (token utilisateur)
    const tokenRes = await fetch(`https://graph.facebook.com/v20.0/oauth/access_token?` +
      new URLSearchParams({
        client_id: process.env.APP_ID,
        client_secret: process.env.APP_SECRET,
        redirect_uri: process.env.ESU_REDIRECT_URI, // doit matcher exactement
        code
      })
    );
    const tokenBody = await tokenRes.json();
    if (!tokenRes.ok || !tokenBody?.access_token) {
      console.error('Token exchange failed', tokenBody);
      return res.redirect('/conectar-whatsapp.html?esu=error');
    }
    const userToken = tokenBody.access_token;

    // (option) log scopes pour diagnostiquer les permissions
    // await debugTokenScopes(userToken);

    // 2) Lire les businesses de l'utilisateur puis les WABA + numéros
    // On évite le me?fields=businesses (qui peut 100) et on fait 2 appels lisibles.
    const bizRes = await fetch(`https://graph.facebook.com/v20.0/me/businesses?` + 
      new URLSearchParams({
        fields: 'id,name,owned_whatsapp_business_accounts{id,name,phone_numbers{id,display_phone_number,verified_name}}',
        access_token: userToken
      })
    );
    const bizBody = await bizRes.json();
    if (!bizRes.ok) {
      console.error('Graph /me/businesses failed:', bizBody);
      return res.redirect('/conectar-whatsapp.html?esu=error');
    }

    // 3) Choix: premier business / premier WABA / premier numéro
    const business = bizBody?.data?.[0] || null;
    const waba = business?.owned_whatsapp_business_accounts?.data?.[0] || null;
    const phone = waba?.phone_numbers?.data?.[0] || null;

    if (!business || !waba || !phone) {
      console.error('ESU: no business/waba/phone found', { business: !!business, waba: !!waba, phone: !!phone });
      return res.redirect('/conectar-whatsapp.html?esu=error');
    }

    const businessId = business.id;
    const wabaId = waba.id;
    const phoneNumberId = phone.id;
    const waNumber = phone.display_phone_number;

    // 4) Souscrire la WABA à l'app => nécessaire pour recevoir les webhooks sur /whatsapp
    await subscribeWabaToApp(wabaId, userToken);

    // 5) Sauvegarde en base (users.whatsapp)
    const u = await db.collection('users').findOne({ email: s.email });
    if (!u) {
      console.error('Usuario no encontrado para', s.email);
      return res.redirect('/conectar-whatsapp.html?esu=error');
    }

    await db.collection('users').updateOne(
      { _id: u._id },
      {
        $set: {
          whatsapp: {
            connected: true,
            mode: 'produccion',
            businessId,
            wabaId,
            phoneNumberId,
            waNumber,
            accessToken: userToken, // ⚠️ en prod: chiffrer ce champ
            connectedAt: new Date()
          }
        }
      }
    );

    console.log('ESU OK →', {
      businessId,
      wabaId,
      phoneNumberId: maskTail(phoneNumberId),
      waNumber
    });

    // 6) Retour page avec succès
    return res.redirect('/conectar-whatsapp.html?esu=ok');
  } catch (e) {
    console.error('ESU callback error', e);
    return res.redirect('/conectar-whatsapp.html?esu=error');
  }
});
