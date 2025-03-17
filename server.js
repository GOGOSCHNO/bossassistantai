require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const OpenAI = require("openai");
const { MongoClient } = require('mongodb');
const twilio = require('twilio');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

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
app.use(cors({
  origin: 'https://www.puravivecoach.com', // Remplace par l'URL de ton front-end si nécessaire
  credentials: true
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.json()); // parse le JSON entrant de Meta

// Exportation de `db` pour pouvoir l'utiliser ailleurs
module.exports = { db };

const { google } = require('googleapis');
let calendar;

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

async function listCalendars() {
  try {
    const res = await calendar.calendarList.list();
    console.log('Calendriers visibles par la service account :');
    (res.data.items || []).forEach(cal => {
      console.log(`- ID: ${cal.id}, Summary: ${cal.summary}`);
    });
  } catch (err) {
    console.error("Erreur listCalendars:", err);
  }
}

async function startCalendar() {
  await initGoogleCalendarClient();  // on attend l'init
  if (calendar) {
    await listCalendars();           // maintenant, calendar est défini
  }
}

// Appeler une seule fois :
startCalendar();

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
        assistant_id: "asst_7gcQiaUIhHn6P9ts1te0Fzpo" // Remplace par ton assistant_id
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
                assistantResponse: messages,
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
      // Intervalle entre deux vérifications de statut :
      const interval = 2000;      // Cada 2 seg
      // Limite de temps avant un abandon :
      const timeoutLimit = 80000; // Máx 80 seg
      let elapsedTime = 0;
  
      const checkRun = async () => {
        try {
          // Récupérer le statut du run
          const runStatus = await openai.beta.threads.runs.retrieve(threadId, runId);
          console.log(`📊 Estado del run: ${runStatus.status}`);
  
          // 1) Si le run est terminé : on récupère la réponse finale
          if (runStatus.status === 'completed') {
            const messages = await fetchThreadMessages(threadId);
            console.log("📩 Respuesta final del asistente:", messages);
            resolve(messages);
            return;
          }
  
          // 2) Si le run demande une action (function calling)
          else if (runStatus.status === 'requires_action') {
            console.log("🔄 El asistente solicita llamadas a funciones.");
  
            // On vérifie s'il y a des tool_calls à effectuer
            if (runStatus.required_action?.submit_tool_outputs?.tool_calls) {
              const toolCalls = runStatus.required_action.submit_tool_outputs.tool_calls;
  
              for (const toolCall of toolCalls) {
                console.log("🔍 Función solicitada:", toolCall.function.name);
  
                // Lecture des arguments de la fonction
                let params;
                try {
                  params = JSON.parse(toolCall.function.arguments);
                } catch (error) {
                  console.error("❌ Error parseando los argumentos JSON:", error);
                  reject(error);
                  return;
                }
  
                // Gestion de chaque fonction spécifique
                try {
                  switch (toolCall.function.name) {
                    
                    // *************** getAppointments ***************
                    case "getAppointments": {
                      console.log("📅 Parámetros para getAppointments:", params);
                      const appointments = await db.collection("appointments")
                                                  .find({ date: params.date })
                                                  .toArray();
  
                      // Construire la sortie
                      const toolOutputs = [{
                        tool_call_id: toolCall.id,
                        output: JSON.stringify(appointments),
                      }];
  
                      // Envoyer la réponse de la fonction à OpenAI
                      await openai.beta.threads.runs.submitToolOutputs(threadId, runId, {
                        tool_outputs: toolOutputs
                      });
  
                      // Retourner dans le polling (pas de resolve ici)
                      setTimeout(checkRun, 500);
                      return; // on quitte cette itération
  
                    }
  
                    // *************** cancelAppointment ***************
                    case "cancelAppointment": {
                      console.log("📅 Parámetros para cancelAppointment:", params);
                      const wasDeleted = await cancelAppointment(params.phoneNumber);
  
                      const toolOutputs = [{
                        tool_call_id: toolCall.id,
                        output: JSON.stringify({
                          success: wasDeleted,
                          message: wasDeleted
                            ? "La cita ha sido cancelada."
                            : "No se encontró ninguna cita para ese número."
                        })
                      }];
  
                      await openai.beta.threads.runs.submitToolOutputs(threadId, runId, {
                        tool_outputs: toolOutputs
                      });
  
                      // Revenir au polling
                      setTimeout(checkRun, 500);
                      return;
                    }
  
                    // *************** createAppointment ***************
                    case "createAppointment": {
                      console.log("📅 Parámetros para createAppointment:", params);
                      const result = await createAppointment(params);
  
                      const toolOutputs = [{
                        tool_call_id: toolCall.id,
                        output: JSON.stringify({
                          success: result.success,
                          message: result.message
                        })
                      }];
  
                      await openai.beta.threads.runs.submitToolOutputs(threadId, runId, {
                        tool_outputs: toolOutputs
                      });
  
                      // Revenir au polling
                      setTimeout(checkRun, 500);
                      return;
                    }
  
                    default: {
                      console.warn(`⚠️ Función desconocida: ${toolCall.function.name}`);
                      // On peut simplement relancer le polling si nécessaire
                      setTimeout(checkRun, 500);
                      return;
                    }
                  }
  
                } catch (error) {
                  console.error(`❌ Error en la función ${toolCall.function.name}:`, error);
                  reject(error);
                  return;
                }
              } // fin du for (const toolCall...)
            } // fin du if toolCalls
  
            // Si le runStatus est requires_action mais qu'il n'y a pas de tool_calls,
            // on relance juste le polling
            setTimeout(checkRun, interval);
          }
  
          // 3) Sinon (status "running" ou autre) : on continue le polling
          else {
            elapsedTime += interval;
            if (elapsedTime >= timeoutLimit) {
              console.error("⏳ Timeout (80s) => Cancelando run...");
              await openai.beta.threads.runs.cancel(threadId, runId);
              reject(new Error("Run cancelado tras 20s sin respuesta."));
              return;
            }
  
            setTimeout(checkRun, interval);
          }
  
        } catch (error) {
          console.error("❌ Error en pollForCompletion:", error);
          reject(error);
        }
      };
  
      // Premier appel de la boucle
      checkRun();
    });
  }  

// Récupérer les messages d'un thread
async function fetchThreadMessages(threadId) {
  try {
    const messagesResponse = await openai.beta.threads.messages.list(threadId);
    const messages = messagesResponse.data
      .filter(msg => msg.role === 'assistant' && msg.content && msg.content.length > 0)
      .map(msg => msg.content.map(content => content.text.value).join(" "));
    return messages.length > 0 ? messages[0] : "";
  } catch (error) {
    console.error("Erreur lors de la récupération des messages du thread:", error);
    return "";
  }
}
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
      summary: `RDV de ${params.customerName}`,
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
      calendarId: 'diegodfr75@gmail.com',
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


async function cancelAppointment(phoneNumber) {
  try {
    // 1) Trouver le RDV en base
    const appointment = await db.collection('appointments')
                                .findOne({ phonenumber: phoneNumber });
    if (!appointment) {
      console.log("Aucun RDV trouvé pour ce phoneNumber:", phoneNumber);
      return false;
    }

    // 2) Supprimer l’event côté Google si googleEventId existe
    if (appointment.googleEventId) {
      await calendar.events.delete({
        calendarId: 'primary',
        eventId: appointment.googleEventId
      });
      console.log("Événement GoogleCalendar supprimé:", appointment.googleEventId);
    } else {
      console.log("Aucun googleEventId stocké, on ne supprime rien sur Google.");
    }

    // 3) Supprimer en base
    const result = await db.collection('appointments').deleteOne({ _id: appointment._id });
    return result.deletedCount > 0;
  } catch (error) {
    console.error("Erreur cancelAppointment:", error);
    return false;
  }
}

// Fonction pour extraire les codes image
function extractImageCodes(reply) {
    const imageCodes = reply.match(/naysa\d+/g) || [];
    console.log("Codes image détectés :", imageCodes);
    return imageCodes;
}

// Fonction pour récupérer les URLs des images depuis MongoDB
async function getImageUrls(imageCodes) {
    try {
        const imagesCollection = db.collection('images');
        const images = await imagesCollection.find({ _id: { $in: imageCodes } }).toArray();
        return images.map(img => img.url);
    } catch (error) {
        console.error("Erreur lors de la récupération des images :", error);
        return [];
    }
}

// Fonction pour nettoyer la réponse
function cleanReply(reply) {
    return reply.replace(/naysa\d+/g, '').trim();
}


// Modification du endpoint WhatsApp pour gérer les images
// Endpoint pour recevoir les messages WhatsApp Cloud API
app.post('/whatsapp', async (req, res) => {
  console.log('Requête reçue :', JSON.stringify(req.body, null, 2));

  try {
    // 1) Vérifier la structure du body : Meta envoie { object, entry: [...] }
    if (
      !req.body.entry ||
      !req.body.entry[0].changes ||
      !req.body.entry[0].changes[0].value.messages
    ) {
      // Pas de message entrant : on répond 200 pour signifier qu'on a bien reçu l'event
      return res.status(200).send('Aucun message entrant.');
    }

    // Récupération des infos importantes
    const value = req.body.entry[0].changes[0].value;
    const message = value.messages[0];                // Le message entrant
    const from = message.from;                        // Numéro de l'expéditeur (ex. "573009016472")
    const phoneNumberId = value.metadata.phone_number_id; 
      // phone_number_id renvoyé par Meta (ex. "577116808821334"), 
      // tu peux utiliser la variable globale "whatsappPhoneNumberId" si c'est toujours le même

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
      // Pas de texte exploitable => on arrête
      return res.status(200).send('Message vide ou non géré.');
    }

    // 3) Envoyer le message à l'assistant (logique existante)
    const reply = await interactWithAssistant(userMessage, from);

    // 4) Extraire d'éventuels codes d’images dans la réponse
    const imageCodes = extractImageCodes(reply);
    const imageUrls = await getImageUrls(imageCodes);
    let cleanedReply = cleanReply(reply);

    // Si pas de texte mais qu’on a des images => on met un texte par défaut
    if (!cleanedReply && imageUrls.length > 0) {
      cleanedReply = "La imagen :";
    }

    // Si vraiment rien à envoyer
    if (!cleanedReply && imageUrls.length === 0) {
      console.error("Erreur : Aucun texte ou média à envoyer.");
      return res.status(200).send('Aucun contenu à envoyer.');
    }

    // 5) Répondre à l'utilisateur via l’API WhatsApp Cloud
    //    -> On utilise "axios.post(...)" vers "graph.facebook.com/v16.0/{phoneNumberId}/messages"
    //    -> phoneNumberId : ID du numéro WhatsApp (ex. "577116808821334")
    //    -> token : ton token permanent
    const apiUrl = `https://graph.facebook.com/v16.0/${phoneNumberId}/messages`;
    const headers = {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    };

    // 5a) Envoyer le message textuel s'il existe
    if (cleanedReply) {
      await axios.post(
        apiUrl,
        {
          messaging_product: 'whatsapp',
          to: from, // ex. "573009016472"
          text: { body: cleanedReply },
        },
        { headers }
      );
    }

    // 5b) Envoyer les images si disponibles
    for (const url of imageUrls) {
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

    // 6) Retour OK
    res.status(200).send('Message envoyé avec succès');
  } catch (error) {
    console.error("Erreur lors du traitement du message WhatsApp:", error);
    res.status(500).json({ error: "Erreur interne." });
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