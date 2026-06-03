/* ==========================================================================
   LUGH HUB — BACKEND DE PAGAMENTOS (Stripe + Firestore Admin)
   --------------------------------------------------------------------------
   Stack:
     - Node.js + Express
     - Stripe API (Checkout Session: aceita Cartão + Pix)
     - firebase-admin (escreve no MESMO Firestore que o frontend usa — grátis)
   Por que Express separado:
     - Você pediu manter o Firebase grátis (sem Cloud Functions Blaze).
     - Faça deploy GRÁTIS em: Render.com, Railway, Fly.io ou Vercel Functions.
   Endpoints expostos:
     POST /api/checkout         → cria a Stripe Checkout Session (cartão+pix)
     POST /api/webhook          → recebe confirmação do Stripe (raw body)
     GET  /api/admin/logs       → lista paginada de purchase_logs (10/pág)
     GET  /api/settings/featured-price → leitura pública do valor atual
     POST /api/admin/settings/featured-price → admin define valor
   ========================================================================== */
"use strict";

const express = require("express");
const cors = require("cors");
const Stripe = require("stripe");
const admin = require("firebase-admin");

// ===== ENV =====
const {
    STRIPE_SECRET_KEY,
    STRIPE_WEBHOOK_SECRET,
    FIREBASE_SERVICE_ACCOUNT_JSON, // string JSON da service account
    PUBLIC_SITE_URL = "http://localhost:5173",
    ADMIN_EMAILS = "romanohenri@gmail.com",
    PORT = 8787
} = process.env;

if (!STRIPE_SECRET_KEY) throw new Error("STRIPE_SECRET_KEY ausente");
if (!FIREBASE_SERVICE_ACCOUNT_JSON) throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON ausente");

const stripe = new Stripe(STRIPE_SECRET_KEY, { apiVersion: "2024-06-20" });
admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON))
});
const db = admin.firestore();
const ADMINS = ADMIN_EMAILS.split(",").map(s => s.trim().toLowerCase());

// ===== APP =====
const app = express();
app.use(cors({ origin: true, credentials: true }));

// IMPORTANTE: a rota de webhook precisa do body RAW. Ela é declarada ANTES
// do express.json() para que o middleware JSON não consuma o stream.
app.post("/api/webhook",
    express.raw({ type: "application/json" }),
    async (req, res) => {
        const sig = req.headers["stripe-signature"];
        let event;
        try {
            event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
        } catch (err) {
            console.error("[webhook] assinatura inválida:", err.message);
            return res.status(400).send(`Webhook Error: ${err.message}`);
        }

        try {
            // Tratamos cartão (checkout.session.completed) e Pix (checkout.session.async_payment_succeeded)
            if (
                event.type === "checkout.session.completed" ||
                event.type === "checkout.session.async_payment_succeeded"
            ) {
                const session = event.data.object;
                if (session.payment_status !== "paid") {
                    console.log("[webhook] sessão não paga ainda:", session.id);
                    return res.json({ received: true });
                }
                await handlePaidSession(session);
            }
            res.json({ received: true });
        } catch (err) {
            console.error("[webhook] erro processando:", err);
            res.status(500).send("internal");
        }
    }
);

// JSON para o restante das rotas
app.use(express.json({ limit: "200kb" }));

// ===== Helpers de autenticação =====
// Verifica o ID Token do Firebase enviado pelo frontend no header Authorization.
async function getUser(req) {
    const h = req.headers.authorization || "";
    const m = h.match(/^Bearer (.+)$/);
    if (!m) return null;
    try {
        const decoded = await admin.auth().verifyIdToken(m[1]);
        return decoded;
    } catch { return null; }
}
function isAdmin(user) {
    return user && user.email && ADMINS.includes(user.email.toLowerCase());
}

// ===== Settings (preço do destaque) =====
const SETTINGS_DOC = db.collection("settings").doc("market_premium");

async function getFeaturedPriceCents() {
    const snap = await SETTINGS_DOC.get();
    const data = snap.exists ? snap.data() : null;
    // valor padrão se admin nunca configurou
    const cents = data && Number.isFinite(data.featured_price_cents)
        ? data.featured_price_cents
        : 499; // R$ 4,99
    return cents;
}

app.get("/api/settings/featured-price", async (_req, res) => {
    const cents = await getFeaturedPriceCents();
    res.json({ cents, brl: (cents / 100).toFixed(2) });
});

app.post("/api/admin/settings/featured-price", async (req, res) => {
    const user = await getUser(req);
    if (!isAdmin(user)) return res.status(403).json({ error: "forbidden" });
    const cents = Math.round(Number(req.body && req.body.cents));
    if (!Number.isFinite(cents) || cents < 100 || cents > 1000000) {
        return res.status(400).json({ error: "cents inválido (mín 100 = R$1,00)" });
    }
    await SETTINGS_DOC.set({
        featured_price_cents: cents,
        updated_at: admin.firestore.FieldValue.serverTimestamp(),
        updated_by: user.email
    }, { merge: true });
    res.json({ ok: true, cents });
});

// ===== Checkout =====
// O frontend chama isso ao marcar "Destaque Premium" no card.
app.post("/api/checkout", async (req, res) => {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ error: "auth required" });

    const { listingId } = req.body || {};
    if (!listingId || typeof listingId !== "string" || listingId.length > 128) {
        return res.status(400).json({ error: "listingId inválido" });
    }

    // Confirma que o anúncio existe e pertence ao usuário (a coleção pode variar
    // no seu projeto — ajuste o nome se necessário; aqui usamos "market_listings").
    const listingRef = db.collection("market_listings").doc(listingId);
    const listingSnap = await listingRef.get();
    if (!listingSnap.exists) return res.status(404).json({ error: "anúncio não encontrado" });
    const listing = listingSnap.data();
    if (listing.ownerEmail && listing.ownerEmail.toLowerCase() !== user.email.toLowerCase()) {
        return res.status(403).json({ error: "anúncio não pertence ao usuário" });
    }
    if (listing.is_featured === true) {
        return res.status(409).json({ error: "anúncio já é destaque" });
    }

    const cents = await getFeaturedPriceCents();

    const session = await stripe.checkout.sessions.create({
        mode: "payment",
        payment_method_types: ["card", "pix"], // Cartão + Pix (QR Code gerado pelo Stripe)
        line_items: [{
            price_data: {
                currency: "brl",
                product_data: {
                    name: `Destaque Premium — Anúncio ${listingId}`,
                    description: "Aura dourada + prioridade no topo da listagem"
                },
                unit_amount: cents
            },
            quantity: 1
        }],
        customer_email: user.email,
        metadata: {
            listingId,
            userId: user.uid,
            userEmail: user.email
        },
        success_url: `${PUBLIC_SITE_URL}/?premium=success&listing=${encodeURIComponent(listingId)}`,
        cancel_url: `${PUBLIC_SITE_URL}/?premium=cancel&listing=${encodeURIComponent(listingId)}`
    });

    res.json({ url: session.url, id: session.id });
});

// ===== Lógica do pagamento confirmado =====
async function handlePaidSession(session) {
    const meta = session.metadata || {};
    const listingId = meta.listingId;
    if (!listingId) {
        console.warn("[webhook] session sem listingId:", session.id);
        return;
    }
    const paymentMethod = (session.payment_method_types || [])[0] || "unknown";

    const batch = db.batch();
    // 1) marca o anúncio como destaque
    const listingRef = db.collection("market_listings").doc(listingId);
    batch.set(listingRef, {
        is_featured: true,
        featured_at: admin.firestore.FieldValue.serverTimestamp(),
        featured_session_id: session.id
    }, { merge: true });

    // 2) grava log de transação
    const logRef = db.collection("purchase_logs").doc(session.id);
    batch.set(logRef, {
        session_id: session.id,
        listing_id: listingId,
        user_id: meta.userId || null,
        email: meta.userEmail || session.customer_email || null,
        amount_cents: session.amount_total,
        currency: session.currency,
        payment_method: paymentMethod,
        status: session.payment_status,
        created_at: admin.firestore.FieldValue.serverTimestamp()
    });

    await batch.commit();
    console.log("[webhook] anúncio destacado + log gravado:", listingId, session.id);
}

// ===== Logs paginados (admin) =====
// Cursor-based (Firestore não tem OFFSET eficiente). Cliente envia ?cursor=<doc id>
app.get("/api/admin/logs", async (req, res) => {
    const user = await getUser(req);
    if (!isAdmin(user)) return res.status(403).json({ error: "forbidden" });

    const PAGE = 10;
    let q = db.collection("purchase_logs").orderBy("created_at", "desc").limit(PAGE + 1);
    if (req.query.cursor) {
        const cursorSnap = await db.collection("purchase_logs").doc(String(req.query.cursor)).get();
        if (cursorSnap.exists) q = q.startAfter(cursorSnap);
    }
    const snap = await q.get();
    const docs = snap.docs.slice(0, PAGE).map(d => {
        const data = d.data();
        return {
            id: d.id,
            email: data.email,
            payment_method: data.payment_method,
            amount_cents: data.amount_cents,
            listing_id: data.listing_id,
            status: data.status,
            created_at: data.created_at && data.created_at.toDate
                ? data.created_at.toDate().toISOString()
                : null
        };
    });
    const nextCursor = snap.docs.length > PAGE ? snap.docs[PAGE - 1].id : null;
    res.json({ items: docs, nextCursor, pageSize: PAGE });
});

// ===== Healthcheck =====
app.get("/", (_req, res) => res.send("Lugh Premium API ok"));

app.listen(PORT, () => console.log(`Lugh Premium API rodando em :${PORT}`));
