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
const crypto = require("crypto");

// ===== ENV =====
const {
    STRIPE_SECRET_KEY,
    STRIPE_WEBHOOK_SECRET,
    FIREBASE_SERVICE_ACCOUNT_JSON, // string JSON da service account
    PUBLIC_SITE_URL = "http://localhost:5173",
    PUBLIC_API_URL = "",
    ADMIN_EMAILS = "romanohenri@gmail.com",
    DISCORD_CLIENT_ID = "",
    DISCORD_CLIENT_SECRET = "",
    DISCORD_REDIRECT_URI = "",
    STEAM_NEWS_AUTO_IMPORT_MINUTES = "30",
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

// ===== Healthcheck / Warmup Render =====
// Rota leve usada pelo frontend para acordar o backend antes do Checkout Premium.
app.get("/api/health", (_req, res) => {
    res.set("Cache-Control", "no-store");
    res.json({ ok: true, service: "lugh-premium-api", ts: Date.now() });
});

// ===== Helpers de autenticação =====
// Verifica o ID Token do Firebase enviado pelo frontend no header Authorization.
async function getUser(req) {
    const h = req.headers.authorization || "";
    const m = h.match(/^Bearer (.+)$/);
    const token = (m && m[1])
        || (req.query && typeof req.query.token === "string" ? req.query.token : "")
        || (req.body && typeof req.body.token === "string" ? req.body.token : "");
    if (!token) return null;
    try {
        const decoded = await admin.auth().verifyIdToken(token);
        return decoded;
    } catch { return null; }
}
function isAdmin(user) {
    return user && user.email && ADMINS.includes(user.email.toLowerCase());
}


// ===== Discord OAuth (vincular Discord ao usuário Firebase) =====
// Uso no Mercado/Fórum: o usuário vincula uma vez; o frontend copia os dados
// para o anúncio/post. Não consulta o Discord em cada renderização.
const DISCORD_STATE_COLLECTION = "discord_oauth_states";
const USERS_COLLECTION = "users";

function getBaseApiUrl(req) {
    return String(PUBLIC_API_URL || `${req.protocol}://${req.get("host")}`).replace(/\/+$/, "");
}

function getDiscordRedirectUri(req) {
    return DISCORD_REDIRECT_URI || `${getBaseApiUrl(req)}/api/auth/discord/callback`;
}

function sanitizeDiscordReturnTo(value, options = {}) {
    const fallback = String(PUBLIC_SITE_URL || "http://localhost:5173").replace(/\/+$/, "");
    const raw = String(value || "").trim();
    const status = String(options.discord || "linked").trim() || "linked";
    const safeDefault = () => `${fallback}/?tab=market&open=createListing&discord=${encodeURIComponent(status)}`;

    let target;
    let tab = String(options.tab || "").trim();
    let open = String(options.open || "").trim();

    try {
        if (/^(createListing|market-create-listing)$/i.test(raw)) {
            target = new URL(fallback);
            tab = "market";
            open = "createListing";
        } else if (/^(createGuide|forum-create-guide)$/i.test(raw)) {
            target = new URL(fallback);
            tab = "forum";
            open = "createGuide";
        } else if (raw) {
            target = new URL(raw, fallback);
            const allowed = new URL(fallback);
            if (target.origin !== allowed.origin) return safeDefault();
            tab = tab || target.searchParams.get("tab") || "";
            open = open || target.searchParams.get("open") || "";
        } else {
            target = new URL(fallback);
        }

        if (!tab && /forum/i.test(open)) tab = "forum";
        if (!tab) tab = "market";
        if (!open) open = tab === "forum" ? "createGuide" : "createListing";

        target.searchParams.set("tab", tab);
        target.searchParams.set("open", open);
        target.searchParams.set("discord", status);
        return target.toString();
    } catch (_) {
        return safeDefault();
    }
}

function withDiscordReturnStatus(returnTo, status) {
    try {
        const url = new URL(returnTo || sanitizeDiscordReturnTo(""));
        url.searchParams.set("discord", status || "linked");
        return url.toString();
    } catch (_) {
        return sanitizeDiscordReturnTo("", { discord: status || "linked" });
    }
}

function discordAvatarUrl(user) {
    if (!user || !user.id || !user.avatar) return "";
    const ext = String(user.avatar).startsWith("a_") ? "gif" : "png";
    return `https://cdn.discordapp.com/avatars/${encodeURIComponent(user.id)}/${encodeURIComponent(user.avatar)}.${ext}?size=128`;
}

function discordPublicPayload(data) {
    if (!data || !data.discordId) return null;
    return {
        discordId: data.discordId,
        discordUsername: data.discordUsername || "",
        discordGlobalName: data.discordGlobalName || "",
        discordAvatar: data.discordAvatar || "",
        discordLinkedAt: data.discordLinkedAt || null
    };
}

app.post("/api/auth/discord/start", async (req, res) => {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ error: "auth required" });
    if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET) {
        return res.status(500).json({ error: "discord_env_missing" });
    }

    const state = crypto.randomBytes(24).toString("hex");
    const redirectUri = getDiscordRedirectUri(req);
    const returnTo = sanitizeDiscordReturnTo((req.body && req.body.returnTo) || (req.query && req.query.returnTo), {
        tab: (req.body && req.body.tab) || (req.query && req.query.tab),
        open: (req.body && req.body.open) || (req.query && req.query.open)
    });
    await db.collection(DISCORD_STATE_COLLECTION).doc(state).set({
        uid: user.uid,
        email: user.email || null,
        returnTo,
        created_at: admin.firestore.FieldValue.serverTimestamp(),
        expires_at_ms: Date.now() + 10 * 60 * 1000
    });

    const params = new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        redirect_uri: redirectUri,
        response_type: "code",
        scope: "identify",
        state,
        prompt: "consent"
    });
    res.json({ url: `https://discord.com/oauth2/authorize?${params.toString()}` });
});


app.get("/api/auth/discord/start", async (req, res) => {
    const user = await getUser(req);
    if (!user) return res.status(401).send("Login Firebase necessário antes de vincular Discord.");
    if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET) {
        return res.status(500).send("Discord OAuth não configurado no servidor.");
    }

    const state = crypto.randomBytes(24).toString("hex");
    const redirectUri = getDiscordRedirectUri(req);
    const returnTo = sanitizeDiscordReturnTo(req.query && req.query.returnTo, {
        tab: req.query && req.query.tab,
        open: req.query && req.query.open
    });
    await db.collection(DISCORD_STATE_COLLECTION).doc(state).set({
        uid: user.uid,
        email: user.email || null,
        returnTo,
        created_at: admin.firestore.FieldValue.serverTimestamp(),
        expires_at_ms: Date.now() + 10 * 60 * 1000
    });

    const params = new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        redirect_uri: redirectUri,
        response_type: "code",
        scope: "identify",
        state,
        prompt: "consent"
    });
    res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
});

app.get("/api/auth/discord/callback", async (req, res) => {
    const code = String(req.query.code || "").trim();
    const state = String(req.query.state || "").trim();
    const oauthError = String(req.query.error || "").trim();
    const sendHtml = (ok, payload) => {
        const safePayload = JSON.stringify({ type: ok ? "lugh-discord-linked" : "lugh-discord-link-error", ...payload }).replace(/</g, "\\u003c");
        const returnTo = payload && payload.returnTo ? String(payload.returnTo) : sanitizeDiscordReturnTo("");
        const safeReturnTo = JSON.stringify(returnTo).replace(/</g, "\\u003c");
        res.set("Content-Type", "text/html; charset=utf-8");
        res.send(`<!doctype html><html><head><meta charset="utf-8"><title>Discord</title></head><body style="font-family:Arial;background:#0b1024;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;"><div>${ok ? "Discord vinculado. Voltando para o anúncio..." : "Falha ao vincular Discord."}</div><script>var sent=false;try{if(window.opener){window.opener.postMessage(${safePayload}, "*");sent=true;setTimeout(function(){window.close();},700);}}catch(e){} if(!sent){setTimeout(function(){window.location.href=${safeReturnTo};},500);}</script></body></html>`);
    };
    if (oauthError === "access_denied" && state) {
        try {
            const cancelSnap = await db.collection(DISCORD_STATE_COLLECTION).doc(state).get();
            const cancelData = cancelSnap.exists ? (cancelSnap.data() || {}) : {};
            const cancelTo = cancelData.returnTo || sanitizeDiscordReturnTo("", { discord: "cancelled" });
            return res.redirect(withDiscordReturnStatus(cancelTo, "cancelled"));
        } catch (_) {}
    }

    if (!code || !state) return sendHtml(false, { error: "missing_code_or_state" });

    const stateRef = db.collection(DISCORD_STATE_COLLECTION).doc(state);
    const stateSnap = await stateRef.get();
    if (!stateSnap.exists) return sendHtml(false, { error: "invalid_state" });
    const stateData = stateSnap.data() || {};
    if (!stateData.uid || Number(stateData.expires_at_ms || 0) < Date.now()) {
        await stateRef.delete().catch(() => {});
        return sendHtml(false, { error: "expired_state", returnTo: withDiscordReturnStatus(stateData.returnTo, "expired") });
    }

    try {
        const redirectUri = getDiscordRedirectUri(req);
        const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                client_id: DISCORD_CLIENT_ID,
                client_secret: DISCORD_CLIENT_SECRET,
                grant_type: "authorization_code",
                code,
                redirect_uri: redirectUri
            })
        });
        const tokenData = await tokenRes.json().catch(() => ({}));
        if (!tokenRes.ok || !tokenData.access_token) throw new Error(tokenData.error || "discord_token_failed");

        const userRes = await fetch("https://discord.com/api/users/@me", {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const discordUser = await userRes.json().catch(() => ({}));
        if (!userRes.ok || !discordUser.id) throw new Error(discordUser.message || "discord_user_failed");

        const profile = {
            discordId: String(discordUser.id),
            discordUsername: String(discordUser.username || ""),
            discordGlobalName: String(discordUser.global_name || ""),
            discordAvatar: discordAvatarUrl(discordUser),
            discordLinkedAt: Date.now(),
            updated_at: admin.firestore.FieldValue.serverTimestamp(),
            email: stateData.email || null
        };
        await db.collection(USERS_COLLECTION).doc(stateData.uid).set(profile, { merge: true });
        await stateRef.delete().catch(() => {});
        sendHtml(true, { discord: discordPublicPayload(profile), returnTo: stateData.returnTo });
    } catch (err) {
        console.error("[discord-oauth] erro:", err);
        sendHtml(false, { error: err.message || "discord_link_failed", returnTo: withDiscordReturnStatus(stateData && stateData.returnTo, "error") });
    }
});

app.get("/api/me/discord", async (req, res) => {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ error: "auth required" });
    const snap = await db.collection(USERS_COLLECTION).doc(user.uid).get();
    const profile = snap.exists ? discordPublicPayload(snap.data()) : null;
    res.json({ discord: profile });
});

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
    // no seu projeto — ajuste o nome se necessário; aqui usamos "listings").
    const listingRef = db.collection("listings").doc(listingId);
    const listingSnap = await listingRef.get();
    if (!listingSnap.exists) return res.status(404).json({ error: "anúncio não encontrado" });
    const listing = listingSnap.data();
    const ownerEmail = (listing.ownerEmail || listing.authorEmail || listing.seller_email || "").toLowerCase();
    if (ownerEmail && ownerEmail !== user.email.toLowerCase()) {
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
    const listingRef = db.collection("listings").doc(listingId);
    batch.set(listingRef, {
        is_featured: true,
        featured_at: admin.firestore.FieldValue.serverTimestamp(),
        featured_session_id: session.id,

        // Validade do anúncio Premium:
        // a partir da aprovação do pagamento, o anúncio ganha 7 dias completos.
        // O frontend usa "date" para expiração automática, então resetamos para agora.
        date: Date.now(),
        premium_paid_at_ms: Date.now(),
        premium_expires_at_ms: Date.now() + (7 * 24 * 60 * 60 * 1000),
        expires_at_ms: Date.now() + (7 * 24 * 60 * 60 * 1000)
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

// ===== Steam News Importer =====
const NEWS_COLLECTION = "news";
const NEWS_STEAM_GAMES_COLLECTION = "news_steam_games";
const NEWS_SETTINGS_COLLECTION = "site_settings";
const NEWS_SETTINGS_DOC_ID = "news";
const HOME_CONFIG_COLLECTION = "home_config";
const HOME_CONFIG_DOC_ID = "main";
const DEFAULT_NEWS_GLOBAL_IMAGE = "assets/wallpapers/enhanced_ankys.png";
let steamNewsImportRunning = false;
const steamAnnouncementMediaCache = new Map();
const steamTranslationCache = new Map();
const STEAM_ANNOUNCEMENT_CACHE_MS = 6 * 60 * 60 * 1000;

function escapeSteamHtml(value) {
    return String(value || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function stripEmojiFromNewsTitle(value) {
    return String(value || "")
        .replace(/[#*0-9]\uFE0F?\u20E3/gu, "")
        .replace(/[\p{Extended_Pictographic}\p{Emoji_Presentation}\p{Regional_Indicator}\p{Emoji_Modifier}]/gu, "")
        .replace(/[\u200D\uFE0E\uFE0F\u20E3]/gu, "")
        .replace(/\s+/g, " ")
        .trim();
}

function safeSteamHttpUrl(value) {
    if (!value) return "";
    let raw = String(value).trim().replace(/^["']|["']$/g, "");
    raw = raw.replace(/&amp;/gi, "&").replace(/&quot;/gi, "").replace(/&#34;/g, "").replace(/&#39;/g, "");
    raw = raw
        .replace(/^\{STEAM_CLAN_IMAGE\}\//i, "https://clan.cloudflare.steamstatic.com/images/")
        .replace(/^\{STEAM_CLAN_LOC_IMAGE\}\//i, "https://clan.cloudflare.steamstatic.com/images/");
    if (/^\/\//.test(raw)) raw = "https:" + raw;
    if (!/^https?:\/\//i.test(raw)) return "";
    try {
        const u = new URL(raw);
        return (u.protocol === "http:" || u.protocol === "https:") ? u.toString() : "";
    } catch (_) {
        return "";
    }
}

function steamDocKey(appId, gid) {
    return `${String(appId || "").trim()}:${String(gid || "").trim()}`;
}

function steamDocId(appId, gid) {
    return `steam_${steamDocKey(appId, gid)}`.replace(/[^a-zA-Z0-9_-]+/g, "_").slice(0, 140);
}

function convertSteamListBlocksServer(html, steamTag, htmlTag) {
    const rx = new RegExp("\\[" + steamTag + "\\]([\\s\\S]*?)\\[\\/" + steamTag + "\\]", "gi");
    let previous = "";
    while (previous !== html) {
        previous = html;
        html = html.replace(rx, (_match, body) => {
            const items = String(body || "")
                .split(/\[\*\]/i)
                .map(item => item.trim())
                .filter(Boolean)
                .map(item => `<li>${item}</li>`)
                .join("");
            return items ? `<${htmlTag} class="steam-news-list">${items}</${htmlTag}>` : "";
        });
    }
    return html;
}

function wrapLooseSteamListItemsServer(html) {
    if (!/\[\*\]/i.test(html)) return html;
    return html.replace(/((?:^|\n)\s*\[\*\][\s\S]*?)(?=\n{2,}|$)/gi, block => {
        const items = String(block || "")
            .split(/\[\*\]/i)
            .map(item => item.trim())
            .filter(Boolean)
            .map(item => `<li>${item.replace(/\n/g, "<br>")}</li>`)
            .join("");
        return items ? `<ul class="steam-news-list">${items}</ul>` : "";
    });
}

function normalizeSteamHtmlAttributesServer(html) {
    return String(html || "").replace(/\s(src|href)=["']([^"']+)["']/gi, (_match, attr, url) => {
        const safe = safeSteamHttpUrl(url);
        return safe ? ` ${attr.toLowerCase()}="${escapeSteamHtml(safe)}"` : "";
    });
}

function convertSteamAttributeImagesServer(html) {
    return String(html || "")
        .replace(/\[img\s+src\s*=\s*&quot;([\s\S]*?)&quot;[^\]]*\](?:\s*\[\/img\])?/gi, (_match, url) => {
            const safe = safeSteamHttpUrl(url);
            return safe ? `<figure><img src="${escapeSteamHtml(safe)}" loading="lazy"></figure>` : "";
        })
        .replace(/\[img\s+src\s*=\s*(["'])([\s\S]*?)\1[^\]]*\](?:\s*\[\/img\])?/gi, (_match, _quote, url) => {
            const safe = safeSteamHttpUrl(url);
            return safe ? `<figure><img src="${escapeSteamHtml(safe)}" loading="lazy"></figure>` : "";
        })
        .replace(/\[img\s+src\s*=\s*([^\]\s]+)[^\]]*\](?:\s*\[\/img\])?/gi, (_match, url) => {
            const safe = safeSteamHttpUrl(url);
            return safe ? `<figure><img src="${escapeSteamHtml(safe)}" loading="lazy"></figure>` : "";
        });
}

function enhanceSteamEmojiBulletsServer(html) {
    return String(html || "").replace(
        /(^|\n|<\/(?:p|div|figure|blockquote|h[1-6])>)\s*([^\p{L}\p{N}\s<>'"“‘([{]{1,12})\s+(\p{L}[^:\n<]{1,100}:)/gu,
        (_match, lead, marker, label) => `${lead}\n[*] ${marker} <strong>${label.trim()}</strong>`
    );
}

function normalizeSteamLineBreaksServer(html) {
    html = String(html || "").replace(/\r\n?/g, "\n").replace(/\n{3,}/g, "\n\n");
    if (!/<(p|h\d|ul|ol|li|figure|iframe|blockquote|table|hr|div)\b/i.test(html)) {
        return html
            .split(/\n{2,}/)
            .map(part => part.trim())
            .filter(Boolean)
            .map(part => `<p>${part.replace(/\n/g, "<br>")}</p>`)
            .join("");
    }
    return html
        .replace(/\n\s*(<\/?(?:h\d|ul|ol|li|figure|iframe|blockquote|table|thead|tbody|tr|td|th|hr|div)[^>]*>)\s*\n/g, "$1")
        .replace(/\n{2,}/g, "<br><br>")
        .replace(/\n/g, "<br>")
        .replace(/<(ul|ol|table|tbody|thead|tr)><br\s*\/?>/gi, "<$1>")
        .replace(/<br\s*\/?><\/(ul|ol|table|tbody|thead|tr)>/gi, "</$1>")
        .replace(/<\/(h\d|p|li|figure|blockquote|tr)><br\s*\/?>/gi, "</$1>")
        .replace(/<br\s*\/?><(h\d|ul|ol|figure|iframe|blockquote|table|hr|div)/gi, "<$1");
}

function steamContentToHtmlServer(content) {
    let html = String(content || "").trim();
    html = convertSteamAttributeImagesServer(html);
    html = enhanceSteamEmojiBulletsServer(html);
    html = html
        .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "")
        .replace(/\son\w+=(["']).*?\1/gi, "")
        .replace(/\[previewyoutube=([a-zA-Z0-9_-]+)(?:;[^\]]*)?\][\s\S]*?\[\/previewyoutube\]/gi, (_m, id) => {
            const videoId = String(id || "").trim();
            return videoId ? `<iframe src="https://www.youtube.com/embed/${escapeSteamHtml(videoId)}" loading="lazy" allowfullscreen></iframe>` : "";
        })
        .replace(/\[youtube\]([a-zA-Z0-9_-]+)\[\/youtube\]/gi, (_m, id) => {
            const videoId = String(id || "").trim();
            return videoId ? `<iframe src="https://www.youtube.com/embed/${escapeSteamHtml(videoId)}" loading="lazy" allowfullscreen></iframe>` : "";
        })
        .replace(/\[h1\]([\s\S]*?)\[\/h1\]/gi, "<h2>$1</h2>")
        .replace(/\[h2\]([\s\S]*?)\[\/h2\]/gi, "<h3>$1</h3>")
        .replace(/\[h3\]([\s\S]*?)\[\/h3\]/gi, "<h4>$1</h4>")
        .replace(/\[(?:header|heading)\]([\s\S]*?)\[\/(?:header|heading)\]/gi, "<h3>$1</h3>")
        .replace(/\[subheader\]([\s\S]*?)\[\/subheader\]/gi, "<h4>$1</h4>")
        .replace(/\[b\]([\s\S]*?)\[\/b\]/gi, "<strong>$1</strong>")
        .replace(/\[i\]([\s\S]*?)\[\/i\]/gi, "<em>$1</em>")
        .replace(/\[u\]([\s\S]*?)\[\/u\]/gi, "<u>$1</u>")
        .replace(/\[strike\]([\s\S]*?)\[\/strike\]/gi, "<s>$1</s>")
        .replace(/\[spoiler\]([\s\S]*?)\[\/spoiler\]/gi, '<span class="news-spoiler">$1</span>')
        .replace(/\[quote\]([\s\S]*?)\[\/quote\]/gi, "<blockquote>$1</blockquote>")
        .replace(/\[code\]([\s\S]*?)\[\/code\]/gi, (_m, code) => `<pre><code>${escapeSteamHtml(code)}</code></pre>`)
        .replace(/\[hr\]/gi, "<hr>")
        .replace(/\[br\]/gi, "<br>")
        .replace(/\[p(?:=[^\]]*)?\]([\s\S]*?)\[\/p\]/gi, (_m, body) => {
            const inner = String(body || "").trim();
            return inner && inner !== "&nbsp;"
                ? `<p>${inner}</p>`
                : '<div class="steam-block-break" aria-hidden="true"></div>';
        })
        .replace(/\[img(?:=[^\]]*)?\]([\s\S]*?)\[\/img\]/gi, (_m, url) => {
            const safe = safeSteamHttpUrl(url);
            return safe ? `<figure><img src="${escapeSteamHtml(safe)}" loading="lazy"></figure>` : "";
        })
        .replace(/\[url=([^\]]+)\]([\s\S]*?)\[\/url\]/gi, (_m, url, label) => {
            const safe = safeSteamHttpUrl(url);
            return safe ? `<a href="${escapeSteamHtml(safe)}" target="_blank" rel="noopener noreferrer">${label}</a>` : label;
        })
        .replace(/\[url\]([\s\S]*?)\[\/url\]/gi, (_m, url) => {
            const safe = safeSteamHttpUrl(url);
            return safe ? `<a href="${escapeSteamHtml(safe)}" target="_blank" rel="noopener noreferrer">${escapeSteamHtml(safe)}</a>` : escapeSteamHtml(url);
        })
        .replace(/\[table\]/gi, "<table>")
        .replace(/\[\/table\]/gi, "</table>")
        .replace(/\[tr\]/gi, "<tr>")
        .replace(/\[\/tr\]/gi, "</tr>")
        .replace(/\[th\]/gi, "<th>")
        .replace(/\[\/th\]/gi, "</th>")
        .replace(/\[td\]/gi, "<td>")
        .replace(/\[\/td\]/gi, "</td>");
    html = convertSteamListBlocksServer(html, "olist", "ol");
    html = convertSteamListBlocksServer(html, "list", "ul");
    html = wrapLooseSteamListItemsServer(html);
    html = html
        .replace(/\[\/?(?:center|left|right|indent|noparse|section|subsection|expand|collapse|carousel|previewicon)[^\]]*\]/gi, "")
        .replace(/\[\/?[a-z][a-z0-9_:-]*(?:=[^\]]*)?\]/gi, "");
    html = normalizeSteamHtmlAttributesServer(html);
    return normalizeSteamLineBreaksServer(html);
}

function extractSteamImagesServer(html) {
    const images = [];
    String(html || "").replace(/<img[^>]+src=["']([^"']+)["'][^>]*>/gi, (_match, url) => {
        const safe = safeSteamHttpUrl(url);
        const comparable = comparableSteamImageUrlServer(safe);
        if (safe && !images.some(img => comparableSteamImageUrlServer(img.url) === comparable)) {
            images.push({ url: safe, alt: "", caption: "", cover: images.length === 0, order: images.length });
        }
        return "";
    });
    return images;
}

function comparableSteamImageUrlServer(value) {
    const safe = safeSteamHttpUrl(value);
    if (!safe) return "";
    try {
        const url = new URL(safe);
        if (/steamstatic\.com$/i.test(url.hostname) && /^\/images\/\d+\//i.test(url.pathname)) {
            return `steam-image:${url.pathname.toLowerCase()}`;
        }
        return `${url.origin}${url.pathname}`.replace(/\/+$/, "");
    } catch (_) {
        return safe.split(/[?#]/)[0].replace(/\/+$/, "");
    }
}

function removeSteamCoverFromBodyServer(html, coverImage) {
    const target = safeSteamHttpUrl(coverImage);
    if (!target) return html;
    const matchesCover = markup => {
        const srcMatch = String(markup || "").match(/<img\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/i);
        return !!(srcMatch && comparableSteamImageUrlServer(srcMatch[1]) === comparableSteamImageUrlServer(target));
    };
    return String(html || "")
        .replace(/<figure\b[^>]*>[\s\S]*?<\/figure>/gi, figure => matchesCover(figure) ? "" : figure)
        .replace(/<img\b[^>]*>/gi, img => matchesCover(img) ? "" : img);
}

function decodeSteamAnnouncementMarkup(value) {
    return String(value || "")
        .replace(/\\?&quot;/gi, "\"")
        .replace(/\\?&#34;/gi, "\"")
        .replace(/\\?&#39;/gi, "'")
        .replace(/&amp;/gi, "&")
        .replace(/\\\//g, "/")
        .replace(/\\"/g, "\"");
}

function extractSteamMetaImage(html, key) {
    const escapedKey = String(key || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const patterns = [
        new RegExp(`<meta[^>]+(?:property|name)=["']${escapedKey}["'][^>]+content=["']([^"']+)["']`, "i"),
        new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["']${escapedKey}["']`, "i")
    ];
    for (const pattern of patterns) {
        const match = String(html || "").match(pattern);
        const safe = match && safeSteamHttpUrl(match[1]);
        if (safe) return safe;
    }
    return "";
}

function extractSteamMetaContent(html, key) {
    const escapedKey = String(key || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const patterns = [
        new RegExp(`<meta[^>]+(?:property|name)=["']${escapedKey}["'][^>]+content=["']([^"']+)["']`, "i"),
        new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["']${escapedKey}["']`, "i")
    ];
    for (const pattern of patterns) {
        const match = String(html || "").match(pattern);
        if (match && match[1]) return decodeSteamAnnouncementMarkup(match[1]).trim();
    }
    return "";
}

function decodeSteamHtmlEntities(value) {
    return String(value || "")
        .replace(/&quot;/gi, "\"")
        .replace(/&#34;/gi, "\"")
        .replace(/&#39;/gi, "'")
        .replace(/&amp;/gi, "&")
        .replace(/&lt;/gi, "<")
        .replace(/&gt;/gi, ">");
}

function decodeSteamJsonString(value) {
    try {
        return JSON.parse(`"${String(value || "")}"`);
    } catch (_) {
        return String(value || "")
            .replace(/\\\//g, "/")
            .replace(/\\"/g, "\"")
            .replace(/\\\\/g, "\\");
    }
}

function getSteamAnnouncementDetailId(url) {
    const safe = safeSteamHttpUrl(url);
    const match = safe && safe.match(/\/announcements\/detail\/(\d+)/i);
    return match ? match[1] : "";
}

function extractSteamAnnouncementLocalization(html, finalUrl) {
    const detailId = getSteamAnnouncementDetailId(finalUrl);
    if (!detailId) return { title: "", content: "" };
    const source = decodeSteamHtmlEntities(html);
    const escapedId = detailId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const match = source.match(new RegExp(
        `"announcement_body"\\s*:\\s*\\{[\\s\\S]*?"gid"\\s*:\\s*"${escapedId}"[\\s\\S]*?"headline"\\s*:\\s*"((?:\\\\.|[^"\\\\])*)"[\\s\\S]*?"body"\\s*:\\s*"((?:\\\\.|[^"\\\\])*)"`,
        "i"
    ));
    return match ? {
        title: decodeSteamJsonString(match[1]).trim(),
        content: decodeSteamJsonString(match[2]).trim()
    } : { title: "", content: "" };
}

function withSteamLanguage(url, language) {
    const parsed = new URL(url);
    parsed.searchParams.set("l", language);
    return parsed.toString();
}

function withoutSteamLanguage(url) {
    const safe = safeSteamHttpUrl(url);
    if (!safe) return "";
    const parsed = new URL(safe);
    parsed.searchParams.delete("l");
    return parsed.toString();
}

function extractSteamLinkImage(html) {
    const patterns = [
        /<link[^>]+rel=["']image_src["'][^>]+href=["']([^"']+)["']/i,
        /<link[^>]+href=["']([^"']+)["'][^>]+rel=["']image_src["']/i
    ];
    for (const pattern of patterns) {
        const match = String(html || "").match(pattern);
        const safe = match && safeSteamHttpUrl(match[1]);
        if (safe) return safe;
    }
    return "";
}

function extractSteamLocalizedImageFile(decodedHtml, field) {
    const escapedField = String(field || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const arrayMatch = String(decodedHtml || "").match(new RegExp(`"${escapedField}"\\s*:\\s*\\[([\\s\\S]*?)\\]`, "i"));
    if (!arrayMatch) return "";
    const fileMatch = arrayMatch[1].match(/"([^"]+\.(?:png|jpe?g|webp|gif))"/i);
    return fileMatch ? fileMatch[1].replace(/^\/+/, "") : "";
}

function steamClanImageBase(...urls) {
    for (const value of urls) {
        const safe = safeSteamHttpUrl(value);
        const match = safe && safe.match(/^(https?:\/\/[^/]+\/images\/\d+\/)/i);
        if (match) return match[1];
    }
    return "";
}

function extractSteamAnnouncementMedia(html, finalUrl) {
    const source = String(html || "");
    const decoded = decodeSteamAnnouncementMarkup(source);
    const ogImage = extractSteamMetaImage(source, "og:image");
    const twitterImage = extractSteamMetaImage(source, "twitter:image");
    const linkedImage = extractSteamLinkImage(source);
    const imageBase = steamClanImageBase(ogImage, twitterImage, linkedImage);
    const titleFile = extractSteamLocalizedImageFile(decoded, "localized_title_image");
    const capsuleFile = extractSteamLocalizedImageFile(decoded, "localized_capsule_image");
    const titleImage = safeSteamHttpUrl(imageBase && titleFile ? imageBase + titleFile : "");
    const capsuleImage = safeSteamHttpUrl(imageBase && capsuleFile ? imageBase + capsuleFile : "")
        || ogImage
        || twitterImage
        || linkedImage;
    return {
        titleImage,
        capsuleImage,
        imageUrl: titleImage || capsuleImage,
        resolvedUrl: safeSteamHttpUrl(finalUrl),
        publishedAt: extractSteamMetaContent(source, "article:published_time")
    };
}

function isAllowedSteamAnnouncementUrl(value) {
    const safe = safeSteamHttpUrl(value);
    if (!safe) return false;
    try {
        const host = new URL(safe).hostname.toLowerCase();
        return host === "steamcommunity.com"
            || host.endsWith(".steamcommunity.com")
            || host === "store.steampowered.com"
            || host.endsWith(".steampowered.com")
            || host === "steamstore-a.akamaihd.net";
    } catch (_) {
        return false;
    }
}

async function fetchSteamAnnouncementMedia(url) {
    const safeUrl = safeSteamHttpUrl(url);
    if (!isAllowedSteamAnnouncementUrl(safeUrl)) return { titleImage: "", capsuleImage: "", imageUrl: "", resolvedUrl: safeUrl };
    const cached = steamAnnouncementMediaCache.get(safeUrl);
    if (cached && Date.now() - cached.savedAt < STEAM_ANNOUNCEMENT_CACHE_MS) return cached.media;

    const fetchLocalizedPage = async (language, acceptLanguage) => {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 12000);
        try {
            const response = await fetch(withSteamLanguage(safeUrl, language), {
                redirect: "follow",
                signal: controller.signal,
                headers: {
                    Accept: "text/html,application/xhtml+xml",
                    "Accept-Language": acceptLanguage,
                    "User-Agent": "Mozilla/5.0 (compatible; LughWorldCommunity/1.0)"
                }
            });
            if (!response.ok) throw new Error(`steam_announcement_${response.status}`);
            if (!isAllowedSteamAnnouncementUrl(response.url || safeUrl)) {
                throw new Error("steam_announcement_redirect_invalido");
            }
            return { html: await response.text(), url: response.url || safeUrl };
        } finally {
            clearTimeout(timeout);
        }
    };

    const [ptResult, enResult] = await Promise.allSettled([
        fetchLocalizedPage("brazilian", "pt-BR,pt;q=0.9,en;q=0.8"),
        fetchLocalizedPage("english", "en-US,en;q=0.9")
    ]);
    const ptPage = ptResult.status === "fulfilled" ? ptResult.value : null;
    const enPage = enResult.status === "fulfilled" ? enResult.value : null;
    const primaryPage = ptPage || enPage;
    if (!primaryPage) throw (ptResult.reason || enResult.reason || new Error("steam_announcement_unavailable"));

    try {
        const media = extractSteamAnnouncementMedia(primaryPage.html, withoutSteamLanguage(primaryPage.url));
        media.localized = {
            pt: ptPage ? extractSteamAnnouncementLocalization(ptPage.html, ptPage.url) : { title: "", content: "" },
            en: enPage ? extractSteamAnnouncementLocalization(enPage.html, enPage.url) : { title: "", content: "" }
        };
        steamAnnouncementMediaCache.set(safeUrl, { savedAt: Date.now(), media });
        if (media.resolvedUrl && media.resolvedUrl !== safeUrl) {
            steamAnnouncementMediaCache.set(media.resolvedUrl, { savedAt: Date.now(), media });
        }
        return media;
    } catch (err) {
        throw err;
    }
}

async function enrichSteamNewsItemServer(item) {
    if (!item) return item;
    try {
        const media = await fetchSteamAnnouncementMedia(item.url);
        return {
            ...item,
            image_url: media.imageUrl || "",
            steam_title_image: media.titleImage || "",
            steam_capsule_image: media.capsuleImage || "",
            steam_published_at: media.publishedAt || "",
            steam_localized: media.localized || {},
            resolved_url: media.resolvedUrl || safeSteamHttpUrl(item.url)
        };
    } catch (err) {
        console.warn("[steam-news] capa do anuncio indisponivel:", item.url, err.message);
        return item;
    }
}

async function fetchSteamNewsPayload(appid, count = 10) {
    const url = `https://api.steampowered.com/ISteamNews/GetNewsForApp/v2/?appid=${encodeURIComponent(appid)}&count=${count}&maxlength=0&format=json`;
    const steamRes = await fetch(url, { headers: { Accept: "application/json" } });
    if (!steamRes.ok) {
        const err = new Error("steam_unavailable");
        err.status = steamRes.status;
        throw err;
    }
    const payload = await steamRes.json();
    const items = payload && payload.appnews && payload.appnews.newsitems;
    if (Array.isArray(items)) {
        payload.appnews.newsitems = await Promise.all(items.map(enrichSteamNewsItemServer));
    }
    return payload;
}

function getSteamExplicitCoverServer(item) {
    const source = item || {};
    const candidates = [
        source.steam_title_image,
        source.image_url,
        source.imageUrl,
        source.image,
        source.thumbnail,
        source.thumbnail_url,
        source.capsule_image,
        source.capsuleImage,
        source.header_image,
        source.steam_capsule_image
    ];
    for (const candidate of candidates) {
        const safe = safeSteamHttpUrl(candidate);
        if (safe) return safe;
    }
    return "";
}

function getSteamPublishedDateServer(item, timestamp) {
    const publishedAt = String(item && item.steam_published_at || "").trim();
    const exactDate = publishedAt.match(/^(\d{4}-\d{2}-\d{2})/);
    if (exactDate) return exactDate[1];
    try {
        const parts = new Intl.DateTimeFormat("en-CA", {
            timeZone: "America/Los_Angeles",
            year: "numeric",
            month: "2-digit",
            day: "2-digit"
        }).formatToParts(new Date(timestamp));
        const values = Object.fromEntries(parts.map(part => [part.type, part.value]));
        return `${values.year}-${values.month}-${values.day}`;
    } catch (_) {
        return new Date(timestamp).toISOString().split("T")[0];
    }
}

function getSteamLocalizedItemServer(item, lang) {
    const localized = item && item.steam_localized && item.steam_localized[lang];
    const fallbackTitle = String(item && item.title || "").trim();
    const fallbackContent = String(item && (item.contents || item.content) || "").trim();
    return {
        title: String(localized && localized.title || (lang === "en" ? fallbackTitle : "")).trim(),
        content: String(localized && localized.content || (lang === "en" ? fallbackContent : "")).trim()
    };
}

function normalizeSteamLanguageText(value) {
    return decodeSteamHtmlEntities(String(value || ""))
        .replace(/<[^>]+>/g, " ")
        .replace(/\[[^\]]+\]/g, " ")
        .toLocaleLowerCase("pt-BR")
        .replace(/[^\p{L}\p{N}]+/gu, " ")
        .replace(/\s+/g, " ")
        .trim();
}

function steamTextLooksPortuguese(ptValue, enValue) {
    const pt = normalizeSteamLanguageText(ptValue);
    const en = normalizeSteamLanguageText(enValue);
    if (!pt) return false;
    if (en && pt === en) return false;

    const ptWords = (pt.match(/\b(?:a|as|ao|aos|com|como|da|das|de|do|dos|e|em|esta|este|foi|mais|melhorias|na|nas|no|nos|novo|para|pela|pelo|por|que|sistema|uma|um|versao|versão)\b/gu) || []).length;
    const enWords = (pt.match(/\b(?:a|added|and|as|by|for|from|game|improvements|in|is|items|new|of|on|system|the|this|to|update|version|was|with)\b/gu) || []).length;
    if (ptWords >= 2 && ptWords >= enWords) return true;
    if (enWords >= 3 && enWords > ptWords) return false;

    if (!en) return ptWords > enWords;
    const ptTokens = new Set(pt.split(" ").filter(token => token.length > 2));
    const enTokens = new Set(en.split(" ").filter(token => token.length > 2));
    const shared = [...ptTokens].filter(token => enTokens.has(token)).length;
    const similarity = shared / Math.max(1, Math.min(ptTokens.size, enTokens.size));
    return similarity < 0.72;
}

async function googleTranslateEnglishToPortugueseServer(value) {
    const text = String(value || "").trim();
    if (!text || !/[A-Za-z]/.test(text)) return text;
    if (steamTranslationCache.has(text)) return steamTranslationCache.get(text);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    try {
        const params = new URLSearchParams({
            client: "gtx",
            sl: "en",
            tl: "pt",
            dt: "t",
            q: text
        });
        const response = await fetch(`https://translate.googleapis.com/translate_a/single?${params}`, {
            signal: controller.signal,
            headers: {
                Accept: "application/json",
                "User-Agent": "Mozilla/5.0 (compatible; LughWorldCommunity/1.0)"
            }
        });
        if (!response.ok) throw new Error(`translate_${response.status}`);
        const payload = await response.json();
        const translated = Array.isArray(payload && payload[0])
            ? payload[0].map(part => Array.isArray(part) ? String(part[0] || "") : "").join("").trim()
            : "";
        if (!translated) throw new Error("translate_empty");
        steamTranslationCache.set(text, translated);
        return translated;
    } finally {
        clearTimeout(timeout);
    }
}

function splitTranslationTextServer(value, maxLength = 430) {
    const source = String(value || "").trim();
    if (!source || source.length <= maxLength) return source ? [source] : [];
    const chunks = [];
    let current = "";
    const parts = source.split(/(?<=[.!?;:])\s+|\n+/);
    for (const part of parts) {
        const text = String(part || "").trim();
        if (!text) continue;
        if (text.length > maxLength) {
            if (current) {
                chunks.push(current);
                current = "";
            }
            for (let index = 0; index < text.length; index += maxLength) {
                chunks.push(text.slice(index, index + maxLength));
            }
            continue;
        }
        const next = current ? `${current} ${text}` : text;
        if (next.length > maxLength) {
            chunks.push(current);
            current = text;
        } else {
            current = next;
        }
    }
    if (current) chunks.push(current);
    return chunks;
}

async function myMemoryTranslateEnglishToPortugueseServer(value) {
    const chunks = splitTranslationTextServer(value);
    const translated = [];
    for (const chunk of chunks) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 20000);
        try {
            const params = new URLSearchParams({ q: chunk, langpair: "en|pt-BR" });
            const response = await fetch(`https://api.mymemory.translated.net/get?${params}`, {
                signal: controller.signal,
                headers: {
                    Accept: "application/json",
                    "User-Agent": "Mozilla/5.0 (compatible; LughWorldCommunity/1.0)"
                }
            });
            if (!response.ok) throw new Error(`mymemory_${response.status}`);
            const payload = await response.json();
            const text = String(payload && payload.responseData && payload.responseData.translatedText || "").trim();
            if (!text || /MYMEMORY WARNING/i.test(text)) throw new Error("mymemory_empty");
            translated.push(text);
        } finally {
            clearTimeout(timeout);
        }
    }
    return translated.join(" ").trim();
}

async function translateEnglishTextToPortugueseServer(value) {
    const text = String(value || "").trim();
    if (!text || !/[A-Za-z]/.test(text)) return text;
    try {
        return await googleTranslateEnglishToPortugueseServer(text);
    } catch (googleError) {
        console.warn("[steam-news] Google Translate indisponivel; usando fallback:", googleError.message);
        return myMemoryTranslateEnglishToPortugueseServer(text);
    }
}

async function translateSteamTextBatchServer(values) {
    if (values.length === 1) {
        return [await translateEnglishTextToPortugueseServer(values[0])];
    }
    const startMarker = "\uE000";
    const endMarker = "\uE001";
    const payload = values.map((value, index) => `${startMarker}${index}${endMarker}${value}`).join("\n");
    try {
        const translated = await translateEnglishTextToPortugueseServer(payload);
        const result = new Array(values.length);
        const markerRx = new RegExp(`${startMarker}(\\d+)${endMarker}([\\s\\S]*?)(?=${startMarker}\\d+${endMarker}|$)`, "g");
        let match;
        while ((match = markerRx.exec(translated))) {
            result[Number(match[1])] = String(match[2] || "").replace(/^\s+|\s+$/g, "");
        }
        if (result.every(Boolean)) return result;
    } catch (err) {
        console.warn("[steam-news] traducao em lote falhou; tentando por bloco:", err.message);
    }

    const result = new Array(values.length);
    let cursor = 0;
    const workers = Array.from({ length: Math.min(4, values.length) }, async () => {
        while (cursor < values.length) {
            const index = cursor++;
            try {
                result[index] = await translateEnglishTextToPortugueseServer(values[index]);
            } catch (err) {
                console.warn("[steam-news] bloco sem traducao:", err.message);
                throw new Error("translation_block_failed");
            }
        }
    });
    await Promise.all(workers);
    return result;
}

async function translateSteamHtmlToPortugueseServer(html) {
    const parts = String(html || "").split(/(<[^>]+>)/g);
    const targets = [];
    parts.forEach((part, index) => {
        if (!part || /^<[^>]+>$/.test(part) || !/[A-Za-z]/.test(part)) return;
        const leading = (part.match(/^\s*/) || [""])[0];
        const trailing = (part.match(/\s*$/) || [""])[0];
        const core = decodeSteamHtmlEntities(part.slice(leading.length, part.length - trailing.length)).trim();
        if (core) targets.push({ index, leading, trailing, core });
    });

    for (let start = 0; start < targets.length;) {
        const batch = [];
        let size = 0;
        while (start < targets.length && (batch.length === 0 || size + targets[start].core.length <= 3200)) {
            batch.push(targets[start]);
            size += targets[start].core.length + 12;
            start += 1;
        }
        const translated = await translateSteamTextBatchServer(batch.map(item => item.core));
        batch.forEach((item, index) => {
            parts[item.index] = item.leading + escapeSteamHtml(translated[index] || item.core) + item.trailing;
        });
    }
    return parts.join("");
}

async function translateSteamNewsToPortugueseServer(titleEn, htmlEn) {
    const [titlePt, contentPt] = await Promise.all([
        translateEnglishTextToPortugueseServer(titleEn),
        translateSteamHtmlToPortugueseServer(htmlEn)
    ]);
    if (htmlEn && !steamTextLooksPortuguese(contentPt, htmlEn)) {
        throw new Error("translation_not_portuguese");
    }
    return { titlePt: titlePt || titleEn, contentPt };
}

function steamSummaryFromHtmlServer(html) {
    return String(html || "")
        .replace(/<script[\s\S]*?<\/script>/gi, " ")
        .replace(/<style[\s\S]*?<\/style>/gi, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/&nbsp;/gi, " ")
        .replace(/&amp;/gi, "&")
        .replace(/&lt;/gi, "<")
        .replace(/&gt;/gi, ">")
        .replace(/&quot;/gi, "\"")
        .replace(/&#39;/gi, "'")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 240);
}


function normalizeLocalAssetPathServer(value) {
    let raw = String(value || "").trim();
    if (!raw || /^(data:image|blob:|https?:\/\/|\/\/)/i.test(raw) || /base64/i.test(raw)) return "";
    raw = raw.replace(/^\/+/, "");
    if (!/^assets\//i.test(raw)) return "";
    if (/["'<>`]/.test(raw)) return "";
    return raw;
}

function normalizeNewsSettingsServer(settings) {
    const s = settings || {};
    const arr = Array.isArray(s.homeNewsImages) ? s.homeNewsImages : (Array.isArray(s.globalImages) ? s.globalImages : []);
    return {
        globalImage1: normalizeLocalAssetPathServer(arr[0] || s.globalImage1 || s.homeImage1 || s.newsGlobalImage1 || s.globalImage) || DEFAULT_NEWS_GLOBAL_IMAGE,
        globalImage2: normalizeLocalAssetPathServer(arr[1] || s.globalImage2 || s.homeImage2 || s.newsGlobalImage2) || "",
        globalImage3: normalizeLocalAssetPathServer(arr[2] || s.globalImage3 || s.homeImage3 || s.newsGlobalImage3) || "",
        globalImage4: normalizeLocalAssetPathServer(arr[3] || s.globalImage4 || s.homeImage4 || s.newsGlobalImage4) || ""
    };
}

function getNewsDateValueServer(news) {
    if (!news) return Date.now();
    if (typeof news.createdAt === "number") return news.createdAt;
    if (news.createdAt && typeof news.createdAt.toMillis === "function") return news.createdAt.toMillis();
    if (news.createdAt && typeof news.createdAt.seconds === "number") return news.createdAt.seconds * 1000;
    if (news.date) {
        const parsed = Date.parse(news.date);
        if (!Number.isNaN(parsed)) return parsed;
    }
    return Date.now();
}

function normalizeNewsStatusServer(news) {
    const raw = String((news && news.status) || "").toLowerCase();
    if (["published", "pending", "draft", "archived"].includes(raw)) return raw;
    if (news && news.archived) return "archived";
    if (news && news.pendingApproval) return "pending";
    if (news && news.draft) return "draft";
    return "published";
}

function isNewsVisiblePublicServer(news) {
    return normalizeNewsStatusServer(news) === "published" && !(news && news.hidden === true);
}

async function reserveNextNewsHomeImageServer() {
    const ref = db.collection(NEWS_SETTINGS_COLLECTION).doc(NEWS_SETTINGS_DOC_ID);
    return db.runTransaction(async tx => {
        const snap = await tx.get(ref);
        const raw = snap.exists ? (snap.data() || {}) : {};
        const settings = normalizeNewsSettingsServer(raw);
        const images = [settings.globalImage1, settings.globalImage2, settings.globalImage3, settings.globalImage4]
            .map(normalizeLocalAssetPathServer).filter(Boolean);
        const usable = images.length ? images : [DEFAULT_NEWS_GLOBAL_IMAGE];
        const rawLast = Number(raw.lastUsedImageIndex);
        const nextIndex = Number.isFinite(rawLast) ? (rawLast + 1) % usable.length : 0;
        tx.set(ref, {
            lastUsedImageIndex: nextIndex,
            lastUsedHomeImage: usable[nextIndex],
            lastUsedHomeImageAt: Date.now()
        }, { merge: true });
        return { homeImage: usable[nextIndex], homeImageSlot: nextIndex + 1 };
    });
}

function buildHomeConfigItemServer(news, index) {
    const createdAt = getNewsDateValueServer(news);
    const homeImage = normalizeLocalAssetPathServer(news && (news.homeImage || news.homeCardImage))
        || (index === 0 ? DEFAULT_NEWS_GLOBAL_IMAGE : "");
    const titlePt = news.titlePt || (news.title && news.title.pt) || news.title || "";
    const titleEn = news.titleEn || (news.title && news.title.en) || titlePt;
    const summaryPt = news.summaryPt || (news.summary && news.summary.pt) || "";
    const summaryEn = news.summaryEn || (news.summary && news.summary.en) || summaryPt;
    return {
        id: news.id || "",
        link: news.id || "",
        title: { pt: titlePt, en: titleEn },
        titlePt,
        titleEn,
        summary: { pt: summaryPt, en: summaryEn },
        summaryPt,
        summaryEn,
        category: news.category || "steam",
        source: news.source || "steam",
        date: news.date || new Date(createdAt).toISOString().split("T")[0],
        createdAt,
        homeImage,
        homeCardImage: homeImage,
        status: "published",
        hidden: false
    };
}

async function updateHomeConfigMainServer() {
    const snap = await db.collection(NEWS_COLLECTION).orderBy("createdAt", "desc").limit(10).get();
    const items = [];
    snap.forEach(doc => items.push({ id: doc.id, ...doc.data() }));
    const latest = items.filter(isNewsVisiblePublicServer).sort((a, b) => getNewsDateValueServer(b) - getNewsDateValueServer(a)).slice(0, 3);
    const payload = {
        news: latest.map(buildHomeConfigItemServer),
        updatedAt: Date.now()
    };
    await db.collection(HOME_CONFIG_COLLECTION).doc(HOME_CONFIG_DOC_ID).set(payload, { merge: true });
    return payload;
}

async function attachHomeImageToNewNewsRecordServer(record) {
    if (normalizeLocalAssetPathServer(record && record.homeImage)) return record;
    const choice = await reserveNextNewsHomeImageServer();
    return {
        ...record,
        homeImage: choice.homeImage,
        homeCardImage: choice.homeImage,
        homeImageSlot: choice.homeImageSlot,
        globalImageSlot: String(choice.homeImageSlot)
    };
}

async function buildSteamNewsRecordServer(game, item) {
    const appId = String(game.appId || game.appid || "").trim();
    const gid = String(item.gid || item.id || item.url || item.title || "");
    const localizedEn = getSteamLocalizedItemServer(item, "en");
    const localizedPt = getSteamLocalizedItemServer(item, "pt");
    const titleEn = stripEmojiFromNewsTitle(localizedEn.title || String(game.name || `Steam App ${appId}`));
    const htmlEn = steamContentToHtmlServer(localizedEn.content);
    const hasOfficialPt = steamTextLooksPortuguese(localizedPt.content, localizedEn.content);
    let titlePt = stripEmojiFromNewsTitle(hasOfficialPt ? (localizedPt.title || titleEn) : titleEn);
    let htmlPt = hasOfficialPt ? steamContentToHtmlServer(localizedPt.content) : htmlEn;
    let translationProvider = hasOfficialPt ? "steam-official-localization" : "english-fallback";
    if (!hasOfficialPt && game.autoTranslate !== false && htmlEn) {
        const translated = await translateSteamNewsToPortugueseServer(titleEn, htmlEn);
        titlePt = stripEmojiFromNewsTitle(translated.titlePt);
        htmlPt = translated.contentPt;
        translationProvider = steamTextLooksPortuguese(htmlPt, htmlEn)
            ? "automatic-translation"
            : "english-fallback";
    }
    const contentImages = extractSteamImagesServer(`${htmlEn}${htmlPt}`);
    const explicitCover = getSteamExplicitCoverServer(item);
    const coverImage = explicitCover;
    const images = contentImages.map(img => ({ ...img, cover: false }));
    if (explicitCover) {
        images.unshift({ url: explicitCover, alt: titlePt || titleEn, caption: "", cover: true, order: -1 });
    }
    const bodyHtmlEn = coverImage ? removeSteamCoverFromBodyServer(htmlEn, coverImage) : htmlEn;
    const bodyHtmlPt = coverImage ? removeSteamCoverFromBodyServer(htmlPt, coverImage) : htmlPt;
    const summaryEn = steamSummaryFromHtmlServer(bodyHtmlEn);
    const summaryPt = steamSummaryFromHtmlServer(bodyHtmlPt);
    const timestamp = item.date ? Number(item.date) * 1000 : Date.now();
    const sourceUrl = safeSteamHttpUrl(item.resolved_url || item.url) || `https://store.steampowered.com/news/app/${encodeURIComponent(appId)}`;
    const key = steamDocKey(appId, gid);
    return {
        steamKey: key,
        titlePt,
        titleEn,
        contentPt: bodyHtmlPt,
        contentEn: bodyHtmlEn,
        summaryPt,
        summaryEn,
        title: { pt: titlePt, en: titleEn },
        content: { pt: bodyHtmlPt, en: bodyHtmlEn },
        summary: { pt: summaryPt, en: summaryEn },
        category: "steam",
        status: game.publishMode === "pending" ? "pending" : "published",
        hidden: false,
        images,
        coverImage,
        source: "steam",
        sourceUrl,
        steam: {
            appId,
            appName: game.name || "",
            gid,
            url: sourceUrl,
            importedAt: Date.now(),
            autoTranslate: game.autoTranslate !== false
        },
        original: {
            source: "steam",
            title: { pt: titlePt, en: titleEn },
            content: {
                pt: hasOfficialPt ? localizedPt.content : htmlPt,
                en: localizedEn.content
            },
            html: { pt: htmlPt, en: htmlEn },
            url: sourceUrl
        },
        translation: {
            requested: game.autoTranslate !== false,
            provider: translationProvider,
            note: translationProvider === "steam-official-localization"
                ? "PT-BR and EN imported from the official Steam announcement."
                : translationProvider === "automatic-translation"
                    ? "Steam did not provide PT-BR; the English announcement was translated automatically."
                    : "Steam did not provide PT-BR and automatic translation was unavailable; English was used as fallback."
        },
        formattingVersion: 9,
        date: getSteamPublishedDateServer(item, timestamp),
        createdAt: timestamp,
        updatedAt: Date.now()
    };
}

async function importSteamNewsForGame(game) {
    if (!game || game.enabled === false || !game.appId) return 0;
    const payload = await fetchSteamNewsPayload(game.appId, 10);
    const items = (payload && payload.appnews && payload.appnews.newsitems) || [];
    let created = 0;
    for (const item of items) {
        const gid = String(item.gid || item.id || item.url || item.title || "");
        if (!gid) continue;
        const key = steamDocKey(game.appId, gid);
        const ref = db.collection(NEWS_COLLECTION).doc(steamDocId(game.appId, gid));
        const snap = await ref.get();
        if (snap.exists) {
            const existing = snap.data() || {};
            if (Number(existing.formattingVersion || 0) < 9
                || !steamTextLooksPortuguese(existing.contentPt || existing.content && existing.content.pt, existing.contentEn || existing.content && existing.content.en)) {
                const rebuilt = await buildSteamNewsRecordServer(game, item);
                await ref.set({
                    ...rebuilt,
                    status: existing.status || rebuilt.status,
                    hidden: existing.hidden === true,
                    createdAt: existing.createdAt || rebuilt.createdAt
                }, { merge: true });
            }
            continue;
        }
        const duplicate = await db.collection(NEWS_COLLECTION).where("steamKey", "==", key).limit(1).get();
        if (!duplicate.empty) {
            const duplicateDoc = duplicate.docs[0];
            const existing = duplicateDoc.data() || {};
            if (Number(existing.formattingVersion || 0) < 9
                || !steamTextLooksPortuguese(existing.contentPt || existing.content && existing.content.pt, existing.contentEn || existing.content && existing.content.en)) {
                const rebuilt = await buildSteamNewsRecordServer(game, item);
                await duplicateDoc.ref.set({
                    ...rebuilt,
                    status: existing.status || rebuilt.status,
                    hidden: existing.hidden === true,
                    createdAt: existing.createdAt || rebuilt.createdAt
                }, { merge: true });
            }
            continue;
        }
        await ref.set(await attachHomeImageToNewNewsRecordServer(await buildSteamNewsRecordServer(game, item)), { merge: true });
        created += 1;
    }
    if (created > 0) {
        try { await updateHomeConfigMainServer(); } catch (err) { console.warn("[home_config] atualização após import Steam falhou:", err.message); }
    }
    return created;
}

async function runSteamNewsAutoImport() {
    if (steamNewsImportRunning) return { skipped: true, created: 0 };
    steamNewsImportRunning = true;
    try {
        const snap = await db.collection(NEWS_STEAM_GAMES_COLLECTION).where("enabled", "==", true).get();
        let created = 0;
        for (const doc of snap.docs) {
            created += await importSteamNewsForGame({ id: doc.id, ...doc.data() });
        }
        if (created > 0) console.log(`[steam-news] ${created} noticia(s) importada(s) automaticamente.`);
        return { skipped: false, created };
    } finally {
        steamNewsImportRunning = false;
    }
}

// ===== Steam News Proxy =====
// Evita bloqueios de CORS no navegador ao importar noticias pelo painel Admin.
app.get("/api/steam-news", async (req, res) => {
    const appid = String(req.query.appid || "").trim();
    const count = Math.max(1, Math.min(20, Number(req.query.count) || 10));
    if (!/^\d+$/.test(appid)) {
        return res.status(400).json({ error: "appid invalido" });
    }

    try {
        const payload = await fetchSteamNewsPayload(appid, count);
        res.set("Cache-Control", "public, max-age=300");
        res.json(payload);
    } catch (err) {
        console.error("[steam-news] erro:", err);
        res.status(err.status || 502).json({ error: "steam_fetch_failed" });
    }
});

app.get("/api/steam-announcement-cover", async (req, res) => {
    const url = String(req.query.url || "").trim();
    if (!isAllowedSteamAnnouncementUrl(url)) {
        return res.status(400).json({ error: "steam_url_invalida" });
    }

    try {
        const media = await fetchSteamAnnouncementMedia(url);
        res.set("Cache-Control", "public, max-age=21600");
        res.json(media);
    } catch (err) {
        console.error("[steam-announcement-cover] erro:", err);
        res.status(502).json({ error: "steam_announcement_fetch_failed" });
    }
});

app.post("/api/admin/steam-news/translate", async (req, res) => {
    const user = await getUser(req);
    if (!isAdmin(user)) return res.status(403).json({ error: "forbidden" });

    const titleEn = stripEmojiFromNewsTitle(String(req.body && req.body.titleEn || "").trim()).slice(0, 1000);
    const contentEn = String(req.body && req.body.contentEn || "").trim();
    if (!titleEn && !contentEn) return res.status(400).json({ error: "content_required" });
    if (contentEn.length > 180000) return res.status(413).json({ error: "content_too_large" });

    try {
        const translated = await translateSteamNewsToPortugueseServer(titleEn, contentEn);
        res.json({
            ok: true,
            titlePt: stripEmojiFromNewsTitle(translated.titlePt),
            contentPt: translated.contentPt,
            provider: steamTextLooksPortuguese(translated.contentPt, contentEn)
                ? "automatic-translation"
                : "english-fallback"
        });
    } catch (err) {
        console.error("[steam-news-translate] erro:", err);
        res.status(502).json({ error: "translation_failed" });
    }
});

app.post("/api/admin/steam-news/import", async (req, res) => {
    const user = await getUser(req);
    if (!isAdmin(user)) return res.status(403).json({ error: "forbidden" });
    try {
        const result = await runSteamNewsAutoImport();
        res.json({ ok: true, ...result });
    } catch (err) {
        console.error("[steam-news-import] erro:", err);
        res.status(502).json({ error: "steam_import_failed" });
    }
});

// ===== Healthcheck =====
app.get("/", (_req, res) => res.send("Lugh Premium API ok"));

// ===== Manifest dinâmico de assets =====
// Varre /assets em tempo real. Permite adicionar imagens sem rebuild.
// O frontend (assets-bridge.js) tenta este endpoint primeiro e cai no
// arquivo estático /assets/assets-manifest.json se este host não estiver
// disponível (ex.: site servido em outro domínio).
const fs = require("fs");
const path = require("path");
const ASSETS_DIR = path.join(__dirname, "assets");
const ASSET_FOLDERS = {
    "Lugs":              "lugs",
    "Lugs Prismaticos":  "lugsPrismaticos",
    "Loot":              "loot",
    "Wallpapers":        "wallpapers",
    "UI Icons":          "uiIcons",
    "Maps":              "maps",
    "Map icons":         "mapIcons"
};
const IMG_RX = /\.(png|jpe?g|gif|webp|avif|svg|bmp|ico)$/i;
function resolveAssetDir(folderName) {
    const direct = path.join(ASSETS_DIR, folderName);
    if (fs.existsSync(direct)) return direct;
    const lower = path.join(ASSETS_DIR, folderName.toLowerCase());
    if (fs.existsSync(lower)) return lower;
    return direct;
}

function listAssetImagesRecursive(dir, prefix = "") {
    if (!fs.existsSync(dir)) return [];
    const out = [];
    for (const item of fs.readdirSync(dir)) {
        if (item.startsWith(".")) continue;
        const full = path.join(dir, item);
        const rel = prefix ? path.posix.join(prefix, item) : item;
        const st = fs.statSync(full);
        if (st.isDirectory()) out.push(...listAssetImagesRecursive(full, rel));
        else if (IMG_RX.test(item)) out.push(rel);
    }
    return out;
}

app.get("/api/assets-manifest", (_req, res) => {
    try {
        const out = {};
        for (const folder of Object.keys(ASSET_FOLDERS)) {
            out[ASSET_FOLDERS[folder]] = listAssetImagesRecursive(resolveAssetDir(folder))
                .sort((a, b) => a.localeCompare(b, "pt-BR", { sensitivity: "base" }));
        }
        res.set("Cache-Control", "no-cache");
        res.json(out);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

const steamAutoImportMinutes = Math.max(0, Number(STEAM_NEWS_AUTO_IMPORT_MINUTES) || 0);
if (steamAutoImportMinutes > 0) {
    const steamAutoImportMs = steamAutoImportMinutes * 60 * 1000;
    setTimeout(() => {
        runSteamNewsAutoImport().catch(err => console.error("[steam-news] auto import inicial falhou:", err));
    }, 30000);
    setInterval(() => {
        runSteamNewsAutoImport().catch(err => console.error("[steam-news] auto import falhou:", err));
    }, steamAutoImportMs);
    console.log(`[steam-news] importacao automatica ativa a cada ${steamAutoImportMinutes} minuto(s).`);
}

app.listen(PORT, () => console.log(`Lugh Premium API rodando em :${PORT}`));
