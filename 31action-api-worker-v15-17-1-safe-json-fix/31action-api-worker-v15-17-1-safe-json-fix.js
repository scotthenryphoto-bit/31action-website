const ALLOWED_ORIGINS = new Set([
  "https://31action.com",
  "https://www.31action.com",
  "http://localhost:8787",
  "http://127.0.0.1:8787"
]);

function cors(request) {
  const origin = request.headers.get("Origin") || "";
  const h = new Headers();
  if (ALLOWED_ORIGINS.has(origin)) {
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Vary", "Origin");
  }
  h.set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  h.set("Access-Control-Allow-Headers", "Authorization,Content-Type");
  if (ALLOWED_ORIGINS.has(origin)) h.set("Access-Control-Allow-Credentials", "true");
  return h;
}
function json(request, data, status = 200) {
  const h = cors(request);
  h.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers: h });
}
function text(request, body, status = 200) {
  const h = cors(request);
  h.set("Content-Type", "text/plain; charset=utf-8");
  return new Response(body, { status, headers: h });
}
function isAdmin(request, env) {
  const auth = request.headers.get("Authorization") || "";
  return Boolean(env.ADMIN_TOKEN) && auth === `Bearer ${env.ADMIN_TOKEN}`;
}
function requireAdmin(request, env) {
  return isAdmin(request, env) ? null : json(request, { ok:false, error:"Unauthorized" }, 401);
}
function safePart(value) {
  return String(value || "").trim()
    .replace(/[^a-zA-Z0-9._ -]+/g, "")
    .replace(/\s+/g, "-").replace(/-+/g, "-").replace(/^\.+/, "").slice(0,180);
}
function uid(prefix="id"){ return `${prefix}_${crypto.randomUUID()}`; }
async function bodyJson(request){ try{return await request.json()}catch{return null} }
async function deletePrefix(bucket,prefix){
  let cursor, deleted=0;
  do{
    const page=await bucket.list({prefix,cursor,limit:1000});
    const keys=(page.objects||[]).map(o=>o.key);
    if(keys.length){await bucket.delete(keys);deleted+=keys.length}
    cursor=page.truncated?page.cursor:undefined;
  }while(cursor);
  return deleted;
}
function parseJson(value,fallback=null){try{return value?JSON.parse(value):fallback}catch{return fallback}}


const PLAYER_SESSION_COOKIE = "act31_session";
const PLAYER_SESSION_DAYS = 30;
const PASSWORD_ITERATIONS = 210000;

function bytesToB64(bytes){
  let s="";
  for(let i=0;i<bytes.length;i++) s+=String.fromCharCode(bytes[i]);
  return btoa(s);
}
function b64ToBytes(value){
  const s=atob(String(value||""));
  const out=new Uint8Array(s.length);
  for(let i=0;i<s.length;i++) out[i]=s.charCodeAt(i);
  return out;
}
function randomToken(byteLength=32){
  const bytes=new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytesToB64(bytes).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
async function sha256B64(value){
  const data=new TextEncoder().encode(String(value||""));
  const digest=await crypto.subtle.digest("SHA-256",data);
  return bytesToB64(new Uint8Array(digest));
}
async function passwordHash(password,saltB64,iterations=PASSWORD_ITERATIONS){
  const key=await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits=await crypto.subtle.deriveBits(
    {name:"PBKDF2",hash:"SHA-256",salt:b64ToBytes(saltB64),iterations:Number(iterations)||PASSWORD_ITERATIONS},
    key,
    256
  );
  return bytesToB64(new Uint8Array(bits));
}
function secureEqual(a,b){
  a=String(a||""); b=String(b||"");
  if(a.length!==b.length)return false;
  let diff=0;
  for(let i=0;i<a.length;i++)diff|=a.charCodeAt(i)^b.charCodeAt(i);
  return diff===0;
}
function parseCookies(request){
  const raw=request.headers.get("Cookie")||"";
  const out={};
  for(const part of raw.split(";")){
    const i=part.indexOf("=");
    if(i<0)continue;
    const k=part.slice(0,i).trim();
    const v=part.slice(i+1).trim();
    if(k)out[k]=decodeURIComponent(v);
  }
  return out;
}
function sessionCookie(token,maxAgeSeconds=PLAYER_SESSION_DAYS*86400){
  return `${PLAYER_SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/api; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}
function clearSessionCookie(){
  return `${PLAYER_SESSION_COOKIE}=; Path=/api; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}
function jsonHeaders(request){
  const h=cors(request);
  h.set("Content-Type","application/json; charset=utf-8");
  return h;
}
function jsonCookie(request,data,status,cookie){
  const h=jsonHeaders(request);
  if(cookie)h.append("Set-Cookie",cookie);
  return new Response(JSON.stringify(data),{status,headers:h});
}
async function getPlayerSession(request,env){
  const token=parseCookies(request)[PLAYER_SESSION_COOKIE];
  if(!token)return null;
  const tokenHash=await sha256B64(token);
  const now=new Date().toISOString();
  const row=await env.DB.prepare(`
    SELECT s.id AS session_id,s.user_id,s.expires_at,s.revoked_at,
           u.email,u.display_name,u.account_status,
           ap.id AS athlete_id,ap.player_name,ap.verification_status
    FROM auth_sessions s
    JOIN user_accounts u ON u.id=s.user_id
    LEFT JOIN athlete_profiles ap ON ap.user_id=u.id
    WHERE s.token_hash=?1
      AND s.revoked_at IS NULL
      AND s.expires_at>?2
    LIMIT 1
  `).bind(tokenHash,now).first();
  if(!row)return null;
  if(row.account_status==="suspended")return null;

  // Throttle last-seen writes to avoid a DB write on every request.
  try{
    await env.DB.prepare(`UPDATE auth_sessions SET last_seen_at=?1 WHERE id=?2`)
      .bind(now,row.session_id).run();
  }catch{}
  return row;
}
async function requirePlayer(request,env){
  const session=await getPlayerSession(request,env);
  if(!session)return {response:json(request,{ok:false,error:"Login required"},401),session:null};
  return {response:null,session};
}
async function createPlayerSession(request,env,userId){
  const token=randomToken(32);
  const tokenHash=await sha256B64(token);
  const now=new Date();
  const expires=new Date(now.getTime()+PLAYER_SESSION_DAYS*86400000);
  const id=`session-${crypto.randomUUID()}`;
  await env.DB.prepare(`
    INSERT INTO auth_sessions(id,user_id,token_hash,created_at,expires_at,last_seen_at,revoked_at,user_agent)
    VALUES(?1,?2,?3,?4,?5,?4,NULL,?6)
  `).bind(
    id,userId,tokenHash,now.toISOString(),expires.toISOString(),
    String(request.headers.get("User-Agent")||"").slice(0,500)||null
  ).run();
  return {token,id,expires_at:expires.toISOString()};
}
function normalizedJerseys(input){
  const raw=Array.isArray(input)
    ? input.flatMap(x=>String(x??"").split(/[\s,;]+/))
    : String(input||"").split(/[\s,;]+/);
  return [...new Set(raw.map(x=>String(x??"").trim()).filter(Boolean))].slice(0,20);
}
function normalizedRoles(input){
  const allowed=new Set(["player","parent","client","other"]);
  const raw=Array.isArray(input)?input:[input];
  const roles=[...new Set(raw.map(x=>String(x??"").trim().toLowerCase()).filter(x=>allowed.has(x)))];
  return roles.length?roles:["other"];
}
function normalizedSports(input){
  const allowed=new Set(["baseball","football","lacrosse","soccer","track","pool","other"]);
  const raw=Array.isArray(input)?input:[input];
  const out=[];
  for(const value of raw){
    const s=String(value??"").trim().toLowerCase();
    if(!s)continue;
    if(allowed.has(s))out.push(s);
  }
  return [...new Set(out)];
}
function publicUserShape(row){
  return {
    id:row.user_id||row.id,
    email:row.email,
    display_name:row.display_name||null,
    account_status:row.account_status,
    athlete_id:row.athlete_id||null,
    player_name:row.player_name||null,
    athlete_verification_status:row.verification_status||null
  };
}


function dateKeyUTC(iso){
  const d=iso?new Date(iso):new Date();
  if(Number.isNaN(d.getTime())) return new Date().toISOString().slice(0,10);
  return d.toISOString().slice(0,10);
}
async function ensureNotificationPrefs(env,userId){
  await env.DB.prepare(`
    INSERT OR IGNORE INTO notification_preferences(
      user_id,email_person_tags,email_client_gallery_updates,in_app_notifications,updated_at
    ) VALUES(?1,1,1,1,?2)
  `).bind(userId,new Date().toISOString()).run();
}
async function queueNotification(env,{
  userId,type,galleryId=null,photoId=null,athleteId=null,title,message=null,
  sourceKey=null,emailKind=null,eventAt=null
}){
  if(!userId||!type||!title)return null;
  const now=eventAt||new Date().toISOString();
  await ensureNotificationPrefs(env,userId);

  let notificationId=`notif-${crypto.randomUUID()}`;
  if(sourceKey){
    const existing=await env.DB.prepare(`
      SELECT id FROM user_notifications WHERE source_key=?1 LIMIT 1
    `).bind(sourceKey).first();
    if(existing) notificationId=existing.id;
  }

  const existingNotif=await env.DB.prepare(`
    SELECT id FROM user_notifications WHERE id=?1
  `).bind(notificationId).first();

  if(!existingNotif){
    await env.DB.prepare(`
      INSERT INTO user_notifications(
        id,user_id,notification_type,gallery_id,photo_id,athlete_id,title,message,
        created_at,read_at,source_key
      ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL,?10)
    `).bind(
      notificationId,userId,type,galleryId,photoId,athleteId,title,message,now,sourceKey
    ).run();
  }

  if(emailKind && galleryId){
    const pref=await env.DB.prepare(`
      SELECT email_person_tags,email_client_gallery_updates
      FROM notification_preferences WHERE user_id=?1
    `).bind(userId).first();

    const allowed = emailKind==="person_tag"
      ? Boolean(pref?.email_person_tags)
      : Boolean(pref?.email_client_gallery_updates);

    if(allowed){
      const batchDate=dateKeyUTC(now);
      let batch=await env.DB.prepare(`
        SELECT id,item_count FROM email_notification_batches
        WHERE user_id=?1 AND gallery_id=?2 AND notification_kind=?3 AND batch_date=?4
        LIMIT 1
      `).bind(userId,galleryId,emailKind,batchDate).first();

      if(!batch){
        const batchId=`emailbatch-${crypto.randomUUID()}`;
        await env.DB.prepare(`
          INSERT INTO email_notification_batches(
            id,user_id,gallery_id,notification_kind,batch_date,first_event_at,last_event_at,
            item_count,email_status,sent_at,provider_message_id,last_error,created_at,updated_at
          ) VALUES(?1,?2,?3,?4,?5,?6,?6,1,'pending',NULL,NULL,NULL,?6,?6)
        `).bind(batchId,userId,galleryId,emailKind,batchDate,now).run();
        batch={id:batchId,item_count:1};
      }else{
        const itemExists=await env.DB.prepare(`
          SELECT id FROM email_notification_batch_items
          WHERE batch_id=?1 AND notification_id=?2 LIMIT 1
        `).bind(batch.id,notificationId).first();
        if(!itemExists){
          await env.DB.prepare(`
            UPDATE email_notification_batches
            SET item_count=item_count+1,last_event_at=?1,updated_at=?1
            WHERE id=?2
          `).bind(now,batch.id).run();
        }
      }

      const batchItemExists=await env.DB.prepare(`
        SELECT id FROM email_notification_batch_items
        WHERE batch_id=?1 AND notification_id=?2 LIMIT 1
      `).bind(batch.id,notificationId).first();
      if(!batchItemExists){
        await env.DB.prepare(`
          INSERT INTO email_notification_batch_items(id,batch_id,photo_id,notification_id,created_at)
          VALUES(?1,?2,?3,?4,?5)
        `).bind(`emailitem-${crypto.randomUUID()}`,batch.id,photoId,notificationId,now).run();
      }
    }
  }

  return notificationId;
}
async function queuePersonTagNotifications(env,photoId,tagId){
  const rows=await env.DB.prepare(`
    SELECT DISTINCT ua.id AS user_id,ap.id AS athlete_id,ap.player_name,
           p.gallery_id,g.title AS gallery_title
    FROM athlete_tag_links atl
    JOIN athlete_profiles ap ON ap.id=atl.athlete_id
    JOIN user_accounts ua ON ua.id=ap.user_id
    JOIN photos p ON p.id=?1
    JOIN galleries g ON g.id=p.gallery_id
    WHERE atl.tag_id=?2
      AND ap.verification_status='verified'
      AND ua.account_status!='suspended'
  `).bind(photoId,tagId).all();

  for(const r of rows.results||[]){
    await queueNotification(env,{
      userId:r.user_id,
      type:"person_tag",
      galleryId:r.gallery_id,
      photoId,
      athleteId:r.athlete_id,
      title:`New photo of you in ${r.gallery_title}`,
      message:"A new photo was tagged as you.",
      sourceKey:`person-tag:${r.user_id}:${photoId}:${tagId}`,
      emailKind:"person_tag"
    });
  }
}
async function queueClientGalleryPhotoNotifications(env,galleryId,photoId){
  const rows=await env.DB.prepare(`
    SELECT e.user_id,g.title AS gallery_title
    FROM client_gallery_entitlements e
    JOIN galleries g ON g.id=e.gallery_id
    WHERE e.gallery_id=?1 AND e.status='active'
  `).bind(galleryId).all();

  for(const r of rows.results||[]){
    await queueNotification(env,{
      userId:r.user_id,
      type:"client_gallery_update",
      galleryId,
      photoId,
      title:`New photos added to ${r.gallery_title}`,
      message:"New photos were added to one of your client galleries.",
      sourceKey:`client-gallery-photo:${r.user_id}:${photoId}`,
      emailKind:"client_gallery_update"
    });
  }
}



function normalizePersonTagLabel(value){
  return String(value||"")
    .trim()
    .replace(/\s+/g," ")
    .slice(0,100);
}


function cleanRosterField(v,max=120){
  return String(v??"").trim().replace(/\s+/g," ").slice(0,max);
}
function splitPlayerName(v){
  const display=cleanRosterField(v,100);
  const parts=display.split(" ").filter(Boolean);
  if(parts.length<2)return {first_name:parts[0]||"",last_name:"",display_name:display};
  return {
    first_name:parts.slice(0,-1).join(" "),
    last_name:parts[parts.length-1],
    display_name:display
  };
}
function rosterPlayerLabel(row){
  const bits=[];
  if(row.school)bits.push(row.school);
  if(row.sport)bits.push(row.sport);
  if(row.team && row.team!==row.school)bits.push(row.team);
  if(row.jersey_number)bits.push(`#${row.jersey_number}`);
  return `${row.display_name}${bits.length?` — ${bits.join(" · ")}`:""}`;
}

async function logActivity(env,{
  eventType,userId=null,galleryId=null,photoId=null,athleteId=null,
  orderId=null,amountCents=null,metadata=null,occurredAt=null
}){
  const now=occurredAt||new Date().toISOString();
  const id=`activity-${crypto.randomUUID()}`;
  await env.DB.prepare(`
    INSERT INTO activity_log(
      id,event_type,user_id,gallery_id,photo_id,athlete_id,order_id,amount_cents,
      metadata_json,occurred_at,created_at
    ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)
  `).bind(
    id,eventType,userId,galleryId,photoId,athleteId,orderId,
    amountCents===null?null:Number(amountCents),
    metadata?JSON.stringify(metadata):null,now
  ).run();
  return id;
}

async function queueAdminEmailBatch(env,{
  batchType,batchKey,activityId=null,claimId=null,orderId=null,eventAt=null
}){
  const now=eventAt||new Date().toISOString();
  let batch=await env.DB.prepare(`
    SELECT id,item_count FROM admin_email_batches
    WHERE batch_type=?1 AND batch_key=?2
    LIMIT 1
  `).bind(batchType,batchKey).first();

  if(!batch){
    const id=`adminbatch-${crypto.randomUUID()}`;
    await env.DB.prepare(`
      INSERT INTO admin_email_batches(
        id,batch_type,batch_key,status,item_count,first_event_at,last_event_at,
        sent_at,provider_message_id,last_error,created_at,updated_at
      ) VALUES(?1,?2,?3,'pending',1,?4,?4,NULL,NULL,NULL,?4,?4)
    `).bind(id,batchType,batchKey,now).run();
    batch={id,item_count:1};
  }else{
    await env.DB.prepare(`
      UPDATE admin_email_batches
      SET item_count=item_count+1,last_event_at=?1,updated_at=?1
      WHERE id=?2
    `).bind(now,batch.id).run();
  }

  await env.DB.prepare(`
    INSERT INTO admin_email_batch_items(id,batch_id,activity_id,claim_id,order_id,created_at)
    VALUES(?1,?2,?3,?4,?5,?6)
  `).bind(
    `adminbatchitem-${crypto.randomUUID()}`,batch.id,
    activityId,claimId,orderId,now
  ).run();

  return batch.id;
}

function reportDateRange(url){
  const now=new Date();
  const startRaw=String(url.searchParams.get("start")||"").trim();
  const endRaw=String(url.searchParams.get("end")||"").trim();

  let start,end;
  if(startRaw){
    start=new Date(startRaw.includes("T")?startRaw:`${startRaw}T00:00:00.000Z`);
  }else{
    start=new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),1,0,0,0,0));
  }

  if(endRaw){
    end=new Date(endRaw.includes("T")?endRaw:`${endRaw}T23:59:59.999Z`);
  }else{
    end=new Date();
  }

  if(Number.isNaN(start.getTime())||Number.isNaN(end.getTime())||start>end){
    return null;
  }
  return {start:start.toISOString(),end:end.toISOString()};
}


// ---------- STRIPE CHECKOUT (SANDBOX/LIVE KEY IS SUPPLIED BY WORKER SECRET) ----------
function stripeMoneyCents(value){
  const n=Number(value);
  if(!Number.isFinite(n)||n<0)return 0;
  return Math.round(n*100);
}

async function stripeCreateCheckoutSession(env, fields){
  if(!env.STRIPE_SECRET_KEY){
    const err=new Error("Stripe secret is not configured on this Worker.");
    err.code="STRIPE_NOT_CONFIGURED";
    throw err;
  }

  const body=new URLSearchParams();

  // Hosted one-time Checkout.
  body.set("mode","payment");
  body.set("success_url","https://31action.com/cart.html?stripe=success&session_id={CHECKOUT_SESSION_ID}");
  body.set("cancel_url","https://31action.com/cart.html?stripe=cancelled");
  body.set("customer_creation","always");
  body.set("billing_address_collection","auto");
  body.set("phone_number_collection[enabled]","true");

  if(fields.customerEmail){
    body.set("customer_email",fields.customerEmail);
  }

  if(fields.collectShipping){
    body.set("shipping_address_collection[allowed_countries][0]","US");
  }

  const ref=String(fields.clientReferenceId||"").trim().slice(0,200);
  if(ref)body.set("client_reference_id",ref);

  // Useful session metadata only. Full order details will move to D1 in the webhook phase.
  body.set("metadata[site]","31action.com");
  body.set("metadata[checkout_phase]","sandbox_initial");
  if(fields.itemCount!=null)body.set("metadata[item_count]",String(fields.itemCount));

  (fields.lineItems||[]).forEach((item,i)=>{
    body.set(`line_items[${i}][quantity]`,String(Math.max(1,Math.floor(Number(item.quantity)||1))));
    body.set(`line_items[${i}][price_data][currency]`,"usd");
    body.set(`line_items[${i}][price_data][unit_amount]`,String(Math.max(1,Math.floor(Number(item.unitAmount)||0))));
    body.set(`line_items[${i}][price_data][product_data][name]`,String(item.name||"31 ACTION Photo").slice(0,120));
    if(item.description){
      body.set(`line_items[${i}][price_data][product_data][description]`,String(item.description).slice(0,500));
    }
  });

  const response=await fetch("https://api.stripe.com/v1/checkout/sessions",{
    method:"POST",
    headers:{
      "Authorization":`Bearer ${env.STRIPE_SECRET_KEY}`,
      "Stripe-Version":"2026-07-29.dahlia",
      "Content-Type":"application/x-www-form-urlencoded"
    },
    body
  });

  const raw=await response.text();
  let data={};
  try{data=raw?JSON.parse(raw):{}}catch(_){data={error:{message:raw||"Stripe returned an unreadable response."}}}

  if(!response.ok){
    const err=new Error(data?.error?.message||`Stripe request failed (${response.status}).`);
    err.status=response.status;
    err.stripeType=data?.error?.type||null;
    err.stripeCode=data?.error?.code||null;
    throw err;
  }

  return data;
}


async function stripeCreateEmbeddedCheckoutSession(env, fields){
  if(!env.STRIPE_SECRET_KEY){
    const err=new Error("Stripe secret is not configured on this Worker.");
    err.code="STRIPE_NOT_CONFIGURED";
    throw err;
  }

  const body=new URLSearchParams();
  body.set("mode","payment");
  body.set("ui_mode","embedded_page");
  body.set("return_url","https://31action.com/order-confirmation.html?session_id={CHECKOUT_SESSION_ID}");
  body.set("customer_creation","always");
  body.set("billing_address_collection","auto");
  body.set("phone_number_collection[enabled]","true");

  if(fields.customerEmail){
    body.set("customer_email",fields.customerEmail);
  }

  if(fields.collectShipping){
    body.set("shipping_address_collection[allowed_countries][0]","US");

    // Required for Stripe Embedded Checkout dynamic shipping.
    body.set("permissions[update_shipping_details]","server_only");

    // Stripe requires an initial placeholder shipping option.
    // The Worker replaces this with the live Prodigi Budget quote after address entry.
    body.set("shipping_options[0][shipping_rate_data][display_name]","Budget Shipping");
    body.set("shipping_options[0][shipping_rate_data][type]","fixed_amount");
    body.set("shipping_options[0][shipping_rate_data][fixed_amount][amount]","0");
    body.set("shipping_options[0][shipping_rate_data][fixed_amount][currency]","usd");
  }

  const ref=String(fields.clientReferenceId||"").trim().slice(0,200);
  if(ref)body.set("client_reference_id",ref);

  body.set("metadata[site]","31action.com");
  body.set("metadata[checkout_phase]","embedded_sandbox");
  if(fields.itemCount!=null)body.set("metadata[item_count]",String(fields.itemCount));

  (fields.lineItems||[]).forEach((item,i)=>{
    body.set(`line_items[${i}][quantity]`,String(Math.max(1,Math.floor(Number(item.quantity)||1))));
    body.set(`line_items[${i}][price_data][currency]`,"usd");
    body.set(`line_items[${i}][price_data][unit_amount]`,String(Math.max(1,Math.floor(Number(item.unitAmount)||0))));
    body.set(`line_items[${i}][price_data][product_data][name]`,String(item.name||"31 ACTION Photo").slice(0,120));
    if(item.description){
      body.set(`line_items[${i}][price_data][product_data][description]`,String(item.description).slice(0,500));
    }
  });

  const response=await fetch("https://api.stripe.com/v1/checkout/sessions",{
    method:"POST",
    headers:{
      "Authorization":`Bearer ${env.STRIPE_SECRET_KEY}`,
      "Stripe-Version":"2026-07-29.dahlia",
      "Content-Type":"application/x-www-form-urlencoded"
    },
    body
  });

  const raw=await response.text();
  let data={};
  try{data=raw?JSON.parse(raw):{}}catch(_){
    data={error:{message:raw||"Stripe returned an unreadable response."}};
  }

  if(!response.ok){
    const err=new Error(data?.error?.message||`Stripe request failed (${response.status}).`);
    err.status=response.status;
    err.stripeType=data?.error?.type||null;
    err.stripeCode=data?.error?.code||null;
    throw err;
  }

  if(!data.client_secret){
    throw new Error("Stripe did not return an Embedded Checkout client secret.");
  }

  return data;
}


function stripeCheckoutPricingItems(rawItems){
  const items=Array.isArray(rawItems)?rawItems:[];
  if(!items.length)throw new Error("Your cart is empty.");
  if(items.length>100)throw new Error("Too many cart items.");

  // These are the currently published 31 ACTION prices.
  // Never trust a price supplied by the browser.
  const products={
    digital:{label:"Digital Download",price:10,shipping:false},
    print_4x6:{label:"4 × 6 Print",price:8,shipping:true},
    print_5x7:{label:"5 × 7 Print",price:12,shipping:true},
    print_8x10:{label:"8 × 10 Print",price:20,shipping:true},
    print_11x14:{label:"11 × 14 Print",price:32,shipping:true}
  };

  const digitalGroups=new Map();
  const physical=[];
  let itemCount=0;
  let collectShipping=false;

  for(const raw of items){
    const productId=String(raw?.productId||"").trim();
    const product=products[productId];
    if(!product)throw new Error(`Unsupported product: ${productId||"unknown"}`);

    const quantity=Math.max(1,Math.min(25,Math.floor(Number(raw?.quantity)||1)));
    itemCount+=quantity;

    const shootId=String(raw?.shootId||"event").trim().slice(0,120)||"event";
    const shootTitle=String(raw?.shootTitle||"Photo Event").trim().slice(0,120)||"Photo Event";
    const filename=String(raw?.filename||"").trim().slice(0,180);

    if(productId==="digital"){
      let g=digitalGroups.get(shootId);
      if(!g){
        g={shootId,shootTitle,count:0};
        digitalGroups.set(shootId,g);
      }
      g.count+=quantity;
      continue;
    }

    collectShipping=true;
    physical.push({
      name:product.label,
      description:filename?`${shootTitle} · ${filename}`:shootTitle,
      quantity,
      unitAmount:stripeMoneyCents(product.price)
    });
  }

  const lineItems=[...physical];

  // Any 3 Digitals = $25, remaining singles = $10.
  for(const g of digitalGroups.values()){
    const packs=Math.floor(g.count/3);
    const singles=g.count%3;
    if(packs){
      lineItems.push({
        name:"Any 3 Digitals",
        description:`${g.shootTitle} · 3 digital photographs per package`,
        quantity:packs,
        unitAmount:2500
      });
    }
    if(singles){
      lineItems.push({
        name:"Digital Download",
        description:g.shootTitle,
        quantity:singles,
        unitAmount:1000
      });
    }
  }

  if(!lineItems.length)throw new Error("No purchasable items were found.");

  return {lineItems,itemCount,collectShipping};
}



function stripeProductCatalog(){
  return {
    digital:{label:"Digital Download",unit_cents:1000,shipping:false},
    print_4x6:{label:"4 × 6 Print",unit_cents:800,shipping:true},
    print_5x7:{label:"5 × 7 Print",unit_cents:1200,shipping:true},
    print_8x10:{label:"8 × 10 Print",unit_cents:2000,shipping:true},
    print_11x14:{label:"11 × 14 Print",unit_cents:3200,shipping:true}
  };
}

async function stripeBuildOrderSnapshot(env,rawItems){
  const items=Array.isArray(rawItems)?rawItems:[];
  const catalog=stripeProductCatalog();
  const snapshot=[];
  const digitalCounts=new Map();
  let regularSubtotalCents=0;
  let requiresShipping=false;

  for(const raw of items){
    const productId=String(raw?.productId||"").trim();
    const product=catalog[productId];
    if(!product)throw new Error(`Unsupported product: ${productId||"unknown"}`);

    const galleryId=String(raw?.shootId||"").trim().slice(0,120);
    const filename=String(raw?.filename||"").trim().slice(0,240);
    const quantity=Math.max(1,Math.min(25,Math.floor(Number(raw?.quantity)||1)));

    if(!galleryId||!filename)throw new Error("A cart item is missing its gallery or filename.");

    const photo=await env.DB.prepare(`
      SELECT p.id,p.gallery_id,p.filename,g.title AS gallery_title
      FROM photos p
      JOIN galleries g ON g.id=p.gallery_id
      WHERE p.gallery_id=?1 AND p.filename=?2
      LIMIT 1
    `).bind(galleryId,filename).first();

    if(!photo)throw new Error(`Photo not found in gallery: ${filename}`);

    const row={
      cart_id:String(raw?.cartId||"").slice(0,120)||null,
      photo_id:String(photo.id),
      gallery_id:String(photo.gallery_id),
      gallery_title:String(photo.gallery_title||raw?.shootTitle||"Photo Event").slice(0,200),
      filename:String(photo.filename),
      product_id:productId,
      product_label:product.label,
      quantity,
      unit_cents:product.unit_cents,
      requires_shipping:Boolean(product.shipping)
    };
    snapshot.push(row);

    regularSubtotalCents+=product.unit_cents*quantity;
    if(product.shipping)requiresShipping=true;
    if(productId==="digital"){
      digitalCounts.set(galleryId,(digitalCounts.get(galleryId)||0)+quantity);
    }
  }

  let discountCents=0;
  for(const count of digitalCounts.values()){
    discountCents+=Math.floor(count/3)*500; // 3 x $10 -> $25
  }

  const chargedItemCents=regularSubtotalCents-discountCents;
  return {snapshot,regularSubtotalCents,discountCents,chargedItemCents,requiresShipping};
}

function stripeHex(bytes){
  return [...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,"0")).join("");
}

function stripeConstantTimeEqual(a,b){
  const aa=String(a||"").toLowerCase();
  const bb=String(b||"").toLowerCase();
  if(aa.length!==bb.length)return false;
  let diff=0;
  for(let i=0;i<aa.length;i++)diff|=aa.charCodeAt(i)^bb.charCodeAt(i);
  return diff===0;
}

async function stripeVerifyWebhookSignature(rawBodyBytes,signatureHeader,secret,toleranceSeconds=300){
  const endpointSecret=String(secret||"").trim();
  if(!endpointSecret)throw new Error("Stripe webhook secret is not configured.");
  if(!signatureHeader)throw new Error("Missing Stripe-Signature header.");

  const parts=String(signatureHeader).split(",").map(x=>x.trim());
  const timestamp=parts.find(x=>x.startsWith("t="))?.slice(2);
  const signatures=parts.filter(x=>x.startsWith("v1=")).map(x=>x.slice(3));
  if(!timestamp||!signatures.length)throw new Error("Invalid Stripe-Signature header.");

  const ts=Number(timestamp);
  if(!Number.isFinite(ts))throw new Error("Invalid Stripe webhook timestamp.");

  const now=Math.floor(Date.now()/1000);
  if(Math.abs(now-ts)>toleranceSeconds)throw new Error("Stripe webhook timestamp is outside the allowed tolerance.");

  const rawBytes=rawBodyBytes instanceof Uint8Array
    ? rawBodyBytes
    : new Uint8Array(rawBodyBytes);
  const prefix=new TextEncoder().encode(`${timestamp}.`);
  const signedPayload=new Uint8Array(prefix.length+rawBytes.length);
  signedPayload.set(prefix,0);
  signedPayload.set(rawBytes,prefix.length);

  const key=await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(endpointSecret),
    {name:"HMAC",hash:{name:"SHA-256"}},
    false,
    ["sign"]
  );
  const digest=await crypto.subtle.sign("HMAC",key,signedPayload);
  const expected=stripeHex(digest);

  if(!signatures.some(sig=>stripeConstantTimeEqual(sig,expected))){
    throw new Error("Stripe webhook signature verification failed.");
  }
  return true;
}
async function stripeMarkWebhookEvent(env,event,status,lastError=null,sessionId=null){
  const now=new Date().toISOString();
  await env.DB.prepare(`
    INSERT INTO stripe_webhook_events(
      event_id,event_type,stripe_created,stripe_session_id,
      processing_status,attempts,last_error,received_at,processed_at
    ) VALUES(?1,?2,?3,?4,?5,1,?6,?7,?8)
    ON CONFLICT(event_id) DO UPDATE SET
      attempts=stripe_webhook_events.attempts+1,
      processing_status=excluded.processing_status,
      last_error=excluded.last_error,
      stripe_session_id=COALESCE(excluded.stripe_session_id,stripe_webhook_events.stripe_session_id),
      processed_at=excluded.processed_at
  `).bind(
    String(event.id),
    String(event.type||"unknown"),
    Number(event.created)||null,
    sessionId||null,
    status,
    lastError,
    now,
    ["processed","ignored","failed"].includes(status)?now:null
  ).run();
}


// ---------- SECURE DIGITAL DOWNLOADS ----------
const DIGITAL_DOWNLOAD_DAYS = 30;

function downloadExpiryIso(days=DIGITAL_DOWNLOAD_DAYS){
  return new Date(Date.now()+Number(days)*86400000).toISOString();
}

async function ensureDigitalEntitlementsForOrder(env,orderId){
  const now=new Date().toISOString();
  const expiresAt=downloadExpiryIso();

  const rows=await env.DB.prepare(`
    SELECT oi.id AS order_item_id,oi.order_id,oi.photo_id,oi.product_id
    FROM order_items oi
    WHERE oi.order_id=?1
      AND oi.product_id='digital'
  `).bind(orderId).all();

  for(const row of rows.results||[]){
    const existing=await env.DB.prepare(`
      SELECT id FROM digital_download_entitlements
      WHERE order_item_id=?1
      LIMIT 1
    `).bind(row.order_item_id).first();

    if(existing)continue;

    // Seed with an unusable-at-client placeholder token hash.
    // A fresh customer-facing token is minted whenever the confirmation API is loaded.
    const seedToken=randomToken(48);
    const seedHash=await sha256B64(seedToken);

    await env.DB.prepare(`
      INSERT INTO digital_download_entitlements(
        id,order_id,order_item_id,photo_id,token_hash,status,
        expires_at,download_count,max_downloads,
        created_at,updated_at,last_download_at
      ) VALUES(
        ?1,?2,?3,?4,?5,'active',
        ?6,0,NULL,
        ?7,?7,NULL
      )
    `).bind(
      `download-${crypto.randomUUID()}`,
      row.order_id,
      row.order_item_id,
      row.photo_id,
      seedHash,
      expiresAt,
      now
    ).run();
  }
}

async function mintDigitalDownloadLinks(env,orderId){
  await ensureDigitalEntitlementsForOrder(env,orderId);

  const rows=await env.DB.prepare(`
    SELECT
      dde.id AS entitlement_id,
      dde.order_id,
      dde.order_item_id,
      dde.photo_id,
      dde.status,
      dde.expires_at,
      dde.download_count,
      oi.product_id,
      oid.filename,
      p.original_key
    FROM digital_download_entitlements dde
    JOIN order_items oi ON oi.id=dde.order_item_id
    LEFT JOIN order_item_details oid ON oid.order_item_id=oi.id
    JOIN photos p ON p.id=dde.photo_id
    WHERE dde.order_id=?1
      AND oi.product_id='digital'
    ORDER BY oi.created_at,oi.id
  `).bind(orderId).all();

  const nowIso=new Date().toISOString();
  const out=[];

  for(const row of rows.results||[]){
    if(row.status!=='active')continue;
    if(String(row.expires_at||'')<=nowIso)continue;
    if(!row.original_key)continue;

    // Rotate the public token every time confirmation is loaded.
    // Only its hash is stored in D1.
    const token=randomToken(48);
    const tokenHash=await sha256B64(token);

    await env.DB.prepare(`
      UPDATE digital_download_entitlements
      SET token_hash=?1,updated_at=?2
      WHERE id=?3
    `).bind(tokenHash,new Date().toISOString(),row.entitlement_id).run();

    out.push({
      order_item_id:row.order_item_id,
      photo_id:row.photo_id,
      filename:row.filename||null,
      expires_at:row.expires_at,
      download_count:Number(row.download_count)||0,
      download_url:`https://api.31action.com/api/download/${encodeURIComponent(row.entitlement_id)}/${encodeURIComponent(token)}`
    });
  }

  return out;
}

function safeDownloadFilename(name){
  const cleaned=String(name||"31ACTION-photo.jpg")
    .replace(/[\r\n"]/g,"")
    .replace(/[\\/:*?<>|]+/g,"-")
    .trim()
    .slice(0,180);
  return cleaned||"31ACTION-photo.jpg";
}

async function stripeCreatePaidOrderFromSession(env,event,session){
  const sessionId=String(session?.id||"");
  if(!sessionId)throw new Error("Stripe session id is missing.");

  const draft=await env.DB.prepare(`
    SELECT * FROM checkout_drafts WHERE stripe_session_id=?1 LIMIT 1
  `).bind(sessionId).first();
  if(!draft)throw new Error(`No checkout draft found for Stripe session ${sessionId}.`);

  const existing=await env.DB.prepare(`
    SELECT id FROM orders WHERE stripe_session_id=?1 LIMIT 1
  `).bind(sessionId).first();
  if(existing){
    await env.DB.prepare(`
      UPDATE checkout_drafts
      SET payment_status='paid',updated_at=?1,paid_at=COALESCE(paid_at,?1)
      WHERE stripe_session_id=?2
    `).bind(new Date().toISOString(),sessionId).run();
    await ensureDigitalEntitlementsForOrder(env,String(existing.id));
    return {orderId:String(existing.id),duplicate:true};
  }

  let cart=[];
  try{cart=JSON.parse(draft.cart_json||"[]")}catch(_){}
  if(!Array.isArray(cart)||!cart.length)throw new Error("Checkout draft cart is empty.");

  const now=new Date().toISOString();
  const orderId=`order-${crypto.randomUUID()}`;

  const stripeSubtotal=Number(session.amount_subtotal)||Number(draft.amount_total_cents)||0;
  const stripeTotal=Number(session.amount_total)||stripeSubtotal;
  const regularSubtotal=cart.reduce((sum,x)=>sum+(Number(x.unit_cents)||0)*(Number(x.quantity)||1),0);
  const discountCents=Math.max(0,regularSubtotal-stripeSubtotal);

  const paymentIntentId=typeof session.payment_intent==="string"
    ?session.payment_intent
    :(session.payment_intent?.id||null);
  const stripeCustomerId=typeof session.customer==="string"
    ?session.customer
    :(session.customer?.id||null);

  const customerDetails=session.customer_details||{};
  const customerEmail=String(customerDetails.email||draft.customer_email||"").trim().toLowerCase();
  if(!customerEmail)throw new Error("Paid Stripe session has no customer email.");

  const shipping=session.collected_information?.shipping_details||session.shipping_details||null;
  const shipAddress=shipping?.address||null;

  // Stripe is the source of truth for the shipping amount actually charged.
  const shippingCents=Math.max(
    0,
    Number(session?.total_details?.amount_shipping) || 0
  );
  const taxCents=Math.max(0,stripeTotal-stripeSubtotal-shippingCents);

  const statements=[];

  statements.push(env.DB.prepare(`
    INSERT INTO orders(
      id,email,stripe_session_id,status,
      subtotal_cents,discount_cents,shipping_cents,tax_cents,total_cents,
      created_at,updated_at
    ) VALUES(?1,?2,?3,'paid',?4,?5,?6,?7,?8,?9,?9)
  `).bind(
    orderId,customerEmail,sessionId,
    regularSubtotal,discountCents,shippingCents,taxCents,stripeTotal,now
  ));

  statements.push(env.DB.prepare(`
    INSERT INTO order_details(
      order_id,client_reference_id,customer_name,customer_phone,
      shipping_name,shipping_address1,shipping_address2,shipping_city,
      shipping_state,shipping_postal_code,shipping_country,
      stripe_payment_intent_id,stripe_customer_id,stripe_checkout_session_id,
      notes,payment_provider,fulfillment_status,paid_at,updated_at
    ) VALUES(
      ?1,?2,?3,?4,
      ?5,?6,?7,?8,
      ?9,?10,?11,
      ?12,?13,?14,
      ?15,'stripe','not_started',?16,?16
    )
  `).bind(
    orderId,draft.client_reference_id||session.client_reference_id||null,
    customerDetails.name||draft.customer_name||null,
    customerDetails.phone||draft.customer_phone||null,
    shipping?.name||null,
    shipAddress?.line1||null,
    shipAddress?.line2||null,
    shipAddress?.city||null,
    shipAddress?.state||null,
    shipAddress?.postal_code||null,
    shipAddress?.country||null,
    paymentIntentId,stripeCustomerId,sessionId,
    draft.notes||null,now
  ));

  for(const item of cart){
    const itemId=`orderitem-${crypto.randomUUID()}`;
    statements.push(env.DB.prepare(`
      INSERT INTO order_items(
        id,order_id,photo_id,product_id,quantity,unit_cents,created_at
      ) VALUES(?1,?2,?3,?4,?5,?6,?7)
    `).bind(
      itemId,orderId,String(item.photo_id),
      String(item.product_id),
      Math.max(1,Math.floor(Number(item.quantity)||1)),
      Math.max(0,Math.floor(Number(item.unit_cents)||0)),
      now
    ));

    statements.push(env.DB.prepare(`
      INSERT INTO order_item_details(
        order_item_id,gallery_id,filename,product_label,
        requires_shipping,cart_snapshot_json
      ) VALUES(?1,?2,?3,?4,?5,?6)
    `).bind(
      itemId,item.gallery_id||null,item.filename||null,
      item.product_label||null,item.requires_shipping?1:0,
      JSON.stringify(item)
    ));
  }

  statements.push(env.DB.prepare(`
    UPDATE checkout_drafts
    SET payment_status='paid',
        amount_subtotal_cents=?1,
        amount_total_cents=?2,
        stripe_payment_intent_id=?3,
        stripe_customer_id=?4,
        updated_at=?5,
        paid_at=?5
    WHERE stripe_session_id=?6
  `).bind(stripeSubtotal,stripeTotal,paymentIntentId,stripeCustomerId,now,sessionId));

  statements.push(env.DB.prepare(`
    INSERT INTO stripe_checkout_status_log(
      id,stripe_session_id,order_id,status,detail,created_at
    ) VALUES(?1,?2,?3,'paid',?4,?5)
  `).bind(
    `slog-${crypto.randomUUID()}`,sessionId,orderId,
    `checkout.session.completed ${event.id}`,now
  ));

  await env.DB.batch(statements);
  await ensureDigitalEntitlementsForOrder(env,orderId);
  return {orderId,duplicate:false};
}


// ---------- PRODIGI SANDBOX PRODUCT + QUOTE TEST ----------
const PRODIGI_SANDBOX_BASE="https://api.sandbox.prodigi.com/v4.0";
const PRODIGI_INITIAL_PRINTS=Object.freeze({
  "4x6":"GLOBAL-PHO-4X6",
  "5x7":"GLOBAL-PHO-5X7",
  "8x10":"GLOBAL-PHO-8X10"
});

async function prodigiSandboxGet(env,path,options={}){
  if(!env.PRODIGI_API_KEY){
    const err=new Error("Prodigi API key is not configured.");
    err.code="PRODIGI_NOT_CONFIGURED";
    throw err;
  }

  const response=await fetch(`${PRODIGI_SANDBOX_BASE}${path}`,{
    method:options.method||"GET",
    headers:{
      "X-API-Key":String(env.PRODIGI_API_KEY),
      "Accept":"application/json",
      ...(options.body?{"Content-Type":"application/json"}:{})
    },
    body:options.body?JSON.stringify(options.body):undefined
  });

  const raw=await response.text();
  let data=null;
  try{ data=raw?JSON.parse(raw):{}; }
  catch(_){ data={raw:String(raw||"").slice(0,2500)}; }

  if(!response.ok){
    const err=new Error(
      data?.message ||
      data?.error?.message ||
      data?.outcome ||
      `Prodigi Sandbox returned HTTP ${response.status}.`
    );
    err.status=response.status;
    err.prodigi=data;
    throw err;
  }

  return data;
}

async function prodigiProductDetails(env,sku){
  return prodigiSandboxGet(env,`/products/${encodeURIComponent(sku)}`);
}

function prodigiChooseUsVariant(product){
  const variants=Array.isArray(product?.variants)?product.variants:[];
  const usVariants=variants.filter(v=>
    Array.isArray(v?.shipsTo) &&
    v.shipsTo.some(c=>String(c).toUpperCase()==="US")
  );

  if(!usVariants.length)return null;

  // Prefer the common photo-paper choices if Prodigi exposes a finish attribute.
  const preferences=["Lustre","Luster","Gloss","Glossy"];
  for(const pref of preferences){
    const hit=usVariants.find(v=>
      Object.values(v?.attributes||{}).some(val=>
        String(val).toLowerCase()===pref.toLowerCase()
      )
    );
    if(hit)return hit;
  }

  return usVariants[0];
}

function prodigiExpectedAssets(product){
  const printAreas=product?.printAreas && typeof product.printAreas==="object"
    ? product.printAreas : {};
  const required=Object.entries(printAreas)
    .filter(([,v])=>v?.required===true)
    .map(([name])=>({printArea:name}));

  // Standard photo products ordinarily require "default"; keep a safe fallback.
  return required.length?required:[{printArea:"default"}];
}

async function prodigiSandboxQuote(env,items){
  const payload={
    shippingMethod:"Budget",
    destinationCountryCode:"US",
    currencyCode:"USD",
    items:items.map(item=>({
      sku:String(item.sku),
      copies:Math.max(1,Math.floor(Number(item.copies)||1)),
      attributes:item.attributes||{},
      assets:Array.isArray(item.assets)&&item.assets.length
        ? item.assets
        :[{printArea:"default"}]
    }))
  };

  return prodigiSandboxGet(env,"/quotes",{
    method:"POST",
    body:payload
  });
}

function prodigiQuoteSummary(data){
  const quote=Array.isArray(data?.quotes)?data.quotes[0]:null;
  if(!quote){
    return {
      ok:false,
      outcome:data?.outcome||null,
      issue:"Prodigi returned no Budget quote.",
      issues:Array.isArray(data?.issues)?data.issues:[]
    };
  }

  const shipments=Array.isArray(quote.shipments)?quote.shipments:[];
  const itemCurrency=quote?.costSummary?.items?.currency||null;
  const shippingCurrency=quote?.costSummary?.shipping?.currency||null;

  return {
    ok:true,
    outcome:data?.outcome||null,
    shipping_method:quote.shipmentMethod||null,
    item_cost:{
      amount:quote?.costSummary?.items?.amount||null,
      currency:itemCurrency
    },
    shipping_cost:{
      amount:quote?.costSummary?.shipping?.amount||null,
      currency:shippingCurrency
    },
    currency_is_usd:itemCurrency==="USD" && shippingCurrency==="USD",
    all_us_fulfillment:shipments.length>0 &&
      shipments.every(s=>String(s?.fulfillmentLocation?.countryCode||"").toUpperCase()==="US"),
    shipments:shipments.map(s=>({
      fulfillment_country:s?.fulfillmentLocation?.countryCode||null,
      lab_code:s?.fulfillmentLocation?.labCode||null,
      carrier:s?.carrier?.name||null,
      service:s?.carrier?.service||null,
      shipping_cost:s?.cost?{
        amount:s.cost.amount||null,
        currency:s.cost.currency||null
      }:null
    })),
    issues:Array.isArray(data?.issues)?data.issues:[]
  };
}

function prodigiErrorDetails(e){
  const p=e?.prodigi;
  return {
    http_status:Number(e?.status)||500,
    error:String(e?.message||e||"Prodigi request failed.").slice(0,500),
    prodigi_outcome:p?.outcome||null,
    prodigi_issues:Array.isArray(p?.issues)?p.issues:[],
    prodigi_detail:
      p?.detail ||
      p?.details ||
      p?.errors ||
      p?.error ||
      null
  };
}


// ---------- PRODIGI SHIPPING FOR CHECKOUT ----------
const PRODIGI_PRINT_CATALOG=Object.freeze({
  print_4x6:{sku:"GLOBAL-PHO-4X6",finish:"lustre"},
  print_5x7:{sku:"GLOBAL-PHO-5X7",finish:"lustre"},
  print_8x10:{sku:"GLOBAL-PHO-8X10",finish:"lustre"}
});

function prodigiCheckoutItemsFromSnapshot(snapshot){
  const aggregate=new Map();

  for(const row of Array.isArray(snapshot)?snapshot:[]){
    if(!row?.requires_shipping)continue;

    const cfg=PRODIGI_PRINT_CATALOG[String(row.product_id||"")];
    if(!cfg){
      throw new Error(
        `Print size ${String(row.product_label||row.product_id||"unknown")} is not enabled for Prodigi fulfillment.`
      );
    }

    const key=`${cfg.sku}|${cfg.finish}`;
    const qty=Math.max(1,Math.floor(Number(row.quantity)||1));
    const existing=aggregate.get(key)||{
      sku:cfg.sku,
      copies:0,
      attributes:{finish:cfg.finish},
      assets:[{printArea:"default"}]
    };
    existing.copies+=qty;
    aggregate.set(key,existing);
  }

  return [...aggregate.values()];
}

function prodigiBudgetQuoteGuard(data){
  const quote=Array.isArray(data?.quotes)?data.quotes[0]:null;
  if(!quote)throw new Error("Prodigi did not return a Budget shipping quote.");

  if(String(quote.shipmentMethod||"").toLowerCase()!=="budget"){
    throw new Error("Prodigi Budget shipping is not available for this order.");
  }

  const itemCurrency=String(quote?.costSummary?.items?.currency||"").toUpperCase();
  const shippingCurrency=String(quote?.costSummary?.shipping?.currency||"").toUpperCase();
  if(itemCurrency!=="USD" || shippingCurrency!=="USD"){
    throw new Error("Prodigi did not return this order in USD.");
  }

  const shipments=Array.isArray(quote.shipments)?quote.shipments:[];
  if(!shipments.length){
    throw new Error("Prodigi did not return a fulfillment location.");
  }

  if(shipments.some(s=>
    String(s?.fulfillmentLocation?.countryCode||"").toUpperCase()!=="US"
  )){
    throw new Error("This basic print order was not allocated to U.S. fulfillment.");
  }

  const shippingAmount=Number(quote?.costSummary?.shipping?.amount);
  if(!Number.isFinite(shippingAmount) || shippingAmount<0){
    throw new Error("Prodigi returned an invalid shipping amount.");
  }

  return {
    shipping_cents:Math.round(shippingAmount*100),
    shipping_amount:shippingAmount.toFixed(2),
    currency:"USD",
    shipping_method:"Budget",
    shipments:shipments.map(s=>({
      fulfillment_country:s?.fulfillmentLocation?.countryCode||null,
      lab_code:s?.fulfillmentLocation?.labCode||null,
      carrier:s?.carrier?.name||null,
      service:s?.carrier?.service||null
    })),
    issues:Array.isArray(data?.issues)?data.issues:[]
  };
}

async function prodigiCheckoutBudgetQuote(env,snapshot){
  const items=prodigiCheckoutItemsFromSnapshot(snapshot);
  if(!items.length){
    return {
      shipping_cents:0,
      shipping_amount:"0.00",
      currency:"USD",
      shipping_method:null,
      shipments:[],
      issues:[]
    };
  }

  const data=await prodigiSandboxQuote(env,items);
  return prodigiBudgetQuoteGuard(data);
}

async function stripeRetrieveCheckoutSession(env,sessionId){
  const response=await fetch(
    `https://api.stripe.com/v1/checkout/sessions/${encodeURIComponent(sessionId)}`,
    {
      method:"GET",
      headers:{"Authorization":`Bearer ${env.STRIPE_SECRET_KEY}`}
    }
  );

  const raw=await response.text();
  let data={};
  try{data=raw?JSON.parse(raw):{};}catch(_){}

  if(!response.ok){
    const err=new Error(data?.error?.message||`Stripe session lookup failed (${response.status}).`);
    err.status=response.status;
    throw err;
  }
  return data;
}

async function stripeSetCalculatedShipping(env,sessionId,shippingDetails,shippingCents){
  const address=shippingDetails?.address||{};
  const body=new URLSearchParams();

  body.set("collected_information[shipping_details][name]",String(shippingDetails?.name||"").slice(0,200));
  body.set("collected_information[shipping_details][address][line1]",String(address.line1||"").slice(0,200));
  if(address.line2){
    body.set("collected_information[shipping_details][address][line2]",String(address.line2).slice(0,200));
  }
  body.set("collected_information[shipping_details][address][city]",String(address.city||"").slice(0,120));
  body.set("collected_information[shipping_details][address][state]",String(address.state||"").slice(0,120));
  body.set("collected_information[shipping_details][address][postal_code]",String(address.postal_code||"").slice(0,40));
  body.set("collected_information[shipping_details][address][country]","US");

  body.set("shipping_options[0][shipping_rate_data][display_name]","Budget Shipping");
  body.set("shipping_options[0][shipping_rate_data][type]","fixed_amount");
  body.set("shipping_options[0][shipping_rate_data][fixed_amount][amount]",String(Math.max(0,Math.floor(Number(shippingCents)||0))));
  body.set("shipping_options[0][shipping_rate_data][fixed_amount][currency]","usd");

  const response=await fetch(
    `https://api.stripe.com/v1/checkout/sessions/${encodeURIComponent(sessionId)}`,
    {
      method:"POST",
      headers:{
        "Authorization":`Bearer ${env.STRIPE_SECRET_KEY}`,
        "Content-Type":"application/x-www-form-urlencoded"
      },
      body
    }
  );

  const raw=await response.text();
  let data={};
  try{data=raw?JSON.parse(raw):{};}catch(_){}

  if(!response.ok){
    const err=new Error(data?.error?.message||`Stripe shipping update failed (${response.status}).`);
    err.status=response.status;
    throw err;
  }

  return data;
}

function validUsShippingDetails(details){
  const a=details?.address||{};
  return Boolean(
    String(details?.name||"").trim() &&
    String(a.line1||"").trim() &&
    String(a.city||"").trim() &&
    String(a.state||"").trim() &&
    String(a.postal_code||"").trim() &&
    String(a.country||"").toUpperCase()==="US"
  );
}


// ---------- PRODIGI SANDBOX ORDER FULFILLMENT ----------
const PRODIGI_ASSET_LINK_SECONDS=7*24*60*60;

function prodigiPrintConfig(productId){
  const map={
    print_4x6:{sku:"GLOBAL-PHO-4X6",finish:"lustre"},
    print_5x7:{sku:"GLOBAL-PHO-5X7",finish:"lustre"},
    print_8x10:{sku:"GLOBAL-PHO-8X10",finish:"lustre"}
  };
  return map[String(productId||"")]||null;
}

function prodigiBase64Url(bytes){
  let s="";
  for(const b of new Uint8Array(bytes))s+=String.fromCharCode(b);
  return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}

async function prodigiAssetSignature(env,orderItemId,expires){
  const secret=String(env.PRODIGI_API_KEY||"");
  if(!secret)throw new Error("Prodigi API key is not configured.");

  const key=await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {name:"HMAC",hash:"SHA-256"},
    false,
    ["sign"]
  );

  const digest=await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${orderItemId}.${expires}`)
  );
  return prodigiBase64Url(digest);
}

async function prodigiAssetUrl(env,orderItemId){
  const expires=Math.floor(Date.now()/1000)+PRODIGI_ASSET_LINK_SECONDS;
  const sig=await prodigiAssetSignature(env,orderItemId,expires);
  return `https://api.31action.com/api/prodigi/asset/${encodeURIComponent(orderItemId)}?expires=${expires}&sig=${encodeURIComponent(sig)}`;
}

async function prodigiCreateSandboxOrder(env,payload){
  const response=await fetch(`${PRODIGI_SANDBOX_BASE}/orders`,{
    method:"POST",
    headers:{
      "X-API-Key":String(env.PRODIGI_API_KEY),
      "Content-Type":"application/json",
      "Accept":"application/json"
    },
    body:JSON.stringify(payload)
  });

  const raw=await response.text();
  let data={};
  try{data=raw?JSON.parse(raw):{};}catch(_){
    data={raw:String(raw||"").slice(0,2500)};
  }

  if(!response.ok){
    const err=new Error(
      data?.statusText ||
      data?.message ||
      data?.outcome ||
      `Prodigi Sandbox order request failed (${response.status}).`
    );
    err.status=response.status;
    err.prodigi=data;
    throw err;
  }

  return data;
}

async function prodigiLogFulfillment(env,fulfillmentId,orderId,prodigiOrderId,eventType,status,detail){
  try{
    await env.DB.prepare(`
      INSERT INTO prodigi_fulfillment_log(
        id,fulfillment_id,order_id,prodigi_order_id,
        event_type,status,detail,created_at
      ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
    `).bind(
      `pflog-${crypto.randomUUID()}`,
      fulfillmentId,
      orderId,
      prodigiOrderId||null,
      eventType,
      status||null,
      detail?String(detail).slice(0,4000):null,
      new Date().toISOString()
    ).run();
  }catch(_){}
}

async function prodigiEnsureSandboxFulfillment(env,orderId){
  const order=await env.DB.prepare(`
    SELECT
      o.id,o.email,o.status,o.shipping_cents,
      od.customer_name,od.customer_phone,
      od.shipping_name,od.shipping_address1,od.shipping_address2,
      od.shipping_city,od.shipping_state,od.shipping_postal_code,
      od.shipping_country,od.fulfillment_status
    FROM orders o
    LEFT JOIN order_details od ON od.order_id=o.id
    WHERE o.id=?1
    LIMIT 1
  `).bind(orderId).first();

  if(!order)throw new Error("Paid order not found for Prodigi fulfillment.");
  if(order.status!=="paid")throw new Error("Prodigi fulfillment requires a paid order.");

  const printRows=await env.DB.prepare(`
    SELECT
      oi.id AS order_item_id,
      oi.photo_id,
      oi.product_id,
      oi.quantity,
      oid.filename,
      oid.requires_shipping,
      p.original_key
    FROM order_items oi
    JOIN order_item_details oid ON oid.order_item_id=oi.id
    JOIN photos p ON p.id=oi.photo_id
    WHERE oi.order_id=?1
      AND oid.requires_shipping=1
    ORDER BY oi.created_at,oi.id
  `).bind(orderId).all();

  const prints=printRows.results||[];
  if(!prints.length){
    return {needed:false,status:"not_applicable"};
  }

  if(String(order.shipping_country||"").toUpperCase()!=="US"){
    throw new Error("Initial Prodigi fulfillment is restricted to U.S. shipping addresses.");
  }

  if(!order.shipping_name || !order.shipping_address1 ||
     !order.shipping_city || !order.shipping_state || !order.shipping_postal_code){
    throw new Error("The paid print order is missing a complete U.S. shipping address.");
  }

  for(const row of prints){
    if(!prodigiPrintConfig(row.product_id)){
      throw new Error(`Unsupported Prodigi print product: ${row.product_id}`);
    }
    if(!row.original_key){
      throw new Error(`Original image is missing for ${row.filename||row.photo_id}.`);
    }
  }

  // Verify Budget / USD / U.S. allocation again immediately before submitting.
  const snapshot=prints.map(row=>({
    product_id:row.product_id,
    requires_shipping:true,
    quantity:row.quantity
  }));
  const freshQuote=await prodigiCheckoutBudgetQuote(env,snapshot);
  if(!freshQuote.shipments?.length ||
     freshQuote.shipments.some(x=>String(x.fulfillment_country||"").toUpperCase()!=="US")){
    throw new Error("Prodigi no longer reports U.S. fulfillment for this order.");
  }

  let fulfillment=await env.DB.prepare(`
    SELECT * FROM prodigi_fulfillments WHERE order_id=?1 LIMIT 1
  `).bind(orderId).first();

  if(fulfillment?.prodigi_order_id){
    return {
      needed:true,
      duplicate:true,
      fulfillment_id:fulfillment.id,
      prodigi_order_id:fulfillment.prodigi_order_id,
      status:fulfillment.status
    };
  }

  const now=new Date().toISOString();
  const fulfillmentId=fulfillment?.id||`prodigi-fulfillment-${crypto.randomUUID()}`;

  if(!fulfillment){
    await env.DB.prepare(`
      INSERT INTO prodigi_fulfillments(
        id,order_id,prodigi_order_id,environment,status,
        shipping_method,currency,fulfillment_country,lab_code,
        shipping_cents,submitted_at,last_checked_at,completed_at,
        last_error,created_at,updated_at
      ) VALUES(
        ?1,?2,NULL,'sandbox','preparing',
        'Budget','USD','US',?3,
        ?4,NULL,NULL,NULL,
        NULL,?5,?5
      )
    `).bind(
      fulfillmentId,
      orderId,
      freshQuote.shipments?.[0]?.lab_code||null,
      Number(order.shipping_cents)||freshQuote.shipping_cents||0,
      now
    ).run();
  }else{
    await env.DB.prepare(`
      UPDATE prodigi_fulfillments
      SET status='preparing',
          fulfillment_country='US',
          lab_code=?1,
          shipping_cents=?2,
          last_error=NULL,
          updated_at=?3
      WHERE id=?4
    `).bind(
      freshQuote.shipments?.[0]?.lab_code||null,
      Number(order.shipping_cents)||freshQuote.shipping_cents||0,
      now,
      fulfillmentId
    ).run();
  }

  const prodigiItems=[];
  for(const row of prints){
    const cfg=prodigiPrintConfig(row.product_id);
    const fiId=`prodigi-item-${crypto.randomUUID()}`;

    await env.DB.prepare(`
      INSERT INTO prodigi_fulfillment_items(
        id,fulfillment_id,order_item_id,photo_id,
        sku,finish,quantity,filename,original_key,
        status,prodigi_item_id,last_error,created_at,updated_at
      ) VALUES(
        ?1,?2,?3,?4,
        ?5,'lustre',?6,?7,?8,
        'preparing',NULL,NULL,?9,?9
      )
      ON CONFLICT(order_item_id) DO UPDATE SET
        sku=excluded.sku,
        finish=excluded.finish,
        quantity=excluded.quantity,
        filename=excluded.filename,
        original_key=excluded.original_key,
        status='preparing',
        last_error=NULL,
        updated_at=excluded.updated_at
    `).bind(
      fiId,fulfillmentId,row.order_item_id,row.photo_id,
      cfg.sku,Math.max(1,Number(row.quantity)||1),
      row.filename||null,row.original_key,now
    ).run();

    prodigiItems.push({
      merchantReference:row.order_item_id,
      sku:cfg.sku,
      copies:Math.max(1,Number(row.quantity)||1),
      sizing:"fillPrintArea",
      attributes:{finish:cfg.finish},
      assets:[{
        printArea:"default",
        url:await prodigiAssetUrl(env,row.order_item_id)
      }]
    });
  }

  const payload={
    merchantReference:orderId,
    idempotencyKey:`31action-${orderId}`,
    shippingMethod:"Budget",
    recipient:{
      name:String(order.shipping_name),
      email:String(order.email||"")||undefined,
      phoneNumber:String(order.customer_phone||"")||undefined,
      address:{
        line1:String(order.shipping_address1),
        ...(order.shipping_address2?{line2:String(order.shipping_address2)}:{}),
        postalOrZipCode:String(order.shipping_postal_code),
        countryCode:"US",
        townOrCity:String(order.shipping_city),
        stateOrCounty:String(order.shipping_state)
      }
    },
    items:prodigiItems,
    metadata:{
      site:"31action.com",
      environment:"sandbox",
      orderId:String(orderId)
    }
  };

  await prodigiLogFulfillment(
    env,fulfillmentId,orderId,null,
    "submit_attempt","preparing",
    `Submitting ${prodigiItems.length} print item(s) to Prodigi Sandbox with Budget shipping.`
  );

  try{
    const response=await prodigiCreateSandboxOrder(env,payload);
    const po=response?.order||{};
    const prodigiOrderId=String(po.id||"").trim();
    if(!prodigiOrderId){
      throw new Error(`Prodigi returned ${response?.outcome||"a response"} without an order ID.`);
    }

    const stage=String(po?.status?.stage||response?.outcome||"submitted");
    const submittedAt=new Date().toISOString();
    const shipments=Array.isArray(po.shipments)?po.shipments:[];
    const firstShipment=shipments[0]||null;
    const fulfillmentCountry=
      firstShipment?.fulfillmentLocation?.countryCode||
      freshQuote.shipments?.[0]?.fulfillment_country||
      "US";
    const labCode=
      firstShipment?.fulfillmentLocation?.labCode||
      freshQuote.shipments?.[0]?.lab_code||
      null;

    await env.DB.prepare(`
      UPDATE prodigi_fulfillments
      SET prodigi_order_id=?1,
          status=?2,
          fulfillment_country=?3,
          lab_code=?4,
          submitted_at=COALESCE(submitted_at,?5),
          last_checked_at=?5,
          last_error=NULL,
          updated_at=?5
      WHERE id=?6
    `).bind(
      prodigiOrderId,stage,fulfillmentCountry,labCode,
      submittedAt,fulfillmentId
    ).run();

    const returnedItems=Array.isArray(po.items)?po.items:[];
    for(const ri of returnedItems){
      const merchantRef=String(ri?.merchantReference||"");
      if(!merchantRef)continue;
      await env.DB.prepare(`
        UPDATE prodigi_fulfillment_items
        SET status=?1,
            prodigi_item_id=?2,
            last_error=NULL,
            updated_at=?3
        WHERE order_item_id=?4
      `).bind(
        String(ri?.status||"submitted"),
        ri?.id||null,
        submittedAt,
        merchantRef
      ).run();
    }

    await env.DB.prepare(`
      UPDATE order_details
      SET fulfillment_status='submitted',updated_at=?1
      WHERE order_id=?2
    `).bind(submittedAt,orderId).run();

    await prodigiLogFulfillment(
      env,fulfillmentId,orderId,prodigiOrderId,
      "submitted",stage,
      `Prodigi outcome: ${String(response?.outcome||"unknown")}`
    );

    return {
      needed:true,
      duplicate:false,
      fulfillment_id:fulfillmentId,
      prodigi_order_id:prodigiOrderId,
      status:stage,
      outcome:response?.outcome||null
    };

  }catch(e){
    const failedAt=new Date().toISOString();
    const detail=String(
      e?.prodigi?.statusText ||
      e?.prodigi?.message ||
      e?.message ||
      e ||
      "Prodigi submission failed."
    ).slice(0,3000);

    await env.DB.prepare(`
      UPDATE prodigi_fulfillments
      SET status='failed',last_error=?1,updated_at=?2
      WHERE id=?3
    `).bind(detail,failedAt,fulfillmentId).run();

    await env.DB.prepare(`
      UPDATE prodigi_fulfillment_items
      SET status='failed',last_error=?1,updated_at=?2
      WHERE fulfillment_id=?3
    `).bind(detail,failedAt,fulfillmentId).run();

    await env.DB.prepare(`
      UPDATE order_details
      SET fulfillment_status='failed',updated_at=?1
      WHERE order_id=?2
    `).bind(failedAt,orderId).run();

    await prodigiLogFulfillment(
      env,fulfillmentId,orderId,null,
      "submission_failed","failed",detail
    );

    throw e;
  }
}


function safeJsonParse(value,fallback=null){
  if(value===null || value===undefined || value==="")return fallback;
  if(typeof value==="object")return value;
  try{return JSON.parse(String(value));}
  catch(_){return fallback;}
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if(request.method==="OPTIONS") return new Response(null,{status:204,headers:cors(request)});

    if(url.pathname==="/api/health" && request.method==="GET"){
      return json(request,{ok:true,bindings:{originals:Boolean(env.ORIGINALS),previews:Boolean(env.PREVIEWS),database:Boolean(env.DB)}});
    }


    // ---------- TEMPORARY SIGNED PRODIGI ASSET ----------
    // Allows Prodigi to download only a paid print's original file.
    const prodigiAssetMatch=url.pathname.match(/^\/api\/prodigi\/asset\/([^/]+)$/);
    if(prodigiAssetMatch && request.method==="GET"){
      try{
        const orderItemId=decodeURIComponent(prodigiAssetMatch[1]||"").trim();
        const expires=Number(url.searchParams.get("expires"));
        const sig=String(url.searchParams.get("sig")||"");

        if(!orderItemId || !Number.isFinite(expires) || !sig){
          return text(request,"Invalid asset link.",400);
        }

        const nowSec=Math.floor(Date.now()/1000);
        if(expires<nowSec || expires>nowSec+PRODIGI_ASSET_LINK_SECONDS+300){
          return text(request,"Asset link expired.",410);
        }

        const expected=await prodigiAssetSignature(env,orderItemId,expires);
        if(!secureEqual(sig,expected)){
          return text(request,"Invalid asset link.",403);
        }

        const row=await env.DB.prepare(`
          SELECT
            p.original_key,
            p.filename,
            o.status AS order_status,
            oid.requires_shipping
          FROM order_items oi
          JOIN orders o ON o.id=oi.order_id
          JOIN order_item_details oid ON oid.order_item_id=oi.id
          JOIN photos p ON p.id=oi.photo_id
          WHERE oi.id=?1
          LIMIT 1
        `).bind(orderItemId).first();

        if(!row || row.order_status!=="paid" || !Number(row.requires_shipping)){
          return text(request,"Asset not available.",404);
        }

        const obj=await env.ORIGINALS.get(String(row.original_key||""));
        if(!obj)return text(request,"Original asset not found.",404);

        const headers=new Headers();
        headers.set("Content-Type",obj.httpMetadata?.contentType||"image/jpeg");
        headers.set("Cache-Control","private, no-store");
        headers.set("X-Content-Type-Options","nosniff");
        return new Response(obj.body,{status:200,headers});
      }catch(e){
        console.error("Prodigi asset error",e);
        return text(request,"Asset unavailable.",500);
      }
    }


    // ---------- PRODIGI -> STRIPE DYNAMIC SHIPPING ----------
    // Called by Stripe Embedded Checkout after a customer completes a U.S. address.
    // It quotes Prodigi Budget shipping and refuses non-US fulfillment.
    if(url.pathname==="/api/checkout/shipping-quote" && request.method==="POST"){
      try{
        if(!env.STRIPE_SECRET_KEY){
          return json(request,{type:"error",message:"Stripe is not configured."},503);
        }
        if(!env.PRODIGI_API_KEY){
          return json(request,{type:"error",message:"Prodigi is not configured."},503);
        }

        const b=await bodyJson(request)||{};
        const sessionId=String(b.checkout_session_id||"").trim();
        const shippingDetails=b.shipping_details||null;

        if(!/^cs_(test_|live_)/.test(sessionId)){
          return json(request,{type:"error",message:"Invalid checkout session."},400);
        }

        if(!validUsShippingDetails(shippingDetails)){
          return json(request,{
            type:"error",
            message:"Please enter a complete United States shipping address."
          },400);
        }

        const stripeSession=await stripeRetrieveCheckoutSession(env,sessionId);
        if(stripeSession.status!=="open"){
          return json(request,{
            type:"error",
            message:"This checkout session is no longer open."
          },409);
        }

        const draft=await env.DB.prepare(`
          SELECT id,cart_json,requires_shipping
          FROM checkout_drafts
          WHERE stripe_session_id=?1
          LIMIT 1
        `).bind(sessionId).first();

        if(!draft){
          return json(request,{
            type:"error",
            message:"We could not find the checkout cart for this payment."
          },404);
        }

        if(!Number(draft.requires_shipping)){
          return json(request,{
            type:"error",
            message:"This checkout does not require shipping."
          },400);
        }

        let snapshot=[];
        try{snapshot=JSON.parse(String(draft.cart_json||"[]"));}catch(_){}

        const quote=await prodigiCheckoutBudgetQuote(env,snapshot);

        const updated=await stripeSetCalculatedShipping(
          env,
          sessionId,
          shippingDetails,
          quote.shipping_cents
        );

        try{
          const base=Number(updated.amount_subtotal)||0;
          const total=Number(updated.amount_total)||(base+quote.shipping_cents);
          await env.DB.prepare(`
            UPDATE checkout_drafts
            SET amount_subtotal_cents=?1,
                amount_total_cents=?2,
                updated_at=?3
            WHERE id=?4
          `).bind(base,total,new Date().toISOString(),draft.id).run();
        }catch(_){}

        return json(request,{
          type:"object",
          value:{succeeded:true},
          shipping:{
            method:"Budget",
            amount_cents:quote.shipping_cents,
            amount:quote.shipping_amount,
            currency:"USD",
            us_fulfillment:true,
            shipments:quote.shipments
          }
        },200);

      }catch(e){
        console.error("Calculated shipping error",e);
        return json(request,{
          type:"error",
          message:String(e?.message||e||"Shipping could not be calculated.").slice(0,500)
        },Number(e?.status)>=400&&Number(e?.status)<600?Number(e.status):500);
      }
    }


    // ---------- PRODIGI SANDBOX PRODUCT + QUOTE TEST ----------
    // Diagnostic only. Reads product data and creates quotes; never creates orders.
    if(url.pathname==="/api/prodigi/quote-test" && request.method==="GET"){
      if(!env.PRODIGI_API_KEY){
        return json(request,{
          ok:false,
          environment:"sandbox",
          api_key_present:false,
          error:"PRODIGI_API_KEY is not configured."
        },503);
      }

      const products=[];
      const quoteItems=[];
      let authFailure=null;

      for(const [size,sku] of Object.entries(PRODIGI_INITIAL_PRINTS)){
        try{
          const productResponse=await prodigiProductDetails(env,sku);
          const product=productResponse?.product||productResponse;
          const variant=prodigiChooseUsVariant(product);
          const assets=prodigiExpectedAssets(product);

          const productResult={
            size,
            sku,
            ok:true,
            outcome:productResponse?.outcome||null,
            description:product?.description||null,
            dimensions:product?.productDimensions||null,
            available_attributes:product?.attributes||{},
            required_print_areas:assets.map(a=>a.printArea),
            variant_count:Array.isArray(product?.variants)?product.variants.length:0,
            has_us_variant:Boolean(variant),
            chosen_attributes:variant?.attributes||null
          };

          products.push(productResult);

          if(variant){
            quoteItems.push({
              size,
              sku,
              copies:1,
              attributes:variant.attributes||{},
              assets
            });
          }

        }catch(e){
          const d=prodigiErrorDetails(e);
          products.push({size,sku,ok:false,...d});
          if(d.http_status===401){
            authFailure="The configured key was not accepted by Prodigi Sandbox.";
          }
        }
      }

      const individual=[];
      for(const item of quoteItems){
        try{
          const data=await prodigiSandboxQuote(env,[item]);
          individual.push({
            size:item.size,
            sku:item.sku,
            chosen_attributes:item.attributes,
            ...prodigiQuoteSummary(data)
          });
        }catch(e){
          individual.push({
            size:item.size,
            sku:item.sku,
            chosen_attributes:item.attributes,
            ok:false,
            ...prodigiErrorDetails(e)
          });
        }
      }

      let combined=null;
      if(quoteItems.length===3){
        try{
          const data=await prodigiSandboxQuote(env,quoteItems);
          combined=prodigiQuoteSummary(data);
        }catch(e){
          combined={ok:false,...prodigiErrorDetails(e)};
        }
      }else{
        combined={
          ok:false,
          error:"Combined quote skipped because one or more SKUs has no U.S.-eligible variant in Sandbox."
        };
      }

      const allPassed=
        products.length===3 &&
        products.every(p=>p.ok&&p.has_us_variant) &&
        individual.length===3 &&
        individual.every(t=>
          t.ok===true &&
          String(t.shipping_method||"").toLowerCase()==="budget" &&
          t.currency_is_usd===true &&
          t.all_us_fulfillment===true
        ) &&
        combined?.ok===true &&
        String(combined.shipping_method||"").toLowerCase()==="budget" &&
        combined.currency_is_usd===true &&
        combined.all_us_fulfillment===true;

      return json(request,{
        ok:allPassed,
        environment:"sandbox",
        api_key_present:true,
        creates_orders:false,
        requested:{
          destination_country:"US",
          currency:"USD",
          shipping_method:"Budget",
          allowed_sizes:Object.keys(PRODIGI_INITIAL_PRINTS)
        },
        authentication_issue:authFailure,
        products,
        individual,
        combined
      },200);
    }

    // ---------- STRIPE EMBEDDED CHECKOUT SESSION ----------
    if(url.pathname==="/api/checkout/embedded-session" && request.method==="POST"){
      let draftId=null;
      try{
        if(!env.STRIPE_SECRET_KEY){
          return json(request,{
            ok:false,
            error:"Stripe is not configured yet.",
            code:"STRIPE_NOT_CONFIGURED"
          },503);
        }
        if(!env.STRIPE_PUBLISHABLE_KEY){
          return json(request,{
            ok:false,
            error:"Stripe publishable key is not configured yet.",
            code:"STRIPE_PUBLISHABLE_KEY_NOT_CONFIGURED"
          },503);
        }

        const b=await bodyJson(request)||{};
        const customer=b.customer||{};
        const email=String(customer.email||"").trim().toLowerCase().slice(0,254);

        if(!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){
          return json(request,{ok:false,error:"Enter a valid email address."},400);
        }

        const priced=stripeCheckoutPricingItems(b.items);
        const orderSnapshot=await stripeBuildOrderSnapshot(env,b.items);

        if(priced.collectShipping!==orderSnapshot.requiresShipping){
          throw new Error("Cart shipping validation failed.");
        }

        const clientReferenceId=String(b.client_reference_id||`31A-${Date.now()}`)
          .replace(/[^a-zA-Z0-9._:-]/g,"")
          .slice(0,200);

        draftId=`draft-${crypto.randomUUID()}`;
        const now=new Date().toISOString();
        const customerName=[customer.firstName,customer.lastName]
          .map(x=>String(x||"").trim()).filter(Boolean).join(" ").slice(0,200)||null;
        const customerPhone=String(customer.phone||"").trim().slice(0,80)||null;
        const notes=String(b.notes||"").trim().slice(0,1000)||null;

        await env.DB.prepare(`
          INSERT INTO checkout_drafts(
            id,stripe_session_id,client_reference_id,
            customer_email,customer_name,customer_phone,
            cart_json,notes,requires_shipping,
            amount_subtotal_cents,amount_total_cents,currency,payment_status,
            stripe_payment_intent_id,stripe_customer_id,
            created_at,updated_at,paid_at
          ) VALUES(
            ?1,NULL,?2,
            ?3,?4,?5,
            ?6,?7,?8,
            ?9,?10,'usd','created',
            NULL,NULL,
            ?11,?11,NULL
          )
        `).bind(
          draftId,clientReferenceId,
          email,customerName,customerPhone,
          JSON.stringify(orderSnapshot.snapshot),notes,orderSnapshot.requiresShipping?1:0,
          orderSnapshot.chargedItemCents,orderSnapshot.chargedItemCents,now
        ).run();

        const session=await stripeCreateEmbeddedCheckoutSession(env,{
          customerEmail:email,
          collectShipping:priced.collectShipping,
          clientReferenceId,
          itemCount:priced.itemCount,
          lineItems:priced.lineItems
        });

        await env.DB.prepare(`
          UPDATE checkout_drafts
          SET stripe_session_id=?1,payment_status='open',
              amount_subtotal_cents=?2,amount_total_cents=?2,updated_at=?3
          WHERE id=?4
        `).bind(
          session.id,
          Number(session.amount_subtotal)||orderSnapshot.chargedItemCents,
          new Date().toISOString(),
          draftId
        ).run();

        return json(request,{
          ok:true,
          test_mode:Boolean(String(env.STRIPE_SECRET_KEY).startsWith("sk_test_")),
          publishable_key:String(env.STRIPE_PUBLISHABLE_KEY),
          session_id:session.id,
          client_secret:session.client_secret,
          client_reference_id:clientReferenceId
        },201);

      }catch(e){
        console.error("Stripe Embedded Checkout session error",e);
        if(draftId){
          try{
            await env.DB.prepare(`
              UPDATE checkout_drafts
              SET payment_status='failed',updated_at=?1
              WHERE id=?2
            `).bind(new Date().toISOString(),draftId).run();
          }catch(_){}
        }
        return json(request,{
          ok:false,
          error:String(e?.message||e||"Stripe Embedded Checkout could not be created.").slice(0,800),
          code:e?.code||e?.stripeCode||"STRIPE_EMBEDDED_CHECKOUT_ERROR"
        },Number(e?.status)>=400&&Number(e?.status)<600?Number(e.status):500);
      }
    }


    // ---------- STRIPE CHECKOUT SESSION ----------
    if(url.pathname==="/api/checkout/session" && request.method==="POST"){
      let draftId=null;
      try{
        if(!env.STRIPE_SECRET_KEY){
          return json(request,{
            ok:false,
            error:"Stripe is not configured yet.",
            code:"STRIPE_NOT_CONFIGURED"
          },503);
        }

        const b=await bodyJson(request)||{};
        const customer=b.customer||{};
        const email=String(customer.email||"").trim().toLowerCase().slice(0,254);

        if(!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){
          return json(request,{ok:false,error:"Enter a valid email address."},400);
        }

        const priced=stripeCheckoutPricingItems(b.items);
        const orderSnapshot=await stripeBuildOrderSnapshot(env,b.items);

        if(priced.collectShipping!==orderSnapshot.requiresShipping){
          throw new Error("Cart shipping validation failed.");
        }

        const clientReferenceId=String(b.client_reference_id||`31A-${Date.now()}`)
          .replace(/[^a-zA-Z0-9._:-]/g,"")
          .slice(0,200);

        draftId=`draft-${crypto.randomUUID()}`;
        const now=new Date().toISOString();
        const customerName=[customer.firstName,customer.lastName]
          .map(x=>String(x||"").trim()).filter(Boolean).join(" ").slice(0,200)||null;
        const customerPhone=String(customer.phone||"").trim().slice(0,80)||null;
        const notes=String(b.notes||"").trim().slice(0,1000)||null;

        await env.DB.prepare(`
          INSERT INTO checkout_drafts(
            id,stripe_session_id,client_reference_id,
            customer_email,customer_name,customer_phone,
            cart_json,notes,requires_shipping,
            amount_subtotal_cents,amount_total_cents,currency,payment_status,
            stripe_payment_intent_id,stripe_customer_id,
            created_at,updated_at,paid_at
          ) VALUES(
            ?1,NULL,?2,
            ?3,?4,?5,
            ?6,?7,?8,
            ?9,?10,'usd','created',
            NULL,NULL,
            ?11,?11,NULL
          )
        `).bind(
          draftId,clientReferenceId,
          email,customerName,customerPhone,
          JSON.stringify(orderSnapshot.snapshot),notes,orderSnapshot.requiresShipping?1:0,
          orderSnapshot.chargedItemCents,orderSnapshot.chargedItemCents,now
        ).run();

        const session=await stripeCreateCheckoutSession(env,{
          customerEmail:email,
          collectShipping:priced.collectShipping,
          clientReferenceId,
          itemCount:priced.itemCount,
          lineItems:priced.lineItems
        });

        await env.DB.prepare(`
          UPDATE checkout_drafts
          SET stripe_session_id=?1,payment_status='open',
              amount_subtotal_cents=?2,amount_total_cents=?2,updated_at=?3
          WHERE id=?4
        `).bind(
          session.id,
          Number(session.amount_subtotal)||orderSnapshot.chargedItemCents,
          new Date().toISOString(),
          draftId
        ).run();

        return json(request,{
          ok:true,
          test_mode:Boolean(String(env.STRIPE_SECRET_KEY).startsWith("sk_test_")),
          session_id:session.id,
          checkout_url:session.url,
          client_reference_id:clientReferenceId
        },201);

      }catch(e){
        console.error("Stripe checkout session error",e);
        if(draftId){
          try{
            await env.DB.prepare(`
              UPDATE checkout_drafts
              SET payment_status='failed',updated_at=?1
              WHERE id=?2
            `).bind(new Date().toISOString(),draftId).run();
          }catch(_){}
        }
        return json(request,{
          ok:false,
          error:String(e?.message||e||"Stripe Checkout could not be created.").slice(0,800),
          code:e?.code||e?.stripeCode||"STRIPE_CHECKOUT_ERROR"
        },Number(e?.status)>=400&&Number(e?.status)<600?Number(e.status):500);
      }
    }

    // ---------- SECURE DIGITAL DOWNLOAD ----------
    const downloadMatch=url.pathname.match(/^\/api\/download\/([^/]+)\/([^/]+)$/);
    if(downloadMatch && request.method==="GET"){
      const entitlementId=decodeURIComponent(downloadMatch[1]||"").trim();
      const token=decodeURIComponent(downloadMatch[2]||"").trim();

      if(!entitlementId||!token){
        return text(request,"Invalid download link.",400);
      }

      const tokenHash=await sha256B64(token);
      const row=await env.DB.prepare(`
        SELECT
          dde.id,dde.order_id,dde.order_item_id,dde.photo_id,
          dde.token_hash,dde.status,dde.expires_at,
          dde.download_count,dde.max_downloads,
          p.original_key,p.filename
        FROM digital_download_entitlements dde
        JOIN orders o ON o.id=dde.order_id
        JOIN order_items oi ON oi.id=dde.order_item_id
        JOIN photos p ON p.id=dde.photo_id
        WHERE dde.id=?1
          AND o.status='paid'
          AND oi.product_id='digital'
        LIMIT 1
      `).bind(entitlementId).first();

      if(!row || !secureEqual(String(row.token_hash||""),tokenHash)){
        return text(request,"This download link is invalid.",404);
      }

      if(row.status!=="active"){
        return text(request,"This download link is no longer active.",410);
      }

      if(!row.expires_at || new Date(row.expires_at).getTime()<=Date.now()){
        try{
          await env.DB.prepare(`
            UPDATE digital_download_entitlements
            SET status='expired',updated_at=?1
            WHERE id=?2
          `).bind(new Date().toISOString(),entitlementId).run();
        }catch(_){}
        return text(request,"This download link has expired.",410);
      }

      const maxDownloads=row.max_downloads===null||row.max_downloads===undefined
        ?null:Number(row.max_downloads);
      if(maxDownloads!==null && Number(row.download_count)>=maxDownloads){
        return text(request,"This download limit has been reached.",410);
      }

      const obj=await env.ORIGINALS.get(String(row.original_key));
      if(!obj){
        return text(request,"The original photo could not be found.",404);
      }

      const now=new Date().toISOString();
      const eventId=`download-event-${crypto.randomUUID()}`;

      // Log download without storing the raw IP address.
      let ipHash=null;
      try{
        const ip=request.headers.get("CF-Connecting-IP")||"";
        if(ip)ipHash=await sha256B64(ip);
      }catch(_){}

      await env.DB.batch([
        env.DB.prepare(`
          UPDATE digital_download_entitlements
          SET download_count=download_count+1,
              last_download_at=?1,
              updated_at=?1
          WHERE id=?2
        `).bind(now,entitlementId),
        env.DB.prepare(`
          INSERT INTO digital_download_events(
            id,entitlement_id,order_id,order_item_id,photo_id,
            downloaded_at,ip_hash,user_agent
          ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
        `).bind(
          eventId,
          entitlementId,
          row.order_id,
          row.order_item_id,
          row.photo_id,
          now,
          ipHash,
          String(request.headers.get("User-Agent")||"").slice(0,500)||null
        )
      ]);

      const headers=new Headers();
      if(obj.httpMetadata?.contentType){
        headers.set("Content-Type",obj.httpMetadata.contentType);
      }else{
        headers.set("Content-Type","application/octet-stream");
      }
      headers.set(
        "Content-Disposition",
        `attachment; filename="${safeDownloadFilename(row.filename)}"`
      );
      headers.set("Cache-Control","private, no-store");
      headers.set("X-Content-Type-Options","nosniff");

      return new Response(obj.body,{status:200,headers});
    }


    // ---------- PUBLIC PAID ORDER CONFIRMATION ----------
    const confirmationMatch=url.pathname.match(/^\/api\/checkout\/confirmation\/([^/]+)$/);
    if(confirmationMatch && request.method==="GET"){
      const sessionId=decodeURIComponent(confirmationMatch[1]||"").trim();

      if(!sessionId || !/^cs_(?:test_|live_)?[A-Za-z0-9_]+$/.test(sessionId)){
        return json(request,{ok:false,error:"Invalid checkout session."},400);
      }

      const order=await env.DB.prepare(`
        SELECT
          o.id,o.status,o.subtotal_cents,o.discount_cents,
          o.shipping_cents,o.tax_cents,o.total_cents,o.created_at,
          od.fulfillment_status,od.paid_at
        FROM orders o
        LEFT JOIN order_details od ON od.order_id=o.id
        WHERE o.stripe_session_id=?1
        LIMIT 1
      `).bind(sessionId).first();

      if(!order){
        const draft=await env.DB.prepare(`
          SELECT payment_status,updated_at
          FROM checkout_drafts
          WHERE stripe_session_id=?1
          LIMIT 1
        `).bind(sessionId).first();

        if(draft){
          return json(request,{
            ok:true,
            ready:false,
            payment_status:draft.payment_status||"processing",
            message:"Payment confirmation is still being processed."
          },202);
        }

        return json(request,{ok:false,error:"Order not found."},404);
      }

      const itemRows=await env.DB.prepare(`
        SELECT
          oi.id,oi.photo_id,oi.product_id,oi.quantity,oi.unit_cents,
          oid.gallery_id,oid.filename,oid.product_label,oid.requires_shipping
        FROM order_items oi
        LEFT JOIN order_item_details oid ON oid.order_item_id=oi.id
        WHERE oi.order_id=?1
        ORDER BY oi.created_at,oi.id
      `).bind(order.id).all();

      const items=(itemRows.results||[]).map(row=>({
        photo_id:row.photo_id||null,
        gallery_id:row.gallery_id||null,
        filename:row.filename||null,
        product_id:row.product_id||null,
        product_label:row.product_label||row.product_id||"Photo",
        quantity:Number(row.quantity)||1,
        unit_cents:Number(row.unit_cents)||0,
        requires_shipping:Boolean(row.requires_shipping)
      }));

      const digitalDownloads=await mintDigitalDownloadLinks(env,order.id);

      return json(request,{
        ok:true,
        ready:true,
        order:{
          id:order.id,
          status:order.status,
          fulfillment_status:order.fulfillment_status||"not_started",
          subtotal_cents:Number(order.subtotal_cents)||0,
          discount_cents:Number(order.discount_cents)||0,
          shipping_cents:Number(order.shipping_cents)||0,
          tax_cents:Number(order.tax_cents)||0,
          total_cents:Number(order.total_cents)||0,
          created_at:order.created_at||null,
          paid_at:order.paid_at||null,
          items,
          digital_downloads:digitalDownloads
        }
      });
    }


    // ---------- STRIPE WEBHOOK SAFE DIAGNOSTIC ----------
    if(url.pathname==="/api/stripe/webhook-diagnostic" && request.method==="GET"){
      const raw=String(env.STRIPE_WEBHOOK_SECRET||"");
      const trimmed=raw.trim();
      return json(request,{
        ok:true,
        webhook_secret:{
          present:Boolean(raw),
          looks_like_whsec:trimmed.startsWith("whsec_"),
          length:trimmed.length,
          has_leading_or_trailing_whitespace:raw!==trimmed
        },
        stripe_secret_key_present:Boolean(env.STRIPE_SECRET_KEY),
        database_present:Boolean(env.DB)
      });
    }

    // ---------- STRIPE WEBHOOK ----------
    if(url.pathname==="/api/stripe/webhook" && request.method==="POST"){
      const rawBuffer=await request.arrayBuffer();
      const rawBytes=new Uint8Array(rawBuffer);
      let event=null;

      try{
        await stripeVerifyWebhookSignature(
          rawBytes,
          request.headers.get("Stripe-Signature"),
          env.STRIPE_WEBHOOK_SECRET
        );
        const rawBody=new TextDecoder("utf-8",{fatal:true}).decode(rawBytes);
        event=JSON.parse(rawBody);
      }catch(e){
        console.error("Stripe webhook verification error",e);
        return json(request,{
          ok:false,
          error:String(e?.message||e||"Invalid Stripe webhook.").slice(0,500)
        },400);
      }

      const session=event?.data?.object||{};
      const sessionId=String(session?.id||"")||null;

      try{
        if(event.type!=="checkout.session.completed"){
          await stripeMarkWebhookEvent(env,event,"ignored",null,sessionId);
          return json(request,{ok:true,ignored:true,type:event.type});
        }

        const prior=await env.DB.prepare(`
          SELECT processing_status FROM stripe_webhook_events WHERE event_id=?1
        `).bind(String(event.id)).first();

        if(prior?.processing_status==="processed"){
          return json(request,{ok:true,duplicate:true,event_id:event.id});
        }

        await stripeMarkWebhookEvent(env,event,"received",null,sessionId);

        if(session.payment_status!=="paid"){
          await stripeMarkWebhookEvent(
            env,event,"ignored",
            `checkout.session.completed payment_status=${String(session.payment_status||"unknown")}`,
            sessionId
          );
          return json(request,{ok:true,ignored:true,payment_status:session.payment_status||null});
        }

        const result=await stripeCreatePaidOrderFromSession(env,event,session);
        const prodigi=await prodigiEnsureSandboxFulfillment(env,result.orderId);
        await stripeMarkWebhookEvent(env,event,"processed",null,sessionId);

        return json(request,{
          ok:true,
          event_id:event.id,
          order_id:result.orderId,
          duplicate_order:Boolean(result.duplicate),
          prodigi
        });

      }catch(e){
        console.error("Stripe webhook processing error",e);
        try{
          await stripeMarkWebhookEvent(
            env,event,"failed",
            String(e?.message||e||"Unknown webhook processing error").slice(0,800),
            sessionId
          );
        }catch(_){}

        // Return 500 so Stripe retries the event.
        return json(request,{
          ok:false,
          error:String(e?.message||e||"Stripe webhook processing failed.").slice(0,800)
        },500);
      }
    }

    // ---------- PLAYER ACCOUNTS / AUTH ----------
    if(url.pathname==="/api/auth/register" && request.method==="POST"){
      const b=await bodyJson(request);
      const email=String(b?.email||"").trim().toLowerCase();
      const password=String(b?.password||"");
      const displayName=String(b?.display_name||b?.player_name||"").trim().slice(0,200);
      const roles=normalizedRoles(b?.roles||b?.role);
      const sports=normalizedSports(b?.sports||b?.sport);
      const customSport=String(b?.custom_sport||"").trim().slice(0,120);
      const team=String(b?.team||"").trim().slice(0,200);
      const jerseys=normalizedJerseys(b?.jersey_numbers);
      const isPlayer=roles.includes("player");

      if(!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return json(request,{ok:false,error:"A valid email address is required"},400);
      if(password.length<10)
        return json(request,{ok:false,error:"Password must be at least 10 characters"},400);
      if(!displayName)
        return json(request,{ok:false,error:"Name is required"},400);

      const existing=await env.DB.prepare(`SELECT id FROM user_accounts WHERE email=?1`).bind(email).first();
      if(existing)return json(request,{ok:false,error:"An account with that email already exists"},409);

      const saltBytes=new Uint8Array(16); crypto.getRandomValues(saltBytes);
      const salt=bytesToB64(saltBytes);
      const hash=await passwordHash(password,salt,PASSWORD_ITERATIONS);
      const now=new Date().toISOString();
      const userId=`user-${crypto.randomUUID()}`;
      const accountStatus=isPlayer?"pending":"verified";

      await env.DB.prepare(`
        INSERT INTO user_accounts(id,email,display_name,account_status,created_at,updated_at)
        VALUES(?1,?2,?3,?4,?5,?5)
      `).bind(userId,email,displayName,accountStatus,now).run();

      await env.DB.prepare(`
        INSERT INTO auth_credentials(user_id,password_salt,password_hash,password_iterations,created_at,updated_at)
        VALUES(?1,?2,?3,?4,?5,?5)
      `).bind(userId,salt,hash,PASSWORD_ITERATIONS,now).run();

      for(const role of roles){
        await env.DB.prepare(`
          INSERT OR IGNORE INTO user_account_roles(user_id,role,created_at,created_by)
          VALUES(?1,?2,?3,'self-registration')
        `).bind(userId,role,now).run();
      }

      for(const sport of sports){
        const custom=sport==="other"?customSport||null:null;
        await env.DB.prepare(`
          INSERT OR IGNORE INTO account_sport_preferences(id,user_id,sport,custom_sport,created_at)
          VALUES(?1,?2,?3,?4,?5)
        `).bind(`sportpref-${crypto.randomUUID()}`,userId,sport,custom,now).run();
      }

      let athleteRequest=null;
      if(isPlayer){
        const primarySport=sports.length
          ? (sports[0]==="other"?(customSport||"Other"):sports[0])
          : null;
        const requestId=`athreq-${crypto.randomUUID()}`;
        await env.DB.prepare(`
          INSERT INTO athlete_profile_requests(
            id,user_id,requested_player_name,requested_sport,requested_team,requested_jersey_numbers,
            status,submitted_at,reviewed_at,reviewed_by,review_note
          ) VALUES(?1,?2,?3,?4,?5,?6,'pending',?7,NULL,NULL,NULL)
        `).bind(
          requestId,userId,displayName,primarySport,team||null,
          JSON.stringify(jerseys),now
        ).run();
        athleteRequest={id:requestId,status:"pending"};
      }

      const session=await createPlayerSession(request,env,userId);
      await env.DB.prepare(`
        INSERT OR REPLACE INTO user_login_activity(user_id,last_login_at,previous_login_at,updated_at)
        VALUES(?1,?2,NULL,?2)
      `).bind(userId,new Date().toISOString()).run();
      await ensureNotificationPrefs(env,userId);
      await logActivity(env,{
        eventType:"account_registered",userId,
        metadata:{roles,sports}
      });
      return jsonCookie(request,{
        ok:true,
        user:{
          id:userId,email,display_name:displayName,
          account_status:accountStatus,athlete_id:null,player_name:null,
          athlete_verification_status:null,roles
        },
        sports,
        jersey_numbers:jerseys,
        athlete_request:athleteRequest
      },201,sessionCookie(session.token));
    }

    if(url.pathname==="/api/auth/login" && request.method==="POST"){
      const b=await bodyJson(request);
      const email=String(b?.email||"").trim().toLowerCase();
      const password=String(b?.password||"");
      if(!email||!password)return json(request,{ok:false,error:"Email and password are required"},400);

      const row=await env.DB.prepare(`
        SELECT u.id AS user_id,u.email,u.display_name,u.account_status,
               c.password_salt,c.password_hash,c.password_iterations,
               ap.id AS athlete_id,ap.player_name,ap.verification_status
        FROM user_accounts u
        JOIN auth_credentials c ON c.user_id=u.id
        LEFT JOIN athlete_profiles ap ON ap.user_id=u.id
        WHERE u.email=?1
        LIMIT 1
      `).bind(email).first();

      if(!row)return json(request,{
        ok:false,
        code:"EMAIL_NOT_FOUND",
        error:"We don't recognize that email address."
      },404);
      if(row.account_status==="suspended")
        return json(request,{ok:false,code:"ACCOUNT_SUSPENDED",error:"This account is suspended"},403);

      const candidate=await passwordHash(password,row.password_salt,row.password_iterations);
      if(!secureEqual(candidate,row.password_hash))
        return json(request,{ok:false,code:"INVALID_PASSWORD",error:"Incorrect password"},401);

      // Revoke old expired sessions opportunistically.
      const now=new Date().toISOString();
      await env.DB.prepare(`
        UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at,?1)
        WHERE user_id=?2 AND expires_at<=?1 AND revoked_at IS NULL
      `).bind(now,row.user_id).run();

      const session=await createPlayerSession(request,env,row.user_id);
      const loginNow=new Date().toISOString();
      const activity=await env.DB.prepare(`
        SELECT last_login_at FROM user_login_activity WHERE user_id=?1
      `).bind(row.user_id).first();
      await env.DB.prepare(`
        INSERT INTO user_login_activity(user_id,last_login_at,previous_login_at,updated_at)
        VALUES(?1,?2,?3,?2)
        ON CONFLICT(user_id) DO UPDATE SET
          previous_login_at=user_login_activity.last_login_at,
          last_login_at=excluded.last_login_at,
          updated_at=excluded.updated_at
      `).bind(row.user_id,loginNow,activity?.last_login_at||null).run();
      await ensureNotificationPrefs(env,row.user_id);
      await logActivity(env,{eventType:"login",userId:row.user_id});
      return jsonCookie(request,{ok:true,user:publicUserShape(row)},200,sessionCookie(session.token));
    }

    if(url.pathname==="/api/auth/logout" && request.method==="POST"){
      const token=parseCookies(request)[PLAYER_SESSION_COOKIE];
      if(token){
        const tokenHash=await sha256B64(token);
        await env.DB.prepare(`
          UPDATE auth_sessions SET revoked_at=?1
          WHERE token_hash=?2 AND revoked_at IS NULL
        `).bind(new Date().toISOString(),tokenHash).run();
      }
      return jsonCookie(request,{ok:true},200,clearSessionCookie());
    }

    if(url.pathname==="/api/auth/me" && request.method==="GET"){
      const session=await getPlayerSession(request,env);
      if(!session)return json(request,{ok:true,logged_in:false,user:null});
      const pending=await env.DB.prepare(`
        SELECT id,requested_player_name,requested_sport,requested_team,
               requested_jersey_numbers,status,submitted_at,reviewed_at,review_note
        FROM athlete_profile_requests
        WHERE user_id=?1
        ORDER BY submitted_at DESC
        LIMIT 1
      `).bind(session.user_id).first();

      let memberships=[];
      if(session.athlete_id){
        const m=await env.DB.prepare(`
          SELECT * FROM athlete_memberships WHERE athlete_id=?1 AND active=1 ORDER BY sport,team
        `).bind(session.athlete_id).all();
        memberships=m.results||[];
        for(const membership of memberships){
          const j=await env.DB.prepare(`
            SELECT id,jersey_number,active FROM athlete_jersey_numbers
            WHERE membership_id=?1 AND active=1 ORDER BY jersey_number
          `).bind(membership.id).all();
          membership.jersey_numbers=j.results||[];
        }
      }

      const roleRows=await env.DB.prepare(`
        SELECT role FROM user_account_roles WHERE user_id=?1 ORDER BY role
      `).bind(session.user_id).all();
      const roles=(roleRows.results||[]).map(x=>x.role);

      const sportRows=await env.DB.prepare(`
        SELECT sport,custom_sport FROM account_sport_preferences
        WHERE user_id=?1 ORDER BY sport,custom_sport
      `).bind(session.user_id).all();

      const entitlementRows=await env.DB.prepare(`
        SELECT e.id,e.gallery_id,e.can_download_all,e.can_order_prints,e.status,e.granted_at,e.note,
               g.title,g.shoot_date
        FROM client_gallery_entitlements e
        JOIN galleries g ON g.id=e.gallery_id
        WHERE e.user_id=?1 AND e.status='active'
        ORDER BY COALESCE(g.shoot_date,g.created_at) DESC
      `).bind(session.user_id).all();

      return json(request,{
        ok:true,logged_in:true,
        user:{...publicUserShape(session),roles},
        athlete_request:pending?{
          ...pending,
          requested_jersey_numbers:parseJson(pending.requested_jersey_numbers,[])
        }:null,
        memberships,
        sport_preferences:sportRows.results||[],
        client_entitlements:entitlementRows.results||[]
      });
    }


    // ---------- PLAYER / CLIENT ACCOUNT ACCESS ----------
    if(url.pathname==="/api/account/preferences" && request.method==="PATCH"){
      const gate=await requirePlayer(request,env); if(gate.response)return gate.response;
      const b=await bodyJson(request);
      const roles=normalizedRoles(b?.roles||b?.role);
      const sports=normalizedSports(b?.sports||[]);
      const customSport=String(b?.custom_sport||"").trim().slice(0,120);
      const now=new Date().toISOString();

      await env.DB.prepare(`DELETE FROM user_account_roles WHERE user_id=?1`).bind(gate.session.user_id).run();
      for(const role of roles){
        await env.DB.prepare(`
          INSERT INTO user_account_roles(user_id,role,created_at,created_by)
          VALUES(?1,?2,?3,'account-update')
        `).bind(gate.session.user_id,role,now).run();
      }

      await env.DB.prepare(`DELETE FROM account_sport_preferences WHERE user_id=?1`).bind(gate.session.user_id).run();
      for(const sport of sports){
        await env.DB.prepare(`
          INSERT INTO account_sport_preferences(id,user_id,sport,custom_sport,created_at)
          VALUES(?1,?2,?3,?4,?5)
        `).bind(
          `sportpref-${crypto.randomUUID()}`,gate.session.user_id,sport,
          sport==="other"?(customSport||null):null,now
        ).run();
      }

      return json(request,{ok:true,roles,sports});
    }

    if(url.pathname==="/api/client/my-galleries" && request.method==="GET"){
      const gate=await requirePlayer(request,env); if(gate.response)return gate.response;
      const rows=await env.DB.prepare(`
        SELECT e.id,e.gallery_id,e.can_download_all,e.can_order_prints,e.status,e.granted_at,e.note,
               g.title,g.shoot_date
        FROM client_gallery_entitlements e
        JOIN galleries g ON g.id=e.gallery_id
        WHERE e.user_id=?1 AND e.status='active'
        ORDER BY COALESCE(g.shoot_date,g.created_at) DESC
      `).bind(gate.session.user_id).all();
      return json(request,{ok:true,galleries:rows.results||[]});
    }

    const clientGalleryPhotos=url.pathname.match(/^\/api\/client\/galleries\/([^/]+)\/photos$/);
    if(clientGalleryPhotos && request.method==="GET"){
      const gate=await requirePlayer(request,env); if(gate.response)return gate.response;
      const galleryId=decodeURIComponent(clientGalleryPhotos[1]);
      const entitlement=await env.DB.prepare(`
        SELECT can_download_all,can_order_prints FROM client_gallery_entitlements
        WHERE user_id=?1 AND gallery_id=?2 AND status='active'
      `).bind(gate.session.user_id,galleryId).first();
      if(!entitlement)return json(request,{ok:false,error:"You do not have client access to this gallery"},403);

      const rows=await env.DB.prepare(`
        SELECT id,filename,preview_key,sort_order
        FROM photos WHERE gallery_id=?1 ORDER BY sort_order,filename
      `).bind(galleryId).all();

      return json(request,{
        ok:true,
        can_download_all:Boolean(entitlement.can_download_all),
        can_order_prints:Boolean(entitlement.can_order_prints),
        photos:(rows.results||[]).map(p=>({
          ...p,
          preview_url:p.preview_key?`/api/preview/${encodeURIComponent(p.preview_key)}`:null,
          download_url:entitlement.can_download_all?`/api/client/photos/${encodeURIComponent(p.id)}/download`:null
        }))
      });
    }

    const clientDownload=url.pathname.match(/^\/api\/client\/photos\/([^/]+)\/download$/);
    if(clientDownload && request.method==="GET"){
      const gate=await requirePlayer(request,env); if(gate.response)return gate.response;
      const photoId=decodeURIComponent(clientDownload[1]);
      const row=await env.DB.prepare(`
        SELECT p.id,p.filename,p.original_key,p.gallery_id
        FROM photos p
        JOIN client_gallery_entitlements e ON e.gallery_id=p.gallery_id
        WHERE p.id=?1 AND e.user_id=?2 AND e.status='active' AND e.can_download_all=1
        LIMIT 1
      `).bind(photoId,gate.session.user_id).first();
      if(!row)return json(request,{ok:false,error:"Digital download access is not available for this photo"},403);

      const object=await env.ORIGINALS.get(row.original_key);
      if(!object)return json(request,{ok:false,error:"Original file not found"},404);

      const headers=cors(request);
      object.writeHttpMetadata(headers);
      headers.set("Content-Disposition",`attachment; filename="${String(row.filename||"photo").replace(/["\\r\\n]/g,"_")}"`);
      headers.set("Cache-Control","private, no-store");
      return new Response(object.body,{headers});
    }


    // ---------- ACCOUNT NOTIFICATIONS ----------
    if(url.pathname==="/api/account/notifications" && request.method==="GET"){
      const gate=await requirePlayer(request,env); if(gate.response)return gate.response;
      const since=String(url.searchParams.get("since")||"").trim();
      const rows=await env.DB.prepare(`
        SELECT n.id,n.notification_type,n.gallery_id,n.photo_id,n.athlete_id,
               n.title,n.message,n.created_at,n.read_at,
               g.title AS gallery_title
        FROM user_notifications n
        LEFT JOIN galleries g ON g.id=n.gallery_id
        WHERE n.user_id=?1
          AND (?2='' OR n.created_at>?2)
        ORDER BY n.created_at DESC
        LIMIT 200
      `).bind(gate.session.user_id,since).all();

      const activity=await env.DB.prepare(`
        SELECT last_login_at,previous_login_at FROM user_login_activity WHERE user_id=?1
      `).bind(gate.session.user_id).first();

      const unread=(rows.results||[]).filter(x=>!x.read_at).length;
      const sinceLastLogin=(rows.results||[]).filter(x=>
        activity?.previous_login_at && x.created_at>activity.previous_login_at
      ).length;

      return json(request,{
        ok:true,
        unread_count:unread,
        new_since_previous_login:sinceLastLogin,
        previous_login_at:activity?.previous_login_at||null,
        last_login_at:activity?.last_login_at||null,
        notifications:rows.results||[]
      });
    }

    if(url.pathname==="/api/account/notifications/read-all" && request.method==="POST"){
      const gate=await requirePlayer(request,env); if(gate.response)return gate.response;
      const now=new Date().toISOString();
      await env.DB.prepare(`
        UPDATE user_notifications SET read_at=?1
        WHERE user_id=?2 AND read_at IS NULL
      `).bind(now,gate.session.user_id).run();
      return json(request,{ok:true,read_at:now});
    }

    const notifRead=url.pathname.match(/^\/api\/account\/notifications\/([^/]+)\/read$/);
    if(notifRead && request.method==="POST"){
      const gate=await requirePlayer(request,env); if(gate.response)return gate.response;
      const id=decodeURIComponent(notifRead[1]);
      const now=new Date().toISOString();
      await env.DB.prepare(`
        UPDATE user_notifications SET read_at=?1
        WHERE id=?2 AND user_id=?3
      `).bind(now,id,gate.session.user_id).run();
      return json(request,{ok:true,id,read_at:now});
    }

    if(url.pathname==="/api/account/notification-preferences" && request.method==="GET"){
      const gate=await requirePlayer(request,env); if(gate.response)return gate.response;
      await ensureNotificationPrefs(env,gate.session.user_id);
      const pref=await env.DB.prepare(`
        SELECT email_person_tags,email_client_gallery_updates,in_app_notifications,updated_at
        FROM notification_preferences WHERE user_id=?1
      `).bind(gate.session.user_id).first();
      return json(request,{ok:true,preferences:pref});
    }

    if(url.pathname==="/api/account/notification-preferences" && request.method==="PATCH"){
      const gate=await requirePlayer(request,env); if(gate.response)return gate.response;
      const b=await bodyJson(request);
      await ensureNotificationPrefs(env,gate.session.user_id);
      const current=await env.DB.prepare(`
        SELECT email_person_tags,email_client_gallery_updates,in_app_notifications
        FROM notification_preferences WHERE user_id=?1
      `).bind(gate.session.user_id).first();
      const p1=b?.email_person_tags===undefined?current.email_person_tags:(b.email_person_tags?1:0);
      const p2=b?.email_client_gallery_updates===undefined?current.email_client_gallery_updates:(b.email_client_gallery_updates?1:0);
      const p3=b?.in_app_notifications===undefined?current.in_app_notifications:(b.in_app_notifications?1:0);
      const now=new Date().toISOString();
      await env.DB.prepare(`
        UPDATE notification_preferences
        SET email_person_tags=?1,email_client_gallery_updates=?2,in_app_notifications=?3,updated_at=?4
        WHERE user_id=?5
      `).bind(p1,p2,p3,now,gate.session.user_id).run();
      return json(request,{ok:true,preferences:{
        email_person_tags:p1,email_client_gallery_updates:p2,in_app_notifications:p3,updated_at:now
      }});
    }

    // Search verified athletes by first name, last name, full/partial name,
    // sport, team, or jersey number. No email addresses are exposed.
    if(url.pathname==="/api/athletes/search" && request.method==="GET"){
      const q=String(url.searchParams.get("q")||"").trim().slice(0,100);
      const sport=String(url.searchParams.get("sport")||"").trim().slice(0,120);
      const team=String(url.searchParams.get("team")||"").trim().slice(0,200);
      const jersey=String(url.searchParams.get("jersey")||"").trim().slice(0,30);
      if(!q&&!sport&&!team&&!jersey)
        return json(request,{ok:true,athletes:[]});

      const like=x=>`%${x.replace(/[\\%_]/g,m=>"\\"+m)}%`;
      const rows=await env.DB.prepare(`
        SELECT DISTINCT ap.id,ap.player_name,am.sport,am.team,ajn.jersey_number
        FROM athlete_profiles ap
        LEFT JOIN athlete_memberships am ON am.athlete_id=ap.id AND am.active=1
        LEFT JOIN athlete_jersey_numbers ajn ON ajn.membership_id=am.id AND ajn.active=1
        WHERE ap.verification_status='verified'
          AND (?1='' OR ap.player_name LIKE ?2 ESCAPE '\\' COLLATE NOCASE)
          AND (?3='' OR am.sport LIKE ?4 ESCAPE '\\' COLLATE NOCASE)
          AND (?5='' OR am.team LIKE ?6 ESCAPE '\\' COLLATE NOCASE)
          AND (?7='' OR ajn.jersey_number=?7)
        ORDER BY ap.player_name COLLATE NOCASE
        LIMIT 50
      `).bind(q,like(q),sport,like(sport),team,like(team),jersey).all();

      const grouped=new Map();
      for(const row of rows.results||[]){
        if(!grouped.has(row.id))grouped.set(row.id,{
          id:row.id,player_name:row.player_name,memberships:[]
        });
        const athlete=grouped.get(row.id);
        if(row.sport||row.team||row.jersey_number){
          let m=athlete.memberships.find(x=>x.sport===row.sport&&x.team===row.team);
          if(!m){
            m={sport:row.sport||null,team:row.team||null,jersey_numbers:[]};
            athlete.memberships.push(m);
          }
          if(row.jersey_number&&!m.jersey_numbers.includes(row.jersey_number))
            m.jersey_numbers.push(row.jersey_number);
        }
      }
      return json(request,{ok:true,athletes:[...grouped.values()]});
    }

    if(url.pathname==="/api/player/athlete-request" && request.method==="POST"){
      const gate=await requirePlayer(request,env); if(gate.response)return gate.response;
      const session=gate.session;
      if(session.athlete_id && session.verification_status==="verified")
        return json(request,{ok:false,error:"This account is already linked to a verified athlete"},409);

      const b=await bodyJson(request);
      const playerName=String(b?.player_name||"").trim().slice(0,200);
      const sport=String(b?.sport||"").trim().slice(0,120);
      const team=String(b?.team||"").trim().slice(0,200);
      const jerseys=normalizedJerseys(b?.jersey_numbers);
      if(!playerName)return json(request,{ok:false,error:"Player name is required"},400);

      const pending=await env.DB.prepare(`
        SELECT id FROM athlete_profile_requests WHERE user_id=?1 AND status='pending' LIMIT 1
      `).bind(session.user_id).first();
      if(pending)return json(request,{ok:false,error:"You already have a pending athlete request"},409);

      const now=new Date().toISOString();
      const id=`athreq-${crypto.randomUUID()}`;
      await env.DB.prepare(`
        INSERT INTO athlete_profile_requests(
          id,user_id,requested_player_name,requested_sport,requested_team,requested_jersey_numbers,
          status,submitted_at,reviewed_at,reviewed_by,review_note
        ) VALUES(?1,?2,?3,?4,?5,?6,'pending',?7,NULL,NULL,NULL)
      `).bind(id,session.user_id,playerName,sport||null,team||null,JSON.stringify(jerseys),now).run();

      return json(request,{ok:true,id,status:"pending"},201);
    }

    if(url.pathname==="/api/player/photo-claims" && request.method==="POST"){
      const gate=await requirePlayer(request,env); if(gate.response)return gate.response;
      const session=gate.session;
      if(!session.athlete_id || session.verification_status!=="verified")
        return json(request,{ok:false,error:"A verified athlete profile is required to claim photos"},403);

      const b=await bodyJson(request);
      const galleryId=String(b?.gallery_id||"");
      const photoId=String(b?.photo_id||"");
      const membershipId=String(b?.membership_id||"")||null;
      const jersey=String(b?.jersey_number||"").trim().slice(0,30)||null;
      if(!galleryId||!photoId)
        return json(request,{ok:false,error:"gallery_id and photo_id are required"},400);

      const photo=await env.DB.prepare(`SELECT id FROM photos WHERE id=?1 AND gallery_id=?2`)
        .bind(photoId,galleryId).first();
      if(!photo)return json(request,{ok:false,error:"Photo not found in this event"},404);

      if(membershipId){
        const owned=await env.DB.prepare(`
          SELECT id FROM athlete_memberships WHERE id=?1 AND athlete_id=?2
        `).bind(membershipId,session.athlete_id).first();
        if(!owned)return json(request,{ok:false,error:"Invalid athlete membership"},400);
      }

      const approved=await env.DB.prepare(`
        SELECT id FROM photo_person_links WHERE photo_id=?1 AND athlete_id=?2
      `).bind(photoId,session.athlete_id).first();
      if(approved)return json(request,{ok:true,already_verified:true,id:approved.id});

      const existing=await env.DB.prepare(`
        SELECT id,status FROM photo_claims
        WHERE user_id=?1 AND photo_id=?2 AND athlete_id=?3
        LIMIT 1
      `).bind(session.user_id,photoId,session.athlete_id).first();
      if(existing)return json(request,{ok:true,id:existing.id,status:existing.status,already_exists:true});

      const now=new Date().toISOString();
      const id=`claim-${crypto.randomUUID()}`;
      await env.DB.prepare(`
        INSERT INTO photo_claims(
          id,user_id,athlete_id,gallery_id,photo_id,membership_id,jersey_number,
          status,submitted_at,reviewed_at,reviewed_by,review_note
        ) VALUES(?1,?2,?3,?4,?5,?6,?7,'pending',?8,NULL,NULL,NULL)
      `).bind(id,session.user_id,session.athlete_id,galleryId,photoId,membershipId,jersey,now).run();

      const claimActivity=await logActivity(env,{
        eventType:"photo_claim_submitted",userId:session.user_id,
        galleryId,photoId,athleteId:session.athlete_id,
        metadata:{membership_id:membershipId,jersey_number:jersey}
      });
      const claimGallery=await env.DB.prepare(`SELECT title FROM galleries WHERE id=?1`).bind(galleryId).first();
      const adminSettings=await env.DB.prepare(`
        SELECT pending_claim_alerts FROM admin_notification_settings WHERE id=1
      `).first();
      if(adminSettings?.pending_claim_alerts){
        await queueAdminEmailBatch(env,{
          batchType:"pending_claims",
          batchKey:`${galleryId}:${dateKeyUTC(now)}`,
          activityId:claimActivity,
          claimId:id,
          eventAt:now
        });
      }
      return json(request,{ok:true,id,status:"pending"},201);
    }



    if(url.pathname==="/api/player/player-tag-suggestions-v15" && request.method==="GET"){
      const session=await currentSession(request,env);
      if(!session)return json(request,{ok:false,error:"Login required"},401);
      const athlete=await env.DB.prepare(`
        SELECT id,player_name,verification_status FROM athlete_profiles WHERE user_id=?1
      `).bind(session.user_id).first();
      if(!athlete || athlete.verification_status!=="verified")
        return json(request,{ok:true,suggestions:[]});

      const rows=await env.DB.prepare(`
        SELECT pts.*,p.filename,p.preview_key,g.title AS gallery_title,g.shoot_date
        FROM player_tag_suggestions pts
        JOIN photos p ON p.id=pts.photo_id
        JOIN galleries g ON g.id=pts.gallery_id
        LEFT JOIN roster_players rp ON rp.id=pts.roster_player_id
        WHERE pts.status='pending'
          AND (
            rp.athlete_id=?1
            OR LOWER(TRIM(pts.suggested_name))=LOWER(TRIM(?2))
          )
        ORDER BY pts.submitted_at DESC
        LIMIT 200
      `).bind(athlete.id,athlete.player_name).all();

      return json(request,{ok:true,suggestions:rows.results||[]});
    }

    const playerV15Approve=url.pathname.match(/^\/api\/player\/player-tag-suggestions-v15\/([^/]+)\/approve$/);
    if(playerV15Approve && request.method==="POST"){
      const session=await currentSession(request,env);
      if(!session)return json(request,{ok:false,error:"Login required"},401);
      const athlete=await env.DB.prepare(`
        SELECT id,player_name,verification_status FROM athlete_profiles WHERE user_id=?1
      `).bind(session.user_id).first();
      if(!athlete || athlete.verification_status!=="verified")
        return json(request,{ok:false,error:"Verified player account required"},403);

      const suggestionId=decodeURIComponent(playerV15Approve[1]);
      const row=await env.DB.prepare(`
        SELECT pts.*,rp.athlete_id AS roster_athlete_id
        FROM player_tag_suggestions pts
        LEFT JOIN roster_players rp ON rp.id=pts.roster_player_id
        WHERE pts.id=?1 AND pts.status='pending'
      `).bind(suggestionId).first();
      if(!row)return json(request,{ok:false,error:"Pending tag suggestion not found"},404);

      const allowed=
        row.roster_athlete_id===athlete.id ||
        String(row.suggested_name||"").trim().toLowerCase()===String(athlete.player_name||"").trim().toLowerCase();
      if(!allowed)
        return json(request,{ok:false,error:"This suggestion does not match your verified player identity."},403);

      const now=new Date().toISOString();
      await env.DB.prepare(`
        UPDATE player_tag_suggestions
        SET status='approved',approved_athlete_id=?1,reviewed_at=?2,reviewed_by=?3
        WHERE id=?4
      `).bind(athlete.id,now,session.user_id,suggestionId).run();

      await env.DB.prepare(`
        INSERT OR IGNORE INTO photo_person_links(
          id,athlete_id,gallery_id,photo_id,membership_id,jersey_number,
          source,created_at,created_by
        ) VALUES(?1,?2,?3,?4,NULL,?5,'approved_claim',?6,?7)
      `).bind(
        `ppl-${crypto.randomUUID()}`,athlete.id,row.gallery_id,row.photo_id,
        row.suggested_jersey_number||null,now,session.user_id
      ).run();

      if(row.roster_player_id){
        await env.DB.prepare(`
          UPDATE roster_players SET athlete_id=?1,updated_at=?2
          WHERE id=?3 AND athlete_id IS NULL
        `).bind(athlete.id,now,row.roster_player_id).run();
      }

      await logActivity(env,{
        eventType:"player_tag_self_approved",
        userId:session.user_id,galleryId:row.gallery_id,photoId:row.photo_id,athleteId:athlete.id,
        metadata:{suggestion_id:suggestionId,player_name:row.suggested_name}
      });

      return json(request,{ok:true,status:"approved"});
    }

    if(url.pathname==="/api/player/player-tag-suggestions" && request.method==="GET"){
      const session=await currentSession(request,env);
      if(!session)return json(request,{ok:false,error:"Login required"},401);
      const athlete=await env.DB.prepare(`
        SELECT id,player_name,verification_status FROM athlete_profiles WHERE user_id=?1
      `).bind(session.user_id).first();
      if(!athlete || athlete.verification_status!=="verified")
        return json(request,{ok:true,suggestions:[]});

      const rows=await env.DB.prepare(`
        SELECT pt.id AS photo_tag_id,t.label AS player_name,
               p.id AS photo_id,p.filename,p.preview_key,
               g.id AS gallery_id,g.title AS gallery_title,g.shoot_date,
               pt.created_at
        FROM photo_tags pt
        JOIN tags t ON t.id=pt.tag_id
        JOIN photos p ON p.id=pt.photo_id
        JOIN galleries g ON g.id=pt.gallery_id
        WHERE pt.status='pending'
          AND pt.source='user_suggestion'
          AND t.tag_type='person'
          AND LOWER(TRIM(t.label))=LOWER(TRIM(?1))
        ORDER BY pt.created_at DESC
        LIMIT 200
      `).bind(athlete.player_name).all();
      return json(request,{ok:true,suggestions:rows.results||[]});
    }

    const playerTagSuggestionApprove=url.pathname.match(/^\/api\/player\/player-tag-suggestions\/([^/]+)\/approve$/);
    if(playerTagSuggestionApprove && request.method==="POST"){
      const session=await currentSession(request,env);
      if(!session)return json(request,{ok:false,error:"Login required"},401);

      const athlete=await env.DB.prepare(`
        SELECT id,player_name,verification_status FROM athlete_profiles WHERE user_id=?1
      `).bind(session.user_id).first();
      if(!athlete || athlete.verification_status!=="verified")
        return json(request,{ok:false,error:"Verified player account required"},403);

      const photoTagId=decodeURIComponent(playerTagSuggestionApprove[1]);
      const row=await env.DB.prepare(`
        SELECT pt.id,pt.photo_id,pt.gallery_id,pt.tag_id,pt.status,t.label
        FROM photo_tags pt JOIN tags t ON t.id=pt.tag_id
        WHERE pt.id=?1
          AND pt.status='pending'
          AND pt.source='user_suggestion'
          AND t.tag_type='person'
      `).bind(photoTagId).first();
      if(!row)return json(request,{ok:false,error:"Pending player tag not found"},404);

      if(String(row.label).trim().toLowerCase()!==String(athlete.player_name).trim().toLowerCase())
        return json(request,{ok:false,error:"This suggested name does not match your verified player name."},403);

      const now=new Date().toISOString();
      await env.DB.prepare(`
        UPDATE photo_tags SET status='active',reviewed_at=?1,reviewed_by=?2
        WHERE id=?3
      `).bind(now,session.user_id,photoTagId).run();

      await env.DB.prepare(`
        INSERT OR IGNORE INTO athlete_tag_links(athlete_id,tag_id,created_at)
        VALUES(?1,?2,?3)
      `).bind(athlete.id,row.tag_id,now).run();

      await env.DB.prepare(`
        INSERT OR IGNORE INTO photo_person_links(
          id,athlete_id,gallery_id,photo_id,membership_id,jersey_number,
          source,created_at,created_by
        ) VALUES(?1,?2,?3,?4,NULL,NULL,'approved_claim',?5,?6)
      `).bind(`ppl-${crypto.randomUUID()}`,athlete.id,row.gallery_id,row.photo_id,now,session.user_id).run();

      await logActivity(env,{
        eventType:"player_tag_self_approved",userId:session.user_id,
        galleryId:row.gallery_id,photoId:row.photo_id,athleteId:athlete.id,
        metadata:{photo_tag_id:photoTagId,player_name:row.label}
      });

      return json(request,{ok:true,status:"active"});
    }

    if(url.pathname==="/api/player/my-events" && request.method==="GET"){
      const gate=await requirePlayer(request,env); if(gate.response)return gate.response;
      const session=gate.session;
      if(!session.athlete_id || session.verification_status!=="verified")
        return json(request,{ok:true,events:[]});

      const rows=await env.DB.prepare(`
        SELECT g.id AS gallery_id,g.title,g.shoot_date,g.created_at,
               COUNT(DISTINCT ppl.photo_id) AS approved_photo_count
        FROM photo_person_links ppl
        JOIN galleries g ON g.id=ppl.gallery_id
        WHERE ppl.athlete_id=?1
        GROUP BY g.id,g.title,g.shoot_date,g.created_at
        ORDER BY COALESCE(g.shoot_date,g.created_at) DESC
      `).bind(session.athlete_id).all();

      return json(request,{ok:true,events:rows.results||[]});
    }

    if(url.pathname==="/api/player/my-photos" && request.method==="GET"){
      const gate=await requirePlayer(request,env); if(gate.response)return gate.response;
      const session=gate.session;
      if(!session.athlete_id || session.verification_status!=="verified")
        return json(request,{ok:true,photos:[]});

      const galleryId=String(url.searchParams.get("gallery_id")||"");
      if(!galleryId)return json(request,{ok:false,error:"gallery_id is required"},400);
      const rows=await env.DB.prepare(`
        SELECT p.id,p.filename,p.preview_key,ppl.jersey_number,ppl.source
        FROM photo_person_links ppl
        JOIN photos p ON p.id=ppl.photo_id
        WHERE ppl.athlete_id=?1 AND ppl.gallery_id=?2
        ORDER BY p.sort_order,p.filename
      `).bind(session.athlete_id,galleryId).all();

      return json(request,{ok:true,photos:(rows.results||[]).map(x=>({
        ...x,preview_url:x.preview_key?`/api/preview/${encodeURIComponent(x.preview_key)}`:null
      }))});
    }


    // ---------- PUBLIC REELS (MARKETING ONLY) ----------
    if(url.pathname==="/api/reels" && request.method==="GET"){
      const rows=await env.DB.prepare(`
        SELECT r.id,r.title,r.filename,r.poster_key,r.sort_order,r.caption,r.sport,r.team,
               r.event_label,r.related_gallery_id,r.featured,r.created_at,
               g.title AS related_gallery_title
        FROM reels r
        LEFT JOIN galleries g ON g.id=r.related_gallery_id
        WHERE r.status='active'
        ORDER BY r.sort_order,r.created_at
      `).all();
      return json(request,{ok:true,reels:(rows.results||[]).map(x=>({...x,
        video_url:`/api/reels/media/${encodeURIComponent(x.id)}`,
        poster_url:x.poster_key?`/api/preview/${encodeURIComponent(x.poster_key)}`:null,
        gallery_url:x.related_gallery_id?`/shoot.html?id=${encodeURIComponent(x.related_gallery_id)}`:null
      }))});
    }

    const reelMedia=url.pathname.match(/^\/api\/reels\/media\/([^/]+)$/);
    if(reelMedia && request.method==="GET"){
      const id=decodeURIComponent(reelMedia[1]);
      const row=await env.DB.prepare(`SELECT video_key FROM reels WHERE id=?1 AND status='active'`).bind(id).first();
      if(!row)return text(request,"Reel not found",404);

      const object=await env.ORIGINALS.get(row.video_key,{
        onlyIf:request.headers,
        range:request.headers
      });
      if(!object)return text(request,"Video not found",404);

      const headers=cors(request);
      object.writeHttpMetadata(headers);
      headers.set("etag",object.httpEtag);
      headers.set("Accept-Ranges","bytes");
      headers.set("Cache-Control","public, max-age=3600");

      let status=200;
      if(object.range){
        const offset=Number(object.range.offset||0);
        const length=Number(object.range.length||0);
        const end=Math.max(offset,offset+length-1);
        headers.set("Content-Range",`bytes ${offset}-${end}/${object.size}`);
        headers.set("Content-Length",String(length));
        status=206;
      }else{
        headers.set("Content-Length",String(object.size));
      }
      return new Response("body" in object?object.body:undefined,{
        status:"body" in object?status:412,
        headers
      });
    }


    // ---------- PUBLIC PHOTO RATINGS / FAN FAVORITES ----------
    const ratingSummary=url.pathname.match(/^\/api\/galleries\/([^/]+)\/ratings$/);
    if(ratingSummary && request.method==="GET"){
      const galleryId=decodeURIComponent(ratingSummary[1]);
      const guestKey=String(url.searchParams.get("guest_key")||"").trim().slice(0,160);
      const rows=await env.DB.prepare(`
        SELECT p.id AS photo_id,
               COUNT(r.id) AS rating_count,
               ROUND(AVG(r.rating),2) AS average_rating,
               MAX(CASE WHEN ?2<>'' AND r.guest_key=?2 AND r.user_id IS NULL THEN r.rating ELSE NULL END) AS my_rating
        FROM photos p
        LEFT JOIN photo_ratings r ON r.photo_id=p.id AND r.gallery_id=p.gallery_id
        WHERE p.gallery_id=?1
        GROUP BY p.id
      `).bind(galleryId,guestKey).all();
      return json(request,{ok:true,ratings:rows.results||[]});
    }

    const fanFav=url.pathname.match(/^\/api\/galleries\/([^/]+)\/fan-favorites$/);
    if(fanFav && request.method==="GET"){
      const galleryId=decodeURIComponent(fanFav[1]);
      const rows=await env.DB.prepare(`
        SELECT p.id AS photo_id,p.filename,p.preview_key,
               COUNT(r.id) AS rating_count,
               ROUND(AVG(r.rating),2) AS average_rating
        FROM photos p
        JOIN photo_ratings r ON r.photo_id=p.id AND r.gallery_id=p.gallery_id
        WHERE p.gallery_id=?1
        GROUP BY p.id
        HAVING COUNT(r.id)>0
        ORDER BY average_rating DESC,rating_count DESC,p.sort_order ASC
        LIMIT 100
      `).bind(galleryId).all();
      return json(request,{ok:true,photos:(rows.results||[]).map(x=>({...x,
        preview_url:x.preview_key?`/api/preview/${encodeURIComponent(x.preview_key)}`:null
      }))});
    }

    if(url.pathname==="/api/photo-ratings" && request.method==="POST"){
      const b=await bodyJson(request);
      const galleryId=String(b?.gallery_id||"");
      const photoId=String(b?.photo_id||"");
      const guestKey=String(b?.guest_key||"").trim().slice(0,160);
      const rating=Number(b?.rating);

      if(!galleryId||!photoId||!guestKey||!Number.isInteger(rating)||rating<0||rating>5)
        return json(request,{ok:false,error:"gallery_id, photo_id, guest_key and rating 0-5 are required"},400);

      const photo=await env.DB.prepare(`SELECT id FROM photos WHERE id=?1 AND gallery_id=?2`)
        .bind(photoId,galleryId).first();
      if(!photo)return json(request,{ok:false,error:"Photo not found in this gallery"},404);

      const now=new Date().toISOString();
      const existing=await env.DB.prepare(`
        SELECT id FROM photo_ratings WHERE photo_id=?1 AND guest_key=?2 AND user_id IS NULL
      `).bind(photoId,guestKey).first();

      if(rating===0){
        if(existing)await env.DB.prepare(`DELETE FROM photo_ratings WHERE id=?1`).bind(existing.id).run();
      }else if(existing){
        await env.DB.prepare(`
          UPDATE photo_ratings SET rating=?1,updated_at=?2 WHERE id=?3
        `).bind(rating,now,existing.id).run();
      }else{
        const id=`rating-${crypto.randomUUID()}`;
        await env.DB.prepare(`
          INSERT INTO photo_ratings(id,gallery_id,photo_id,user_id,guest_key,rating,created_at,updated_at)
          VALUES(?1,?2,?3,NULL,?4,?5,?6,?6)
        `).bind(id,galleryId,photoId,guestKey,rating,now).run();
      }

      const summary=await env.DB.prepare(`
        SELECT COUNT(*) AS rating_count,ROUND(AVG(rating),2) AS average_rating
        FROM photo_ratings WHERE gallery_id=?1 AND photo_id=?2
      `).bind(galleryId,photoId).first();

      await logActivity(env,{
        eventType:rating===0?"photo_rating_cleared":"photo_rating",galleryId,photoId,
        metadata:{rating,guest:true}
      });
      return json(request,{ok:true,rating,summary});
    }

    // ---------- PUBLIC SITE CONTENT ----------
    if(url.pathname==="/api/site-content" && request.method==="GET"){
      const rows=await env.DB.prepare(`SELECT section,published_json,published_at FROM site_content`).all();
      const content={};
      for(const row of rows.results||[]) content[row.section]=parseJson(row.published_json,{});
      return json(request,{ok:true,content});
    }

    // ---------- PUBLIC PORTFOLIO ----------
    if(url.pathname==="/api/portfolio" && request.method==="GET"){
      const category=(url.searchParams.get("category")||"").toLowerCase();
      const home=url.searchParams.get("home")==="1";
      let sql=`SELECT id,category,title,filename,preview_key,sort_order,is_cover,home_enabled,home_order,crop_desktop,crop_mobile,
                      cover_crop_desktop,cover_crop_mobile,alt_text,caption,location,search_tags,seo_title,seo_description
               FROM portfolio_items WHERE status='active'`;
      const binds=[];
      if(category && ["sports","portraits","events","other"].includes(category)){sql+=" AND category=?1";binds.push(category)}
      if(home) sql+=` AND home_enabled=1`;
      sql+=home?` ORDER BY home_order,created_at`:` ORDER BY is_cover DESC,sort_order,created_at`;
      const stmt=env.DB.prepare(sql);
      const rows=binds.length?await stmt.bind(...binds).all():await stmt.all();
      return json(request,{ok:true,items:(rows.results||[]).map(x=>({
        ...x,
        preview_url:`/api/preview/${encodeURIComponent(x.preview_key)}`,
        crop_desktop:parseJson(x.crop_desktop),
        crop_mobile:parseJson(x.crop_mobile)
      }))});
    }



    // ---------- LEGACY / BUILT-IN PORTFOLIO SETTINGS ----------
    if(url.pathname==="/api/portfolio-legacy-settings" && request.method==="GET"){
      const rows=await env.DB.prepare(`
        SELECT source_path,filename,original_category,category,hidden,is_cover,home_enabled,sort_order,
               crop_desktop,crop_mobile,cover_crop_desktop,cover_crop_mobile,updated_at
        FROM legacy_portfolio_settings
      `).all();
      return json(request,{ok:true,items:(rows.results||[]).map(x=>({
        ...x,
        crop_desktop:parseJson(x.crop_desktop),
        crop_mobile:parseJson(x.crop_mobile)
      }))});
    }

    if(url.pathname==="/api/admin/portfolio-legacy-settings" && request.method==="GET"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const rows=await env.DB.prepare(`
        SELECT source_path,filename,original_category,category,hidden,is_cover,home_enabled,sort_order,
               crop_desktop,crop_mobile,cover_crop_desktop,cover_crop_mobile,updated_at
        FROM legacy_portfolio_settings
        ORDER BY category,is_cover DESC,sort_order,filename
      `).all();
      return json(request,{ok:true,items:(rows.results||[]).map(x=>({
        ...x,
        crop_desktop:parseJson(x.crop_desktop),
        crop_mobile:parseJson(x.crop_mobile)
      }))});
    }

    if(url.pathname==="/api/admin/portfolio-legacy-settings" && request.method==="PUT"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const b=await bodyJson(request);
      const cats=["sports","portraits","events","other"];
      const sourcePath=String(b?.source_path||"").replace(/\\/g,"/").slice(0,600);
      const filename=String(b?.filename||sourcePath.split("/").pop()||"").slice(0,240);
      const originalCategory=cats.includes(b?.original_category)?b.original_category:null;
      const category=cats.includes(b?.category)?b.category:originalCategory;
      if(!sourcePath||!originalCategory||!category)return json(request,{ok:false,error:"source_path, original_category and category are required"},400);
      const existing=await env.DB.prepare(`SELECT * FROM legacy_portfolio_settings WHERE source_path=?1`).bind(sourcePath).first();
      const hidden=b?.hidden===undefined?(existing?.hidden||0):(b.hidden?1:0);
      const isCover=b?.is_cover===undefined?(existing?.is_cover||0):(b.is_cover?1:0);
      const homeEnabled=b?.home_enabled===undefined?(existing?.home_enabled||0):(b.home_enabled?1:0);
      const sortOrder=Number.isFinite(Number(b?.sort_order))?Number(b.sort_order):(existing?.sort_order||0);
      const cropDesktop=b?.crop_desktop===undefined?(existing?.crop_desktop||null):JSON.stringify(b.crop_desktop);
      const cropMobile=b?.crop_mobile===undefined?(existing?.crop_mobile||null):JSON.stringify(b.crop_mobile);
      const coverCropDesktop=b?.cover_crop_desktop===undefined?(existing?.cover_crop_desktop||null):JSON.stringify(b.cover_crop_desktop);
      const coverCropMobile=b?.cover_crop_mobile===undefined?(existing?.cover_crop_mobile||null):JSON.stringify(b.cover_crop_mobile);
      const now=new Date().toISOString();
      if(isCover){
        await env.DB.batch([
          env.DB.prepare(`UPDATE legacy_portfolio_settings SET is_cover=0 WHERE category=?1 AND source_path<>?2`).bind(category,sourcePath),
          env.DB.prepare(`UPDATE portfolio_items SET is_cover=0 WHERE category=?1`).bind(category)
        ]);
      }
      await env.DB.prepare(`
        INSERT INTO legacy_portfolio_settings(
          source_path,filename,original_category,category,hidden,is_cover,home_enabled,sort_order,
          crop_desktop,crop_mobile,cover_crop_desktop,cover_crop_mobile,updated_at
        ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
        ON CONFLICT(source_path) DO UPDATE SET
          filename=excluded.filename,
          original_category=excluded.original_category,
          category=excluded.category,
          hidden=excluded.hidden,
          is_cover=excluded.is_cover,
          home_enabled=excluded.home_enabled,
          sort_order=excluded.sort_order,
          crop_desktop=excluded.crop_desktop,
          crop_mobile=excluded.crop_mobile,
          cover_crop_desktop=excluded.cover_crop_desktop,
          cover_crop_mobile=excluded.cover_crop_mobile,
          updated_at=excluded.updated_at
      `).bind(
        sourcePath,filename,originalCategory,category,hidden,isCover,homeEnabled,sortOrder,
        cropDesktop,cropMobile,coverCropDesktop,coverCropMobile,now
      ).run();
      return json(request,{ok:true,source_path:sourcePath});
    }


    // ---------- LANDING SLIDESHOW ----------
    if(url.pathname==="/api/landing-slides" && request.method==="GET"){
      const rows=await env.DB.prepare(`
        SELECT l.id,l.source_kind,l.source_path,l.portfolio_id,l.filename,l.enabled,l.sort_order,l.duration_ms,
               l.crop_desktop,l.crop_mobile,p.preview_key,p.alt_text
        FROM landing_slides l
        LEFT JOIN portfolio_items p ON l.source_kind='portfolio' AND p.id=l.portfolio_id
        WHERE l.enabled=1
        ORDER BY l.sort_order,l.created_at
      `).all();
      return json(request,{ok:true,slides:(rows.results||[]).map(x=>({
        ...x,
        crop_desktop:parseJson(x.crop_desktop),
        crop_mobile:parseJson(x.crop_mobile),
        preview_url:x.preview_key?`/api/preview/${encodeURIComponent(x.preview_key)}`:null
      }))});
    }

    if(url.pathname==="/api/admin/landing-slides" && request.method==="GET"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const rows=await env.DB.prepare(`
        SELECT l.id,l.source_kind,l.source_path,l.portfolio_id,l.filename,l.enabled,l.sort_order,l.duration_ms,
               l.crop_desktop,l.crop_mobile,l.created_at,l.updated_at,
               p.preview_key,p.category,p.alt_text
        FROM landing_slides l
        LEFT JOIN portfolio_items p ON l.source_kind='portfolio' AND p.id=l.portfolio_id
        ORDER BY l.sort_order,l.created_at
      `).all();
      return json(request,{ok:true,slides:(rows.results||[]).map(x=>({
        ...x,
        crop_desktop:parseJson(x.crop_desktop),
        crop_mobile:parseJson(x.crop_mobile),
        preview_url:x.preview_key?`/api/preview/${encodeURIComponent(x.preview_key)}`:null
      }))});
    }

    if(url.pathname==="/api/admin/landing-slides/sync" && request.method==="POST"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const b=await bodyJson(request),paths=Array.isArray(b?.static_paths)?b.static_paths:[];
      const now=new Date().toISOString();
      let order=0;
      for(const raw of paths){
        const sourcePath=String(raw||"").replace(/\\/g,"/").slice(0,600);
        if(!sourcePath)continue;
        const filename=sourcePath.split("/").pop()||"image";
        await env.DB.prepare(`
          INSERT OR IGNORE INTO landing_slides(
            id,source_kind,source_path,portfolio_id,filename,enabled,sort_order,duration_ms,created_at,updated_at
          )
          VALUES(?1,'static',?2,NULL,?3,1,?4,5200,?5,?5)
        `).bind(uid("landing"),sourcePath,filename,order,now).run();
        order+=10;
      }
      return json(request,{ok:true});
    }

    if(url.pathname==="/api/admin/landing-slides/portfolio" && request.method==="POST"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const b=await bodyJson(request),portfolioId=String(b?.portfolio_id||"");
      const item=await env.DB.prepare(`SELECT id,filename FROM portfolio_items WHERE id=?1`).bind(portfolioId).first();
      if(!item)return json(request,{ok:false,error:"Portfolio photo not found"},404);
      const now=new Date().toISOString();
      const max=await env.DB.prepare(`SELECT COALESCE(MAX(sort_order),-10) AS m FROM landing_slides`).first();
      await env.DB.prepare(`
        INSERT OR IGNORE INTO landing_slides(
          id,source_kind,source_path,portfolio_id,filename,enabled,sort_order,duration_ms,created_at,updated_at
        )
        VALUES(?1,'portfolio',NULL,?2,?3,1,?4,5200,?5,?5)
      `).bind(uid("landing"),portfolioId,item.filename,Number(max?.m||-10)+10,now).run();

      await env.DB.prepare(`
        UPDATE landing_slides
        SET enabled=1,updated_at=?1
        WHERE source_kind='portfolio' AND portfolio_id=?2
      `).bind(now,portfolioId).run();

      return json(request,{ok:true});
    }

    const landingItem=url.pathname.match(/^\/api\/admin\/landing-slides\/([^/]+)$/);
    if(landingItem && request.method==="PATCH"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const id=decodeURIComponent(landingItem[1]),b=await bodyJson(request);
      const current=await env.DB.prepare(`SELECT * FROM landing_slides WHERE id=?1`).bind(id).first();
      if(!current)return json(request,{ok:false,error:"Slide not found"},404);
      const enabled=b?.enabled===undefined?current.enabled:(b.enabled?1:0);
      const sortOrder=Number.isFinite(Number(b?.sort_order))?Number(b.sort_order):current.sort_order;
      const duration=Math.max(1000,Math.min(60000,Number.isFinite(Number(b?.duration_ms))?Number(b.duration_ms):current.duration_ms));
      const cropDesktop=b?.crop_desktop===undefined?current.crop_desktop:JSON.stringify(b.crop_desktop);
      const cropMobile=b?.crop_mobile===undefined?current.crop_mobile:JSON.stringify(b.crop_mobile);
      await env.DB.prepare(`
        UPDATE landing_slides
        SET enabled=?1,sort_order=?2,duration_ms=?3,crop_desktop=?4,crop_mobile=?5,updated_at=?6
        WHERE id=?7
      `).bind(enabled,sortOrder,duration,cropDesktop,cropMobile,new Date().toISOString(),id).run();
      return json(request,{ok:true,id});
    }

    // ---------- PUBLIC SEO SETTINGS ----------
    if(url.pathname==="/api/seo" && request.method==="GET"){
      const rows=await env.DB.prepare(`SELECT page_key,published_json,published_at FROM seo_settings`).all();
      const settings={};
      for(const row of rows.results||[]) settings[row.page_key]=parseJson(row.published_json,{});
      return json(request,{ok:true,settings});
    }

    // ---------- ADMIN SEO SETTINGS ----------
    if(url.pathname==="/api/admin/seo" && request.method==="GET"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const rows=await env.DB.prepare(`SELECT page_key,draft_json,published_json,updated_at,published_at FROM seo_settings ORDER BY page_key`).all();
      return json(request,{ok:true,pages:(rows.results||[]).map(x=>({...x,draft:parseJson(x.draft_json,{}),published:parseJson(x.published_json,{})}))});
    }
    const seoMatch=url.pathname.match(/^\/api\/admin\/seo\/([a-z0-9_-]+)$/);
    if(seoMatch && request.method==="PUT"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const pageKey=seoMatch[1],b=await bodyJson(request),now=new Date().toISOString();
      if(!b||typeof b.data!=="object")return json(request,{ok:false,error:"data object required"},400);
      const action=b.action==="publish"?"publish":"draft";
      const current=await env.DB.prepare(`SELECT draft_json,published_json,published_at FROM seo_settings WHERE page_key=?1`).bind(pageKey).first();
      const draftJson=JSON.stringify(b.data),pubJson=action==="publish"?draftJson:(current?.published_json||null),pubAt=action==="publish"?now:(current?.published_at||null);
      await env.DB.prepare(`
        INSERT INTO seo_settings(page_key,draft_json,published_json,updated_at,published_at)
        VALUES(?1,?2,?3,?4,?5)
        ON CONFLICT(page_key) DO UPDATE SET
          draft_json=excluded.draft_json,published_json=excluded.published_json,updated_at=excluded.updated_at,published_at=excluded.published_at
      `).bind(pageKey,draftJson,pubJson,now,pubAt).run();
      return json(request,{ok:true,page_key:pageKey,action});
    }

    // ---------- PUBLIC RECENT SHOOTS ----------
    if(url.pathname==="/api/galleries" && request.method==="GET"){
      const result=await env.DB.prepare(`
        SELECT
          g.id,g.title,g.shoot_date,g.status,g.created_at,
          g.cover_photo_id,g.cover_crop_desktop,g.cover_crop_mobile,
          cp.preview_key AS cover_preview_key
        FROM galleries g
        LEFT JOIN photos cp ON cp.id=g.cover_photo_id AND cp.gallery_id=g.id
        WHERE g.status='published' AND g.archived_at IS NULL
        ORDER BY COALESCE(g.shoot_date,g.created_at) DESC
      `).all();

      const galleries=(result.results||[]).map(g=>({
        ...g,
        cover_crop_desktop:safeJsonParse(g.cover_crop_desktop,null),
        cover_crop_mobile:safeJsonParse(g.cover_crop_mobile,null),
        cover_preview_url:g.cover_preview_key
          ? `/api/preview/${encodeURIComponent(g.cover_preview_key)}`
          : null
      }));

      return json(request,{ok:true,galleries});
    }
    const galleryMatch=url.pathname.match(/^\/api\/galleries\/([^/]+)$/);
    if(galleryMatch && request.method==="GET"){
      const id=decodeURIComponent(galleryMatch[1]);
      const gallery=await env.DB.prepare(`
        SELECT
          g.id,g.title,g.shoot_date,g.status,g.created_at,
          g.cover_photo_id,g.cover_crop_desktop,g.cover_crop_mobile,
          cp.preview_key AS cover_preview_key
        FROM galleries g
        LEFT JOIN photos cp ON cp.id=g.cover_photo_id AND cp.gallery_id=g.id
        WHERE g.id=?1 AND g.status='published' AND g.archived_at IS NULL
      `).bind(id).first();
      if(!gallery)return json(request,{ok:false,error:"Gallery not found"},404);
      gallery.cover_crop_desktop=safeJsonParse(gallery.cover_crop_desktop,null);
      gallery.cover_crop_mobile=safeJsonParse(gallery.cover_crop_mobile,null);
      gallery.cover_preview_url=gallery.cover_preview_key
        ? `/api/preview/${encodeURIComponent(gallery.cover_preview_key)}`
        : null;
      const photos=await env.DB.prepare(`
        SELECT id,filename,preview_key,width,height,sort_order FROM photos
        WHERE gallery_id=?1 ORDER BY sort_order,filename
      `).bind(id).all();
      return json(request,{ok:true,gallery,photos:(photos.results||[]).map(p=>({...p,preview_url:`/api/preview/${encodeURIComponent(p.preview_key)}`}))});
    }


    // ---------- PUBLIC GALLERY SEARCH / MATCHED PHOTO FOCUS ----------
    const galleryPhotoSearch=url.pathname.match(/^\/api\/galleries\/([^/]+)\/search$/);
    if(galleryPhotoSearch && request.method==="GET"){
      const galleryId=decodeURIComponent(galleryPhotoSearch[1]);
      const q=String(url.searchParams.get("q")||"").trim().slice(0,120);

      if(!q)return json(request,{
        ok:true,
        gallery_id:galleryId,
        query:"",
        matched_photo_ids:[],
        matches:[],
        match_count:0
      });

      const gallery=await env.DB.prepare(`
        SELECT id,title,shoot_date
        FROM galleries
        WHERE id=?1 AND status='published' AND archived_at IS NULL
      `).bind(galleryId).first();

      if(!gallery)return json(request,{ok:false,error:"Gallery not found"},404);

      const pattern=`%${q.replace(/[\\%_]/g,m=>"\\"+m)}%`;
      const exact=q.toLowerCase();
      const matchMap=new Map();

      function addMatch(photoId,reason,status="verified"){
        if(!photoId)return;
        const id=String(photoId);
        let item=matchMap.get(id);
        if(!item){
          item={photo_id:id,reasons:[],has_unverified:false};
          matchMap.set(id,item);
        }
        if(reason && !item.reasons.includes(reason))item.reasons.push(reason);
        if(status==="unverified")item.has_unverified=true;
      }

      // General active photo tags.
      const tagRows=await env.DB.prepare(`
        SELECT DISTINCT p.id AS photo_id,t.label,t.tag_type
        FROM photo_tags pt
        JOIN tags t ON t.id=pt.tag_id
        JOIN photos p ON p.id=pt.photo_id
        WHERE p.gallery_id=?1
          AND pt.status='active'
          AND (
            LOWER(t.normalized_label) LIKE LOWER(?2) ESCAPE '\\'
            OR LOWER(t.label) LIKE LOWER(?2) ESCAPE '\\'
          )
        ORDER BY p.sort_order,p.filename,t.label
        LIMIT 600
      `).bind(galleryId,pattern).all();

      for(const r of tagRows.results||[]){
        const kind=r.tag_type
          ? String(r.tag_type)[0].toUpperCase()+String(r.tag_type).slice(1)
          : "Tag";
        addMatch(r.photo_id,`${kind}: ${r.label}`,"verified");
      }

      // Legacy pending person suggestions.
      const pendingPhotoTagRows=await env.DB.prepare(`
        SELECT DISTINCT p.id AS photo_id,t.label
        FROM photo_tags pt
        JOIN tags t ON t.id=pt.tag_id
        JOIN photos p ON p.id=pt.photo_id
        WHERE p.gallery_id=?1
          AND pt.status='pending'
          AND pt.source='user_suggestion'
          AND t.tag_type='person'
          AND (
            LOWER(t.normalized_label) LIKE LOWER(?2) ESCAPE '\\'
            OR LOWER(t.label) LIKE LOWER(?2) ESCAPE '\\'
          )
        ORDER BY p.sort_order,p.filename,t.label
        LIMIT 600
      `).bind(galleryId,pattern).all();

      for(const r of pendingPhotoTagRows.results||[]){
        addMatch(r.photo_id,`Possible Match — Unverified: ${r.label}`,"unverified");
      }

      // Current V15 player-tag suggestions, pending or approved.
      const suggestionRows=await env.DB.prepare(`
        SELECT pts.photo_id,pts.suggested_name,pts.suggested_jersey_number,
               pts.suggested_school,pts.suggested_team,pts.suggested_sport,pts.status
        FROM player_tag_suggestions pts
        WHERE pts.gallery_id=?1
          AND pts.status IN ('pending','approved')
          AND (
            LOWER(pts.normalized_name) LIKE LOWER(?2) ESCAPE '\\'
            OR LOWER(pts.suggested_name) LIKE LOWER(?2) ESCAPE '\\'
            OR LOWER(COALESCE(pts.suggested_jersey_number,'')) LIKE LOWER(?2) ESCAPE '\\'
            OR LOWER(COALESCE(pts.suggested_school,'')) LIKE LOWER(?2) ESCAPE '\\'
            OR LOWER(COALESCE(pts.suggested_team,'')) LIKE LOWER(?2) ESCAPE '\\'
            OR LOWER(COALESCE(pts.suggested_sport,'')) LIKE LOWER(?2) ESCAPE '\\'
          )
        ORDER BY pts.submitted_at DESC
        LIMIT 600
      `).bind(galleryId,pattern).all();

      for(const r of suggestionRows.results||[]){
        const bits=[];
        if(r.suggested_school)bits.push(r.suggested_school);
        if(r.suggested_sport)bits.push(r.suggested_sport);
        if(r.suggested_team && r.suggested_team!==r.suggested_school)bits.push(r.suggested_team);
        if(r.suggested_jersey_number)bits.push(`#${r.suggested_jersey_number}`);
        let reason=r.status==="pending"
          ? `Possible Match — Unverified: ${r.suggested_name}`
          : `Player: ${r.suggested_name}`;
        if(bits.length)reason+=` · ${bits.join(" · ")}`;
        addMatch(r.photo_id,reason,r.status==="pending"?"unverified":"verified");
      }

      // Verified athlete/person identity links.
      const athleteRows=await env.DB.prepare(`
        SELECT DISTINCT ppl.photo_id,ap.player_name,am.sport,am.team,
               COALESCE(ppl.jersey_number,ajn.jersey_number) AS jersey_number
        FROM photo_person_links ppl
        JOIN athlete_profiles ap ON ap.id=ppl.athlete_id
        LEFT JOIN athlete_memberships am ON am.id=ppl.membership_id
        LEFT JOIN athlete_jersey_numbers ajn ON ajn.membership_id=am.id AND ajn.active=1
        WHERE ppl.gallery_id=?1
          AND ap.verification_status='verified'
          AND (
            LOWER(ap.player_name) LIKE LOWER(?2) ESCAPE '\\'
            OR LOWER(COALESCE(am.sport,'')) LIKE LOWER(?2) ESCAPE '\\'
            OR LOWER(COALESCE(am.team,'')) LIKE LOWER(?2) ESCAPE '\\'
            OR LOWER(COALESCE(ppl.jersey_number,'')) LIKE LOWER(?2) ESCAPE '\\'
            OR LOWER(COALESCE(ajn.jersey_number,'')) LIKE LOWER(?2) ESCAPE '\\'
          )
        ORDER BY ap.player_name
        LIMIT 600
      `).bind(galleryId,pattern).all();

      for(const r of athleteRows.results||[]){
        const bits=[];
        if(r.sport)bits.push(r.sport);
        if(r.team)bits.push(r.team);
        if(r.jersey_number)bits.push(`#${r.jersey_number}`);
        let reason=`Player: ${r.player_name}`;
        if(bits.length)reason+=` · ${bits.join(" · ")}`;
        addMatch(r.photo_id,reason,"verified");
      }

      // If the query matches a gallery-level tag, treat every photo as a match
      // because the tag describes the whole shoot rather than one photograph.
      const galleryTag=await env.DB.prepare(`
        SELECT t.label,t.tag_type
        FROM gallery_tags gt
        JOIN tags t ON t.id=gt.tag_id
        WHERE gt.gallery_id=?1
          AND (
            LOWER(t.normalized_label) LIKE LOWER(?2) ESCAPE '\\'
            OR LOWER(t.label) LIKE LOWER(?2) ESCAPE '\\'
          )
        LIMIT 1
      `).bind(galleryId,pattern).first();

      if(galleryTag){
        const photos=await env.DB.prepare(`
          SELECT id FROM photos WHERE gallery_id=?1 ORDER BY sort_order,filename
        `).bind(galleryId).all();
        const kind=galleryTag.tag_type
          ? String(galleryTag.tag_type)[0].toUpperCase()+String(galleryTag.tag_type).slice(1)
          : "Gallery";
        for(const p of photos.results||[]){
          addMatch(p.id,`${kind}: ${galleryTag.label}`,"verified");
        }
      }

      const matches=[...matchMap.values()].map(x=>({
        photo_id:x.photo_id,
        reasons:x.reasons.slice(0,8),
        has_unverified:Boolean(x.has_unverified)
      }));

      return json(request,{
        ok:true,
        gallery_id:galleryId,
        gallery_title:gallery.title,
        query:q,
        matched_photo_ids:matches.map(x=>x.photo_id),
        matches,
        match_count:matches.length
      });
    }


    // ---------- PUBLIC PHOTO PLAYER TAG DISPLAY ----------
    const galleryPlayerTags=url.pathname.match(/^\/api\/galleries\/([^/]+)\/player-tags$/);
    if(galleryPlayerTags && request.method==="GET"){
      const galleryId=decodeURIComponent(galleryPlayerTags[1]);
      const tags=[];

      // Approved identity links.
      const verified=await env.DB.prepare(`
        SELECT ppl.photo_id,ppl.athlete_id,ap.player_name,ppl.jersey_number
        FROM photo_person_links ppl
        JOIN athlete_profiles ap ON ap.id=ppl.athlete_id
        WHERE ppl.gallery_id=?1
        ORDER BY ppl.photo_id,ap.player_name
      `).bind(galleryId).all();

      for(const r of verified.results||[]){
        tags.push({
          photo_id:r.photo_id,player_name:r.player_name,
          jersey_number:r.jersey_number||null,school:null,team:null,sport:null,
          athlete_id:r.athlete_id,status:"verified",source:"verified_identity"
        });
      }

      // Public/admin suggestions. Pending = "Name — Unverified".
      const suggestions=await env.DB.prepare(`
        SELECT photo_id,suggested_name AS player_name,
               suggested_jersey_number AS jersey_number,
               suggested_school AS school,suggested_team AS team,
               suggested_sport AS sport,approved_athlete_id AS athlete_id,status
        FROM player_tag_suggestions
        WHERE gallery_id=?1 AND status IN ('pending','approved')
        ORDER BY photo_id,submitted_at
      `).bind(galleryId).all();

      for(const r of suggestions.results||[]){
        const displayStatus=r.status==="approved"?"verified":"pending";
        const duplicateVerified=displayStatus==="verified" && tags.some(x=>
          x.photo_id===r.photo_id && x.status==="verified" &&
          ((r.athlete_id && x.athlete_id===r.athlete_id) ||
           String(x.player_name||"").trim().toLowerCase()===
           String(r.player_name||"").trim().toLowerCase())
        );
        if(!duplicateVerified)tags.push({...r,status:displayStatus,source:"player_tag_suggestion"});
      }

      return json(request,{ok:true,tags});
    }

    // ---------- PRIVATE/PUBLIC PREVIEW DELIVERY ----------
    if(url.pathname.startsWith("/api/preview/") && request.method==="GET"){
      const key=decodeURIComponent(url.pathname.slice("/api/preview/".length));
      const obj=await env.PREVIEWS.get(key);
      if(!obj)return text(request,"Not found",404);
      const h=cors(request); obj.writeHttpMetadata(h); h.set("ETag",obj.httpEtag); h.set("Cache-Control","public,max-age=86400");
      return new Response(obj.body,{headers:h});
    }


    // ---------- PUBLIC PRICING ----------
    if(url.pathname==="/api/pricing" && request.method==="GET"){
      const row=await env.DB.prepare(`SELECT published_json FROM pricing_settings WHERE id='default'`).first();
      const fallback={
        currency:"USD",
        products:[
          {id:"digital",label:"Digital Download",price:10,requiresShipping:false},
          {id:"print_4x6",label:"4 × 6 Print",price:8,requiresShipping:true},
          {id:"print_5x7",label:"5 × 7 Print",price:12,requiresShipping:true},
          {id:"print_8x10",label:"8 × 10 Print",price:20,requiresShipping:true},
          {id:"print_11x14",label:"11 × 14 Print",price:32,requiresShipping:true}
        ],
        packages:[
          {quantity:3,price:25,label:"Any 3 Digitals"},
          {type:"player_all",price:35,label:"All Photos of One Player",exclude_team_photos:true}
        ]
      };
      const pricing=parseJson(row?.published_json,fallback)||fallback;
      pricing.products=Array.isArray(pricing.products)?pricing.products:[...fallback.products];
      const digital=pricing.products.find(p=>p.id==="digital");
      if(digital){digital.price=10;digital.label="Digital Download";digital.requiresShipping=false}
      else pricing.products.unshift({id:"digital",label:"Digital Download",price:10,requiresShipping:false});
      pricing.packages=[
        {quantity:3,price:25,label:"Any 3 Digitals"},
        {type:"player_all",price:35,label:"All Photos of One Player",exclude_team_photos:true}
      ];
      return json(request,{ok:true,pricing});
    }

    // ---------- ADMIN PRICING ----------
    if(url.pathname==="/api/admin/pricing" && request.method==="GET"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const row=await env.DB.prepare(`SELECT published_json,updated_at FROM pricing_settings WHERE id='default'`).first();
      return json(request,{ok:true,pricing:parseJson(row?.published_json,null),updated_at:row?.updated_at||null});
    }
    if(url.pathname==="/api/admin/pricing" && request.method==="PUT"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const b=await bodyJson(request);
      if(!b?.pricing || !Array.isArray(b.pricing.products) || !Array.isArray(b.pricing.packages))
        return json(request,{ok:false,error:"Invalid pricing payload"},400);
      const now=new Date().toISOString();
      await env.DB.prepare(`
        INSERT INTO pricing_settings(id,published_json,updated_at)
        VALUES('default',?1,?2)
        ON CONFLICT(id) DO UPDATE SET published_json=excluded.published_json,updated_at=excluded.updated_at
      `).bind(JSON.stringify(b.pricing),now).run();
      return json(request,{ok:true,updated_at:now});
    }

    // ---------- ADMIN SITE CONTENT ----------
    if(url.pathname==="/api/admin/site-content" && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const rows=await env.DB.prepare(`SELECT section,draft_json,published_json,updated_at,published_at FROM site_content ORDER BY section`).all();
      return json(request,{ok:true,sections:(rows.results||[]).map(x=>({...x,draft:parseJson(x.draft_json,{}),published:parseJson(x.published_json,{})}))});
    }
    const contentMatch=url.pathname.match(/^\/api\/admin\/site-content\/(about|contact)$/);
    if(contentMatch && request.method==="PUT"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const section=contentMatch[1], b=await bodyJson(request), now=new Date().toISOString();
      if(!b || typeof b.data!=="object")return json(request,{ok:false,error:"data object required"},400);
      const action=b.action==="publish"?"publish":"draft";
      const current=await env.DB.prepare(`SELECT section,draft_json,published_json,published_at FROM site_content WHERE section=?1`).bind(section).first();
      const draftJson=JSON.stringify(b.data);
      const pubJson=action==="publish"?draftJson:(current?.published_json||null);
      const pubAt=action==="publish"?now:(current?.published_at||null);
      await env.DB.prepare(`
        INSERT INTO site_content(section,draft_json,published_json,updated_at,published_at)
        VALUES(?1,?2,?3,?4,?5)
        ON CONFLICT(section) DO UPDATE SET
          draft_json=excluded.draft_json,
          published_json=excluded.published_json,
          updated_at=excluded.updated_at,
          published_at=excluded.published_at
      `).bind(section,draftJson,pubJson,now,pubAt).run();
      return json(request,{ok:true,section,action});
    }


    // ---------- ADMIN REELS ----------
    if(url.pathname==="/api/admin/reels" && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const rows=await env.DB.prepare(`
        SELECT r.*,g.title AS related_gallery_title
        FROM reels r LEFT JOIN galleries g ON g.id=r.related_gallery_id
        ORDER BY r.sort_order,r.created_at
      `).all();
      return json(request,{ok:true,reels:(rows.results||[]).map(x=>({...x,
        video_url:`/api/reels/media/${encodeURIComponent(x.id)}`,
        poster_url:x.poster_key?`/api/preview/${encodeURIComponent(x.poster_key)}`:null
      }))});
    }

    const reelVideo=url.pathname.match(/^\/api\/admin\/reels\/([^/]+)\/video\/(.+)$/);
    if(reelVideo && request.method==="PUT"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const id=safePart(decodeURIComponent(reelVideo[1]));
      const filename=safePart(decodeURIComponent(reelVideo[2]));
      const contentType=request.headers.get("Content-Type")||"video/mp4";
      if(!["video/mp4","video/webm"].includes(contentType))
        return json(request,{ok:false,error:"Reels currently support MP4 or WebM video"},400);
      const key=`reels/video/${id}/${filename}`;
      await env.ORIGINALS.put(key,request.body,{httpMetadata:{contentType,cacheControl:"public, max-age=3600"}});
      return json(request,{ok:true,key});
    }

    const reelPoster=url.pathname.match(/^\/api\/admin\/reels\/([^/]+)\/poster\/(.+)$/);
    if(reelPoster && request.method==="PUT"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const id=safePart(decodeURIComponent(reelPoster[1]));
      const filename=safePart(decodeURIComponent(reelPoster[2]));
      const key=`reels/posters/${id}/${filename}`;
      await env.PREVIEWS.put(key,request.body,{httpMetadata:{contentType:request.headers.get("Content-Type")||"image/jpeg"}});
      return json(request,{ok:true,key});
    }

    if(url.pathname==="/api/admin/reels" && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const b=await bodyJson(request);
      if(!b?.id || !b?.filename || !b?.video_key)
        return json(request,{ok:false,error:"id, filename and video_key required"},400);
      const now=new Date().toISOString();
      const status=b.status==="hidden"?"hidden":"active";
      await env.DB.prepare(`
        INSERT INTO reels(
          id,title,filename,video_key,poster_key,status,sort_order,caption,sport,team,event_label,
          related_gallery_id,featured,created_at,updated_at
        ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?14)
      `).bind(
        b.id,String(b.title||"").slice(0,200)||null,b.filename,b.video_key,b.poster_key||null,status,
        Number.isFinite(Number(b.sort_order))?Number(b.sort_order):0,
        String(b.caption||"").slice(0,1500)||null,String(b.sport||"").slice(0,120)||null,
        String(b.team||"").slice(0,200)||null,String(b.event_label||"").slice(0,250)||null,
        b.related_gallery_id||null,b.featured?1:0,now
      ).run();
      return json(request,{ok:true,id:b.id},201);
    }

    const reelItem=url.pathname.match(/^\/api\/admin\/reels\/([^/]+)$/);
    if(reelItem && request.method==="PATCH"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const id=decodeURIComponent(reelItem[1]);
      const b=await bodyJson(request);
      const cur=await env.DB.prepare(`SELECT * FROM reels WHERE id=?1`).bind(id).first();
      if(!cur)return json(request,{ok:false,error:"Reel not found"},404);
      const status=b?.status===undefined?cur.status:(b.status==="hidden"?"hidden":"active");
      const sortOrder=Number.isFinite(Number(b?.sort_order))?Number(b.sort_order):cur.sort_order;
      const title=b?.title===undefined?cur.title:String(b.title||"").slice(0,200);
      const caption=b?.caption===undefined?cur.caption:String(b.caption||"").slice(0,1500);
      const sport=b?.sport===undefined?cur.sport:String(b.sport||"").slice(0,120);
      const team=b?.team===undefined?cur.team:String(b.team||"").slice(0,200);
      const eventLabel=b?.event_label===undefined?cur.event_label:String(b.event_label||"").slice(0,250);
      const related=b?.related_gallery_id===undefined?cur.related_gallery_id:(b.related_gallery_id||null);
      const featured=b?.featured===undefined?cur.featured:(b.featured?1:0);
      await env.DB.prepare(`
        UPDATE reels SET title=?1,status=?2,sort_order=?3,caption=?4,sport=?5,team=?6,event_label=?7,
          related_gallery_id=?8,featured=?9,updated_at=?10 WHERE id=?11
      `).bind(title,status,sortOrder,caption,sport,team,eventLabel,related,featured,new Date().toISOString(),id).run();
      return json(request,{ok:true,id});
    }

    if(reelItem && request.method==="DELETE"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const id=decodeURIComponent(reelItem[1]);
      const b=await bodyJson(request);
      if(b?.confirm!=="DELETE")return json(request,{ok:false,error:'Permanent deletion requires confirm: "DELETE"'},400);
      const cur=await env.DB.prepare(`SELECT video_key,poster_key FROM reels WHERE id=?1`).bind(id).first();
      if(!cur)return json(request,{ok:false,error:"Reel not found"},404);
      const keys=[cur.video_key,cur.poster_key].filter(Boolean);
      if(keys.length)await Promise.all(keys.map((k,i)=>i===0?env.ORIGINALS.delete(k):env.PREVIEWS.delete(k)));
      await env.DB.prepare(`DELETE FROM reels WHERE id=?1`).bind(id).run();
      return json(request,{ok:true,id,deleted:true});
    }







    // ---------- PUBLIC ROSTER AUTOCOMPLETE ----------
    if(url.pathname==="/api/roster-player-suggestions" && request.method==="GET"){
      const q=cleanRosterField(url.searchParams.get("q"),100);
      const galleryId=cleanRosterField(url.searchParams.get("gallery_id"),100);
      if(q.length<1)return json(request,{ok:true,suggestions:[]});

      const like=`%${q}%`;
      const exact=q.toLowerCase();
      const out=[];

      // 1) Reusable roster entries. Current-gallery rosters rank first.
      const rosterRows=await env.DB.prepare(`
        SELECT rp.id,rp.roster_id,rp.display_name,rp.first_name,rp.last_name,
               rp.jersey_number,
               COALESCE(NULLIF(rp.school,''),r.school) AS school,
               COALESCE(NULLIF(rp.team,''),r.team) AS team,
               COALESCE(NULLIF(rp.sport,''),r.sport) AS sport,
               COALESCE(NULLIF(rp.season,''),r.season) AS season,
               rp.athlete_id,r.name AS roster_name,
               CASE WHEN gr.gallery_id IS NOT NULL THEN 1 ELSE 0 END AS current_gallery_roster
        FROM roster_players rp
        JOIN rosters r ON r.id=rp.roster_id
        LEFT JOIN gallery_rosters gr
          ON gr.roster_id=rp.roster_id AND gr.gallery_id=?1
        WHERE rp.status='active' AND r.status='active'
          AND (
            LOWER(rp.display_name) LIKE LOWER(?2)
            OR LOWER(rp.normalized_name) LIKE LOWER(?2)
            OR LOWER(COALESCE(rp.jersey_number,'')) LIKE LOWER(?2)
            OR LOWER(COALESCE(rp.school,r.school,'')) LIKE LOWER(?2)
            OR LOWER(COALESCE(rp.team,r.team,'')) LIKE LOWER(?2)
            OR LOWER(COALESCE(rp.sport,r.sport,'')) LIKE LOWER(?2)
          )
        ORDER BY current_gallery_roster DESC,
                 CASE
                   WHEN LOWER(rp.display_name)=?3 THEN 0
                   WHEN LOWER(COALESCE(rp.jersey_number,''))=?3 THEN 1
                   ELSE 2
                 END,
                 rp.display_name
        LIMIT 50
      `).bind(galleryId,like,exact).all();

      for(const r of rosterRows.results||[]){
        out.push({
          id:r.id,roster_id:r.roster_id,roster_name:r.roster_name,
          display_name:r.display_name,first_name:r.first_name,last_name:r.last_name,
          jersey_number:r.jersey_number||null,school:r.school||null,team:r.team||null,
          sport:r.sport||null,season:r.season||null,athlete_id:r.athlete_id||null,
          athlete_verification_status:null,
          current_gallery_roster:Boolean(r.current_gallery_roster),
          source:"roster"
        });
      }

      // 2) Athlete/person records already created in Admin.
      // Do NOT require verification here. A pending athlete is still a useful
      // tagging suggestion; using the suggestion grants no download privileges.
      const athleteRows=await env.DB.prepare(`
        SELECT ap.id AS athlete_id,ap.player_name,ap.verification_status,
               am.id AS membership_id,am.sport,am.team,ajn.jersey_number
        FROM athlete_profiles ap
        LEFT JOIN athlete_memberships am
          ON am.athlete_id=ap.id AND am.active=1
        LEFT JOIN athlete_jersey_numbers ajn
          ON ajn.membership_id=am.id AND ajn.active=1
        WHERE COALESCE(ap.verification_status,'')<>'rejected'
          AND (
            LOWER(ap.player_name) LIKE LOWER(?1)
            OR LOWER(COALESCE(am.team,'')) LIKE LOWER(?1)
            OR LOWER(COALESCE(am.sport,'')) LIKE LOWER(?1)
            OR LOWER(COALESCE(ajn.jersey_number,'')) LIKE LOWER(?1)
          )
        ORDER BY
          CASE
            WHEN LOWER(ap.player_name)=?2 THEN 0
            WHEN LOWER(COALESCE(ajn.jersey_number,''))=?2 THEN 1
            ELSE 2
          END,
          ap.player_name,COALESCE(am.sport,''),COALESCE(ajn.jersey_number,'')
        LIMIT 50
      `).bind(like,exact).all();

      for(const r of athleteRows.results||[]){
        const dup=out.some(x=>x.athlete_id===r.athlete_id &&
          String(x.sport||"")===String(r.sport||"") &&
          String(x.jersey_number||"")===String(r.jersey_number||""));
        if(dup)continue;
        out.push({
          id:null,roster_id:null,roster_name:null,
          display_name:r.player_name,first_name:null,last_name:null,
          jersey_number:r.jersey_number||null,school:null,team:r.team||null,
          sport:r.sport||null,season:null,athlete_id:r.athlete_id,
          athlete_verification_status:r.verification_status,
          current_gallery_roster:false,source:"athlete"
        });
      }

      return json(request,{
        ok:true,query:q,gallery_id:galleryId||null,
        suggestions:out.slice(0,50)
      });
    }

    // ---------- PUBLIC V15.4 RELIABLE GALLERY-LEVEL PLAYER TAG SUBMISSION ----------
    const galleryPlayerTagSubmit=url.pathname.match(/^\/api\/galleries\/([^/]+)\/player-tags$/);
    if(galleryPlayerTagSubmit && request.method==="POST"){
      try{
        const galleryId=decodeURIComponent(galleryPlayerTagSubmit[1]);
        const b=await bodyJson(request)||{};
        const photoIds=Array.isArray(b.photo_ids)
          ? [...new Set(b.photo_ids.map(x=>cleanRosterField(x,120)).filter(Boolean))]
          : [];

        if(photoIds.length<1)
          return json(request,{ok:false,error:"Select at least one photo."},400);
        if(photoIds.length>250)
          return json(request,{ok:false,error:"Too many photos selected at once."},400);

        const rosterPlayerId=cleanRosterField(b.roster_player_id,100)||null;
        const selectedAthleteId=cleanRosterField(b.athlete_id,100)||null;
        const enteredName=cleanRosterField(b.player_name,100);
        const enteredJersey=cleanRosterField(b.jersey_number,30)||null;

        const gallery=await env.DB.prepare(`
          SELECT id,title FROM galleries WHERE id=?1
        `).bind(galleryId).first();
        if(!gallery)return json(request,{ok:false,error:"Gallery not found"},404);

        // Validate each photo individually. This is intentionally simple and robust.
        const validIds=[];
        for(const photoId of photoIds){
          const row=await env.DB.prepare(`
            SELECT id FROM photos WHERE id=?1 AND gallery_id=?2
          `).bind(photoId,galleryId).first();
          if(!row){
            return json(request,{
              ok:false,
              error:`Photo ${photoId} is not part of this gallery. Refresh and try again.`,
              code:"PHOTO_GALLERY_MISMATCH"
            },400);
          }
          validIds.push(String(row.id));
        }

        let rosterPlayer=null;
        if(rosterPlayerId){
          rosterPlayer=await env.DB.prepare(`
            SELECT rp.*,
                   COALESCE(NULLIF(rp.school,''),r.school) AS effective_school,
                   COALESCE(NULLIF(rp.team,''),r.team) AS effective_team,
                   COALESCE(NULLIF(rp.sport,''),r.sport) AS effective_sport
            FROM roster_players rp
            JOIN rosters r ON r.id=rp.roster_id
            WHERE rp.id=?1 AND rp.status='active' AND r.status='active'
          `).bind(rosterPlayerId).first();
          if(!rosterPlayer)return json(request,{ok:false,error:"Roster player not found"},404);
        }

        let selectedAthlete=null;
        if(selectedAthleteId){
          selectedAthlete=await env.DB.prepare(`
            SELECT id,player_name,verification_status
            FROM athlete_profiles
            WHERE id=?1 AND COALESCE(verification_status,'')<>'rejected'
          `).bind(selectedAthleteId).first();
          if(!selectedAthlete)return json(request,{ok:false,error:"Player record not found"},404);
        }

        const suggestedName=cleanRosterField(
          rosterPlayer?.display_name||selectedAthlete?.player_name||enteredName,100
        );
        if(suggestedName.length<2)
          return json(request,{ok:false,error:"Enter or select a player's name."},400);

        const jersey=rosterPlayer?.jersey_number||enteredJersey||null;
        const school=rosterPlayer?.effective_school||null;
        const team=rosterPlayer?.effective_team||null;
        const sport=rosterPlayer?.effective_sport||null;
        const normalized=normalizePersonTagLabel(suggestedName).toLowerCase();
        const now=new Date().toISOString();

        // Session lookup is optional for public tagging.
        let submittedByUserId=null;
        try{
          const session=await currentSession(request,env);
          submittedByUserId=session?.user_id||null;
        }catch(_){}

        let savedCount=0;
        let alreadyCount=0;
        const savedPhotoIds=[];

        for(const photoId of validIds){
          const existing=await env.DB.prepare(`
            SELECT id,status
            FROM player_tag_suggestions
            WHERE photo_id=?1
              AND normalized_name=?2
              AND status IN ('pending','approved')
            ORDER BY submitted_at DESC
            LIMIT 1
          `).bind(photoId,normalized).first();

          if(existing){
            alreadyCount++;
            continue;
          }

          const suggestionId=`pts-${crypto.randomUUID()}`;

          await env.DB.prepare(`
            INSERT INTO player_tag_suggestions(
              id,photo_id,gallery_id,roster_player_id,
              suggested_name,suggested_jersey_number,suggested_school,
              suggested_team,suggested_sport,normalized_name,status,
              submitted_by_user_id,approved_athlete_id,submitted_at,reviewed_at,reviewed_by
            ) VALUES(
              ?1,?2,?3,?4,
              ?5,?6,?7,?8,?9,?10,'pending',
              ?11,NULL,?12,NULL,NULL
            )
          `).bind(
            suggestionId,photoId,galleryId,rosterPlayer?.id||null,
            suggestedName,jersey,school,team,sport,normalized,
            submittedByUserId,now
          ).run();

          savedCount++;
          savedPhotoIds.push(photoId);

          // Activity logging is deliberately non-blocking.
          try{
            await logActivity(env,{
              eventType:"player_tag_suggested",
              userId:submittedByUserId,
              galleryId,
              photoId,
              athleteId:rosterPlayer?.athlete_id||selectedAthlete?.id||null,
              metadata:{
                suggestion_id:suggestionId,
                roster_player_id:rosterPlayer?.id||null,
                selected_athlete_id:selectedAthlete?.id||null,
                player_name:suggestedName,
                jersey_number:jersey,
                school,team,sport
              }
            });
          }catch(_){}
        }

        return json(request,{
          ok:true,
          status:"pending",
          player_name:suggestedName,
          requested_count:validIds.length,
          saved_count:savedCount,
          already_tagged_count:alreadyCount,
          photo_ids:validIds,
          saved_photo_ids:savedPhotoIds,
          message:"Player tag submitted as unverified until approved."
        },201);

      }catch(e){
        console.error("V15.5 player tag save error",e);
        const detail=String(e?.message||e||"Unknown Worker error").slice(0,800);
        return json(request,{
          ok:false,
          error:`Player tag save failed: ${detail}`,
          detail,
          code:"PLAYER_TAG_SAVE_ERROR"
        },500);
      }
    }

    // ---------- PUBLIC V15 PLAYER TAG SUBMISSIONS ----------
    const publicRosterTagRoute=url.pathname.match(/^\/api\/photos\/([^/]+)\/player-tags$/);
    if(publicRosterTagRoute && request.method==="POST"){
      const photoId=decodeURIComponent(publicRosterTagRoute[1]);
      const b=await bodyJson(request)||{};
      const rosterPlayerId=cleanRosterField(b.roster_player_id,100)||null;
      const selectedAthleteId=cleanRosterField(b.athlete_id,100)||null;
      const enteredName=cleanRosterField(b.player_name,100);
      const enteredJersey=cleanRosterField(b.jersey_number,30)||null;

      const photo=await env.DB.prepare(`
        SELECT p.id,p.gallery_id,g.title AS gallery_title
        FROM photos p JOIN galleries g ON g.id=p.gallery_id
        WHERE p.id=?1
      `).bind(photoId).first();
      if(!photo)return json(request,{ok:false,error:"Photo not found"},404);

      let rosterPlayer=null;
      if(rosterPlayerId){
        rosterPlayer=await env.DB.prepare(`
          SELECT rp.*,
                 COALESCE(NULLIF(rp.school,''),r.school) AS effective_school,
                 COALESCE(NULLIF(rp.team,''),r.team) AS effective_team,
                 COALESCE(NULLIF(rp.sport,''),r.sport) AS effective_sport
          FROM roster_players rp
          JOIN rosters r ON r.id=rp.roster_id
          WHERE rp.id=?1 AND rp.status='active' AND r.status='active'
        `).bind(rosterPlayerId).first();
        if(!rosterPlayer)return json(request,{ok:false,error:"Roster player not found"},404);
      }

      let selectedAthlete=null;
      if(selectedAthleteId){
        selectedAthlete=await env.DB.prepare(`
          SELECT id,player_name,verification_status
          FROM athlete_profiles
          WHERE id=?1 AND COALESCE(verification_status,'')<>'rejected'
        `).bind(selectedAthleteId).first();
        if(!selectedAthlete)return json(request,{ok:false,error:"Player record not found"},404);
      }

      const suggestedName=cleanRosterField(
        rosterPlayer?.display_name||selectedAthlete?.player_name||enteredName,100
      );
      if(suggestedName.length<2)
        return json(request,{ok:false,error:"Enter or select a player's name."},400);

      const jersey=rosterPlayer?.jersey_number||enteredJersey||null;
      const school=rosterPlayer?.effective_school||null;
      const team=rosterPlayer?.effective_team||null;
      const sport=rosterPlayer?.effective_sport||null;
      const normalized=normalizePersonTagLabel(suggestedName).toLowerCase();

      // Don't create duplicate pending/approved labels for the same player/photo.
      const existing=await env.DB.prepare(`
        SELECT id,status FROM player_tag_suggestions
        WHERE photo_id=?1
          AND normalized_name=?2
          AND status IN ('pending','approved')
        ORDER BY submitted_at DESC
        LIMIT 1
      `).bind(photoId,normalized).first();

      if(existing){
        return json(request,{
          ok:true,id:existing.id,status:existing.status,already_exists:true,
          message:existing.status==="approved"
            ?"That player is already approved on this photo."
            :"That player is already shown as unverified on this photo."
        });
      }

      const session=await currentSession(request,env).catch(()=>null);
      const now=new Date().toISOString();
      const id=`pts-${crypto.randomUUID()}`;

      await env.DB.prepare(`
        INSERT INTO player_tag_suggestions(
          id,photo_id,gallery_id,roster_player_id,
          suggested_name,suggested_jersey_number,suggested_school,
          suggested_team,suggested_sport,normalized_name,status,
          submitted_by_user_id,approved_athlete_id,submitted_at,reviewed_at,reviewed_by
        ) VALUES(
          ?1,?2,?3,?4,
          ?5,?6,?7,?8,?9,?10,'pending',
          ?11,NULL,?12,NULL,NULL
        )
      `).bind(
        id,photoId,photo.gallery_id,rosterPlayer?.id||null,
        suggestedName,jersey,school,team,sport,normalized,
        session?.user_id||null,now
      ).run();

      let activityId=null;
      try{
        activityId=await logActivity(env,{
          eventType:"player_tag_suggested",
          userId:session?.user_id||null,
          galleryId:photo.gallery_id,
          photoId,
          athleteId:rosterPlayer?.athlete_id||selectedAthlete?.id||null,
          metadata:{
            suggestion_id:id,
            roster_player_id:rosterPlayer?.id||null,
            selected_athlete_id:selectedAthlete?.id||null,
            player_name:suggestedName,
            jersey_number:jersey,school,team,sport
          }
        });
      }catch(_){}

      // Admin notification batching is best-effort; it must never make the public
      // tag submission look like it failed after the D1 insert succeeded.
      try{
        const settings=await env.DB.prepare(`
          SELECT pending_claim_alerts FROM admin_notification_settings WHERE id=1
        `).first();
        if(settings?.pending_claim_alerts && activityId){
          await queueAdminEmailBatch(env,{
            batchType:"pending_claims",
            batchKey:`${photo.gallery_id}:${dateKeyUTC(now)}`,
            activityId,eventAt:now
          });
        }
      }catch(_){}

      return json(request,{
        ok:true,id,status:"pending",
        player_name:suggestedName,
        message:"Player tag submitted as unverified until approved."
      },201);
    }

    // ---------- PUBLIC PLAYER TAG SUGGESTIONS ----------
    const publicTagSuggestionRoute=url.pathname.match(/^\/api\/photos\/([^/]+)\/player-tag-suggestions$/);
    if(publicTagSuggestionRoute && request.method==="POST"){
      const photoId=decodeURIComponent(publicTagSuggestionRoute[1]);
      const b=await bodyJson(request);
      const playerName=normalizePersonTagLabel(b?.player_name);
      if(playerName.length<2)
        return json(request,{ok:false,error:"Enter the player's name."},400);

      const photo=await env.DB.prepare(`
        SELECT p.id,p.gallery_id,g.title AS gallery_title
        FROM photos p JOIN galleries g ON g.id=p.gallery_id
        WHERE p.id=?1
      `).bind(photoId).first();
      if(!photo)return json(request,{ok:false,error:"Photo not found"},404);

      const normalized=normalizePersonTagLabel(playerName).toLowerCase();
      let tag=await env.DB.prepare(`
        SELECT id,label,normalized_label,tag_type FROM tags
        WHERE tag_type='person' AND normalized_label=?1
        LIMIT 1
      `).bind(normalized).first();

      const now=new Date().toISOString();
      if(!tag){
        const tagId=`tag-${crypto.randomUUID()}`;
        await env.DB.prepare(`
          INSERT INTO tags(id,label,normalized_label,tag_type,created_at,updated_at)
          VALUES(?1,?2,?3,'person',?4,?4)
        `).bind(tagId,playerName,normalized,now).run();
        tag={id:tagId,label:playerName,normalized_label:normalized,tag_type:"person"};
      }

      const existing=await env.DB.prepare(`
        SELECT id,status,source FROM photo_tags
        WHERE photo_id=?1 AND tag_id=?2
        LIMIT 1
      `).bind(photoId,tag.id).first();

      if(existing){
        if(existing.status==="active")
          return json(request,{ok:true,already_exists:true,status:"active",message:"That player tag is already verified on this photo."});
        if(existing.status==="pending")
          return json(request,{ok:true,already_exists:true,status:"pending",message:"That player tag is already awaiting approval."});
        await env.DB.prepare(`
          UPDATE photo_tags
          SET status='pending',source='user_suggestion',reviewed_at=NULL,reviewed_by=NULL
          WHERE id=?1
        `).bind(existing.id).run();
        await logActivity(env,{
          eventType:"player_tag_suggested",galleryId:photo.gallery_id,photoId,
          metadata:{photo_tag_id:existing.id,player_name:playerName,resubmitted:true}
        });
        return json(request,{ok:true,id:existing.id,status:"pending",message:"Possible player match submitted for approval."});
      }

      const id=`ptag-${crypto.randomUUID()}`;
      await env.DB.prepare(`
        INSERT INTO photo_tags(
          id,photo_id,gallery_id,tag_id,source,status,created_at,created_by,reviewed_at,reviewed_by
        ) VALUES(?1,?2,?3,?4,'user_suggestion','pending',?5,NULL,NULL,NULL)
      `).bind(id,photoId,photo.gallery_id,tag.id,now).run();

      const activityId=await logActivity(env,{
        eventType:"player_tag_suggested",galleryId:photo.gallery_id,photoId,
        metadata:{photo_tag_id:id,player_name:playerName}
      });

      const settings=await env.DB.prepare(`
        SELECT pending_claim_alerts FROM admin_notification_settings WHERE id=1
      `).first();
      if(settings?.pending_claim_alerts){
        await queueAdminEmailBatch(env,{
          batchType:"pending_claims",
          batchKey:`${photo.gallery_id}:${dateKeyUTC(now)}`,
          activityId,eventAt:now
        });
      }

      return json(request,{
        ok:true,id,status:"pending",
        message:"Possible player match submitted. It will remain unverified until the player or administrator approves it."
      },201);
    }

    if(publicTagSuggestionRoute && request.method==="GET"){
      const photoId=decodeURIComponent(publicTagSuggestionRoute[1]);
      const rows=await env.DB.prepare(`
        SELECT pt.id,pt.status,t.label AS player_name,pt.created_at
        FROM photo_tags pt
        JOIN tags t ON t.id=pt.tag_id
        WHERE pt.photo_id=?1 AND t.tag_type='person'
          AND pt.source='user_suggestion'
          AND pt.status IN ('pending','active')
        ORDER BY pt.created_at DESC
        LIMIT 50
      `).bind(photoId).all();
      return json(request,{ok:true,suggestions:rows.results||[]});
    }

    // ---------- PUBLIC FIND-A-SHOOT SEARCH ----------
    if(url.pathname==="/api/find-shoots" && request.method==="GET"){
      const q=String(url.searchParams.get("q")||"").trim().slice(0,120);
      const date=String(url.searchParams.get("date")||"").trim().slice(0,20);
      const normalized=q.toLowerCase();
      const pattern=`%${q.replace(/[\\%_]/g,m=>"\\"+m)}%`;
      const resultMap=new Map();

      function addResult(row, reason, matchedPhotoId=null, previewKey=null){
        if(!row?.gallery_id)return;
        let item=resultMap.get(row.gallery_id);
        if(!item){
          item={
            id:row.gallery_id,
            title:row.gallery_title||"Untitled Shoot",
            shoot_date:row.shoot_date||null,
            match_reasons:[],
            matched_photo_ids:new Set(),
            preview_key:previewKey||null
          };
          resultMap.set(row.gallery_id,item);
        }
        if(reason && !item.match_reasons.includes(reason))item.match_reasons.push(reason);
        if(matchedPhotoId)item.matched_photo_ids.add(matchedPhotoId);
        if(!item.preview_key && previewKey)item.preview_key=previewKey;
      }

      // Shoot title/date match.
      const galleryRows=await env.DB.prepare(`
        SELECT g.id AS gallery_id,g.title AS gallery_title,g.shoot_date,
               p.id AS photo_id,p.preview_key
        FROM galleries g
        LEFT JOIN photos p ON p.id=(
          SELECT p2.id FROM photos p2
          WHERE p2.gallery_id=g.id
          ORDER BY p2.sort_order,p2.filename
          LIMIT 1
        )
        WHERE (?1='' OR g.title LIKE ?2 ESCAPE '\\' COLLATE NOCASE)
          AND (?3='' OR g.shoot_date=?3)
        ORDER BY COALESCE(g.shoot_date,g.created_at) DESC
        LIMIT 200
      `).bind(q,pattern,date).all();

      for(const r of galleryRows.results||[]){
        addResult(r,q?`Event: ${r.gallery_title}`:"Event",r.photo_id,r.preview_key);
      }

      if(q){
        // General photo tags: person, product, team, sport, event, location, subject, custom.
        const tagRows=await env.DB.prepare(`
          SELECT DISTINCT p.gallery_id,g.title AS gallery_title,g.shoot_date,
                 p.id AS photo_id,p.preview_key,t.label,t.tag_type
          FROM photo_tags pt
          JOIN tags t ON t.id=pt.tag_id
          JOIN photos p ON p.id=pt.photo_id
          JOIN galleries g ON g.id=p.gallery_id
          WHERE pt.status='active'
            AND t.normalized_label LIKE LOWER(?1) ESCAPE '\\'
            AND (?2='' OR g.shoot_date=?2)
          ORDER BY COALESCE(g.shoot_date,g.created_at) DESC,p.sort_order
          LIMIT 300
        `).bind(pattern,date).all();

        for(const r of tagRows.results||[]){
          const label=r.tag_type?`${String(r.tag_type)[0].toUpperCase()+String(r.tag_type).slice(1)}: ${r.label}`:`Tag: ${r.label}`;
          addResult(r,label,r.photo_id,r.preview_key);
        }

        // Pending public player-name suggestions remain searchable as possible matches.
        const pendingPersonRows=await env.DB.prepare(`
          SELECT DISTINCT p.gallery_id,g.title AS gallery_title,g.shoot_date,
                 p.id AS photo_id,p.preview_key,t.label
          FROM photo_tags pt
          JOIN tags t ON t.id=pt.tag_id
          JOIN photos p ON p.id=pt.photo_id
          JOIN galleries g ON g.id=p.gallery_id
          WHERE pt.status='pending'
            AND pt.source='user_suggestion'
            AND t.tag_type='person'
            AND t.normalized_label LIKE LOWER(?1) ESCAPE '\\'
            AND (?2='' OR g.shoot_date=?2)
          ORDER BY COALESCE(g.shoot_date,g.created_at) DESC,p.sort_order
          LIMIT 300
        `).bind(pattern,date).all();

        for(const r of pendingPersonRows.results||[]){
          addResult(r,`Possible Match — Unverified: ${r.label}`,r.photo_id,r.preview_key);
        }


        // Roster players / school / team / sport / jersey.
        const rosterRows=await env.DB.prepare(`
          SELECT DISTINCT g.id AS gallery_id,g.title AS gallery_title,g.shoot_date,
                 rp.display_name,rp.jersey_number,
                 COALESCE(NULLIF(rp.school,''),r.school) AS school,
                 COALESCE(NULLIF(rp.team,''),r.team) AS team,
                 COALESCE(NULLIF(rp.sport,''),r.sport) AS sport,
                 p.id AS photo_id,p.preview_key
          FROM gallery_rosters gr
          JOIN rosters r ON r.id=gr.roster_id
          JOIN roster_players rp ON rp.roster_id=r.id
          JOIN galleries g ON g.id=gr.gallery_id
          LEFT JOIN photos p ON p.id=(
            SELECT p2.id FROM photos p2
            WHERE p2.gallery_id=g.id
            ORDER BY p2.sort_order,p2.filename
            LIMIT 1
          )
          WHERE r.status='active' AND rp.status='active'
            AND (
              LOWER(rp.normalized_name) LIKE LOWER(?1) ESCAPE '\\'
              OR LOWER(rp.display_name) LIKE LOWER(?1) ESCAPE '\\'
              OR LOWER(COALESCE(rp.jersey_number,'')) LIKE LOWER(?1) ESCAPE '\\'
              OR LOWER(COALESCE(rp.school,r.school,'')) LIKE LOWER(?1) ESCAPE '\\'
              OR LOWER(COALESCE(rp.team,r.team,'')) LIKE LOWER(?1) ESCAPE '\\'
              OR LOWER(COALESCE(rp.sport,r.sport,'')) LIKE LOWER(?1) ESCAPE '\\'
            )
            AND (?2='' OR g.shoot_date=?2)
          ORDER BY COALESCE(g.shoot_date,g.created_at) DESC
          LIMIT 400
        `).bind(pattern,date).all();

        for(const r of rosterRows.results||[]){
          let reason=`Roster: ${r.display_name}`;
          const bits=[];
          if(r.school)bits.push(r.school);
          if(r.sport)bits.push(r.sport);
          if(r.team && r.team!==r.school)bits.push(r.team);
          if(r.jersey_number)bits.push(`#${r.jersey_number}`);
          if(bits.length)reason+=` · ${bits.join(" · ")}`;
          addResult(r,reason,r.photo_id,r.preview_key);
        }

        // V15 pending player-tag suggestions remain searchable as possible matches.
        const v15PendingRows=await env.DB.prepare(`
          SELECT DISTINCT pts.gallery_id,g.title AS gallery_title,g.shoot_date,
                 pts.photo_id,p.preview_key,pts.suggested_name,
                 pts.suggested_school,pts.suggested_team,
                 pts.suggested_sport,pts.suggested_jersey_number
          FROM player_tag_suggestions pts
          JOIN galleries g ON g.id=pts.gallery_id
          JOIN photos p ON p.id=pts.photo_id
          WHERE pts.status='pending'
            AND (
              LOWER(pts.normalized_name) LIKE LOWER(?1) ESCAPE '\\'
              OR LOWER(COALESCE(pts.suggested_school,'')) LIKE LOWER(?1) ESCAPE '\\'
              OR LOWER(COALESCE(pts.suggested_team,'')) LIKE LOWER(?1) ESCAPE '\\'
              OR LOWER(COALESCE(pts.suggested_sport,'')) LIKE LOWER(?1) ESCAPE '\\'
              OR LOWER(COALESCE(pts.suggested_jersey_number,'')) LIKE LOWER(?1) ESCAPE '\\'
            )
            AND (?2='' OR g.shoot_date=?2)
          ORDER BY pts.submitted_at DESC
          LIMIT 400
        `).bind(pattern,date).all();

        for(const r of v15PendingRows.results||[]){
          const bits=[];
          if(r.suggested_school)bits.push(r.suggested_school);
          if(r.suggested_sport)bits.push(r.suggested_sport);
          if(r.suggested_team && r.suggested_team!==r.suggested_school)bits.push(r.suggested_team);
          if(r.suggested_jersey_number)bits.push(`#${r.suggested_jersey_number}`);
          let reason=`Possible Match — Unverified: ${r.suggested_name}`;
          if(bits.length)reason+=` · ${bits.join(" · ")}`;
          addResult(r,reason,r.photo_id,r.preview_key);
        }

        // Gallery-level tags.
        const galleryTagRows=await env.DB.prepare(`
          SELECT DISTINCT g.id AS gallery_id,g.title AS gallery_title,g.shoot_date,
                 t.label,t.tag_type,
                 p.id AS photo_id,p.preview_key
          FROM gallery_tags gt
          JOIN tags t ON t.id=gt.tag_id
          JOIN galleries g ON g.id=gt.gallery_id
          LEFT JOIN photos p ON p.id=(
            SELECT p2.id FROM photos p2
            WHERE p2.gallery_id=g.id
            ORDER BY p2.sort_order,p2.filename
            LIMIT 1
          )
          WHERE t.normalized_label LIKE LOWER(?1) ESCAPE '\\'
            AND (?2='' OR g.shoot_date=?2)
          ORDER BY COALESCE(g.shoot_date,g.created_at) DESC
          LIMIT 200
        `).bind(pattern,date).all();

        for(const r of galleryTagRows.results||[]){
          const label=r.tag_type?`${String(r.tag_type)[0].toUpperCase()+String(r.tag_type).slice(1)}: ${r.label}`:`Tag: ${r.label}`;
          addResult(r,label,r.photo_id,r.preview_key);
        }

        // Verified person / athlete matches by first, last, full/partial name,
        // team, sport, or jersey number.
        const athleteRows=await env.DB.prepare(`
          SELECT DISTINCT ppl.gallery_id,g.title AS gallery_title,g.shoot_date,
                 ppl.photo_id,p.preview_key,
                 ap.player_name,am.sport,am.team,
                 COALESCE(ppl.jersey_number,ajn.jersey_number) AS jersey_number
          FROM photo_person_links ppl
          JOIN athlete_profiles ap ON ap.id=ppl.athlete_id
          JOIN galleries g ON g.id=ppl.gallery_id
          JOIN photos p ON p.id=ppl.photo_id
          LEFT JOIN athlete_memberships am ON am.id=ppl.membership_id
          LEFT JOIN athlete_jersey_numbers ajn ON ajn.membership_id=am.id AND ajn.active=1
          WHERE ap.verification_status='verified'
            AND (
              ap.player_name LIKE ?1 ESCAPE '\\' COLLATE NOCASE
              OR COALESCE(am.sport,'') LIKE ?1 ESCAPE '\\' COLLATE NOCASE
              OR COALESCE(am.team,'') LIKE ?1 ESCAPE '\\' COLLATE NOCASE
              OR COALESCE(ppl.jersey_number,'')=?2
              OR COALESCE(ajn.jersey_number,'')=?2
            )
            AND (?3='' OR g.shoot_date=?3)
          ORDER BY COALESCE(g.shoot_date,g.created_at) DESC,p.sort_order
          LIMIT 400
        `).bind(pattern,q,date).all();

        for(const r of athleteRows.results||[]){
          let reason=`Player: ${r.player_name}`;
          const bits=[];
          if(r.team)bits.push(r.team);
          if(r.sport)bits.push(r.sport);
          if(r.jersey_number)bits.push(`#${r.jersey_number}`);
          if(bits.length)reason+=` · ${bits.join(" · ")}`;
          addResult(r,reason,r.photo_id,r.preview_key);
        }
      }

      // If only a date was supplied and there was no text query, include all shoots on that date.
      if(!q && date){
        const dateRows=await env.DB.prepare(`
          SELECT g.id AS gallery_id,g.title AS gallery_title,g.shoot_date,
                 p.id AS photo_id,p.preview_key
          FROM galleries g
          LEFT JOIN photos p ON p.id=(
            SELECT p2.id FROM photos p2
            WHERE p2.gallery_id=g.id
            ORDER BY p2.sort_order,p2.filename
            LIMIT 1
          )
          WHERE g.shoot_date=?1
          ORDER BY g.title
        `).bind(date).all();
        for(const r of dateRows.results||[])addResult(r,`Date: ${date}`,r.photo_id,r.preview_key);
      }

      const results=[...resultMap.values()]
        .map(item=>({
          id:item.id,
          title:item.title,
          shoot_date:item.shoot_date,
          match_reasons:item.match_reasons.slice(0,8),
          matched_photo_count:item.matched_photo_ids.size,
          preview_url:item.preview_key?`/api/preview/${encodeURIComponent(item.preview_key)}`:null
        }))
        .sort((a,b)=>String(b.shoot_date||"").localeCompare(String(a.shoot_date||"")) || a.title.localeCompare(b.title))
        .slice(0,100);

      return json(request,{ok:true,query:q,date,results});
    }

    // ---------- PUBLIC GENERAL TAG SEARCH ----------
    if(url.pathname==="/api/search" && request.method==="GET"){
      const q=String(url.searchParams.get("q")||"").trim().slice(0,120);
      const type=String(url.searchParams.get("type")||"").trim().slice(0,40);
      const galleryId=String(url.searchParams.get("gallery_id")||"").trim();

      if(!q)return json(request,{ok:true,photos:[],tags:[]});

      const pattern=`%${q.replace(/[\\%_]/g,m=>"\\"+m)}%`;

      const tags=await env.DB.prepare(`
        SELECT id,label,tag_type
        FROM tags
        WHERE normalized_label LIKE LOWER(?1) ESCAPE '\\'
          AND (?2='' OR tag_type=?2)
        ORDER BY
          CASE WHEN normalized_label=LOWER(?3) THEN 0 ELSE 1 END,
          label COLLATE NOCASE
        LIMIT 50
      `).bind(pattern,type,q).all();

      const photos=await env.DB.prepare(`
        SELECT DISTINCT p.id,p.gallery_id,p.filename,p.preview_key,g.title AS gallery_title,g.shoot_date,
               t.label AS matched_tag,t.tag_type AS matched_tag_type
        FROM photo_tags pt
        JOIN tags t ON t.id=pt.tag_id
        JOIN photos p ON p.id=pt.photo_id
        JOIN galleries g ON g.id=pt.gallery_id
        WHERE pt.status='active'
          AND t.normalized_label LIKE LOWER(?1) ESCAPE '\\'
          AND (?2='' OR t.tag_type=?2)
          AND (?3='' OR p.gallery_id=?3)
        ORDER BY COALESCE(g.shoot_date,g.created_at) DESC,p.sort_order,p.filename
        LIMIT 200
      `).bind(pattern,type,galleryId).all();

      return json(request,{
        ok:true,
        tags:tags.results||[],
        photos:(photos.results||[]).map(x=>({
          ...x,
          preview_url:x.preview_key?`/api/preview/${encodeURIComponent(x.preview_key)}`:null
        }))
      });
    }

    if(url.pathname==="/api/tags" && request.method==="GET"){
      const q=String(url.searchParams.get("q")||"").trim().slice(0,120);
      const type=String(url.searchParams.get("type")||"").trim().slice(0,40);
      const pattern=`%${q.replace(/[\\%_]/g,m=>"\\"+m)}%`;

      const rows=await env.DB.prepare(`
        SELECT id,label,tag_type
        FROM tags
        WHERE (?1='' OR normalized_label LIKE LOWER(?2) ESCAPE '\\')
          AND (?3='' OR tag_type=?3)
        ORDER BY label COLLATE NOCASE
        LIMIT 100
      `).bind(q,pattern,type).all();

      return json(request,{ok:true,tags:rows.results||[]});
    }

    const publicPhotoTags=url.pathname.match(/^\/api\/photos\/([^/]+)\/tags$/);
    if(publicPhotoTags && request.method==="GET"){
      const photoId=decodeURIComponent(publicPhotoTags[1]);
      const rows=await env.DB.prepare(`
        SELECT t.id,t.label,t.tag_type,pt.source
        FROM photo_tags pt
        JOIN tags t ON t.id=pt.tag_id
        WHERE pt.photo_id=?1 AND pt.status='active'
        ORDER BY t.tag_type,t.label COLLATE NOCASE
      `).bind(photoId).all();
      return json(request,{ok:true,tags:rows.results||[]});
    }

    // ---------- ADMIN GENERAL TAGS ----------
    if(url.pathname==="/api/admin/tags" && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const q=String(url.searchParams.get("q")||"").trim().slice(0,120);
      const type=String(url.searchParams.get("type")||"").trim().slice(0,40);
      const pattern=`%${q.replace(/[\\%_]/g,m=>"\\"+m)}%`;

      const rows=await env.DB.prepare(`
        SELECT t.id,t.label,t.normalized_label,t.tag_type,
               COUNT(DISTINCT CASE WHEN pt.status='active' THEN pt.photo_id END) AS photo_count,
               COUNT(DISTINCT gt.gallery_id) AS gallery_count
        FROM tags t
        LEFT JOIN photo_tags pt ON pt.tag_id=t.id
        LEFT JOIN gallery_tags gt ON gt.tag_id=t.id
        WHERE (?1='' OR t.normalized_label LIKE LOWER(?2) ESCAPE '\\')
          AND (?3='' OR t.tag_type=?3)
        GROUP BY t.id
        ORDER BY t.label COLLATE NOCASE
        LIMIT 250
      `).bind(q,pattern,type).all();

      return json(request,{ok:true,tags:rows.results||[]});
    }

    if(url.pathname==="/api/admin/tags" && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const b=await bodyJson(request);
      const label=String(b?.label||"").trim().replace(/\s+/g," ").slice(0,200);
      const tagType=String(b?.tag_type||"custom").trim().toLowerCase();
      const allowed=new Set(["person","product","team","sport","event","location","subject","custom"]);

      if(!label)return json(request,{ok:false,error:"Tag label is required"},400);
      if(!allowed.has(tagType))return json(request,{ok:false,error:"Invalid tag type"},400);

      const normalized=label.toLowerCase();
      const existing=await env.DB.prepare(`
        SELECT id,label,tag_type FROM tags WHERE tag_type=?1 AND normalized_label=?2
      `).bind(tagType,normalized).first();
      if(existing)return json(request,{ok:true,tag:existing,already_exists:true});

      const now=new Date().toISOString();
      const id=`tag-${crypto.randomUUID()}`;
      await env.DB.prepare(`
        INSERT INTO tags(id,label,normalized_label,tag_type,created_at,updated_at)
        VALUES(?1,?2,?3,?4,?5,?5)
      `).bind(id,label,normalized,tagType,now).run();

      return json(request,{ok:true,tag:{id,label,tag_type:tagType}},201);
    }

    const adminPhotoTags=url.pathname.match(/^\/api\/admin\/photos\/([^/]+)\/tags$/);
    if(adminPhotoTags && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const photoId=decodeURIComponent(adminPhotoTags[1]);

      const rows=await env.DB.prepare(`
        SELECT pt.id AS photo_tag_id,pt.photo_id,pt.gallery_id,pt.source,pt.status,
               t.id AS tag_id,t.label,t.tag_type
        FROM photo_tags pt
        JOIN tags t ON t.id=pt.tag_id
        WHERE pt.photo_id=?1
        ORDER BY t.tag_type,t.label COLLATE NOCASE
      `).bind(photoId).all();

      return json(request,{ok:true,tags:rows.results||[]});
    }

    if(adminPhotoTags && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const photoId=decodeURIComponent(adminPhotoTags[1]);
      const b=await bodyJson(request);

      let tagId=String(b?.tag_id||"").trim();
      const label=String(b?.label||"").trim().replace(/\s+/g," ").slice(0,200);
      const tagType=String(b?.tag_type||"custom").trim().toLowerCase();
      const allowed=new Set(["person","product","team","sport","event","location","subject","custom"]);

      const photo=await env.DB.prepare(`SELECT id,gallery_id FROM photos WHERE id=?1`).bind(photoId).first();
      if(!photo)return json(request,{ok:false,error:"Photo not found"},404);

      if(!tagId){
        if(!label)return json(request,{ok:false,error:"tag_id or label is required"},400);
        if(!allowed.has(tagType))return json(request,{ok:false,error:"Invalid tag type"},400);

        const normalized=label.toLowerCase();
        let tag=await env.DB.prepare(`
          SELECT id FROM tags WHERE tag_type=?1 AND normalized_label=?2
        `).bind(tagType,normalized).first();

        if(!tag){
          tagId=`tag-${crypto.randomUUID()}`;
          const now=new Date().toISOString();
          await env.DB.prepare(`
            INSERT INTO tags(id,label,normalized_label,tag_type,created_at,updated_at)
            VALUES(?1,?2,?3,?4,?5,?5)
          `).bind(tagId,label,normalized,tagType,now).run();
        }else tagId=tag.id;
      }

      const tag=await env.DB.prepare(`SELECT id,label,tag_type FROM tags WHERE id=?1`).bind(tagId).first();
      if(!tag)return json(request,{ok:false,error:"Tag not found"},404);

      const existing=await env.DB.prepare(`
        SELECT id,status FROM photo_tags WHERE photo_id=?1 AND tag_id=?2
      `).bind(photoId,tagId).first();

      if(existing){
        if(existing.status!=="active"){
          await env.DB.prepare(`
            UPDATE photo_tags SET status='active',source='admin',reviewed_at=NULL,reviewed_by=NULL
            WHERE id=?1
          `).bind(existing.id).run();
        }
        if(tag.tag_type==="person"){
          await queuePersonTagNotifications(env,photoId,tagId);
        }
        return json(request,{ok:true,photo_tag_id:existing.id,tag,already_exists:true});
      }

      const now=new Date().toISOString();
      const id=`phototag-${crypto.randomUUID()}`;
      await env.DB.prepare(`
        INSERT INTO photo_tags(
          id,photo_id,gallery_id,tag_id,source,status,created_at,created_by,reviewed_at,reviewed_by
        ) VALUES(?1,?2,?3,?4,'admin','active',?5,'admin',NULL,NULL)
      `).bind(id,photo.id,photo.gallery_id,tagId,now).run();

      if(tag.tag_type==="person"){
        await queuePersonTagNotifications(env,photoId,tagId);
      }
      await logActivity(env,{
        eventType:"photo_tag_added",galleryId:photo.gallery_id,photoId,
        metadata:{tag_id:tagId,tag_type:tag.tag_type,label:tag.label}
      });
      return json(request,{ok:true,photo_tag_id:id,tag},201);
    }

    const adminPhotoTagDelete=url.pathname.match(/^\/api\/admin\/photos\/([^/]+)\/tags\/([^/]+)$/);
    if(adminPhotoTagDelete && request.method==="DELETE"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const photoId=decodeURIComponent(adminPhotoTagDelete[1]);
      const tagId=decodeURIComponent(adminPhotoTagDelete[2]);

      await env.DB.prepare(`DELETE FROM photo_tags WHERE photo_id=?1 AND tag_id=?2`)
        .bind(photoId,tagId).run();

      return json(request,{ok:true});
    }

    const adminGalleryTags=url.pathname.match(/^\/api\/admin\/galleries\/([^/]+)\/tags$/);
    if(adminGalleryTags && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const galleryId=decodeURIComponent(adminGalleryTags[1]);

      const rows=await env.DB.prepare(`
        SELECT gt.id AS gallery_tag_id,t.id AS tag_id,t.label,t.tag_type
        FROM gallery_tags gt
        JOIN tags t ON t.id=gt.tag_id
        WHERE gt.gallery_id=?1
        ORDER BY t.tag_type,t.label COLLATE NOCASE
      `).bind(galleryId).all();

      return json(request,{ok:true,tags:rows.results||[]});
    }

    if(adminGalleryTags && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const galleryId=decodeURIComponent(adminGalleryTags[1]);
      const b=await bodyJson(request);
      let tagId=String(b?.tag_id||"").trim();
      const label=String(b?.label||"").trim().replace(/\s+/g," ").slice(0,200);
      const tagType=String(b?.tag_type||"custom").trim().toLowerCase();
      const allowed=new Set(["person","product","team","sport","event","location","subject","custom"]);

      const gallery=await env.DB.prepare(`SELECT id FROM galleries WHERE id=?1`).bind(galleryId).first();
      if(!gallery)return json(request,{ok:false,error:"Gallery not found"},404);

      if(!tagId){
        if(!label)return json(request,{ok:false,error:"tag_id or label is required"},400);
        if(!allowed.has(tagType))return json(request,{ok:false,error:"Invalid tag type"},400);

        const normalized=label.toLowerCase();
        let tag=await env.DB.prepare(`
          SELECT id FROM tags WHERE tag_type=?1 AND normalized_label=?2
        `).bind(tagType,normalized).first();

        if(!tag){
          tagId=`tag-${crypto.randomUUID()}`;
          const now=new Date().toISOString();
          await env.DB.prepare(`
            INSERT INTO tags(id,label,normalized_label,tag_type,created_at,updated_at)
            VALUES(?1,?2,?3,?4,?5,?5)
          `).bind(tagId,label,normalized,tagType,now).run();
        }else tagId=tag.id;
      }

      const existing=await env.DB.prepare(`
        SELECT id FROM gallery_tags WHERE gallery_id=?1 AND tag_id=?2
      `).bind(galleryId,tagId).first();
      if(existing)return json(request,{ok:true,gallery_tag_id:existing.id,already_exists:true});

      const now=new Date().toISOString();
      const id=`gallerytag-${crypto.randomUUID()}`;
      await env.DB.prepare(`
        INSERT INTO gallery_tags(id,gallery_id,tag_id,created_at,created_by)
        VALUES(?1,?2,?3,?4,'admin')
      `).bind(id,galleryId,tagId,now).run();

      return json(request,{ok:true,gallery_tag_id:id,tag_id:tagId},201);
    }

    const adminGalleryTagDelete=url.pathname.match(/^\/api\/admin\/galleries\/([^/]+)\/tags\/([^/]+)$/);
    if(adminGalleryTagDelete && request.method==="DELETE"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const galleryId=decodeURIComponent(adminGalleryTagDelete[1]);
      const tagId=decodeURIComponent(adminGalleryTagDelete[2]);

      await env.DB.prepare(`DELETE FROM gallery_tags WHERE gallery_id=?1 AND tag_id=?2`)
        .bind(galleryId,tagId).run();

      return json(request,{ok:true});
    }

    if(url.pathname==="/api/admin/athlete-tag-links" && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const b=await bodyJson(request);
      const athleteId=String(b?.athlete_id||"").trim();
      const tagId=String(b?.tag_id||"").trim();

      if(!athleteId||!tagId)
        return json(request,{ok:false,error:"athlete_id and tag_id are required"},400);

      const athlete=await env.DB.prepare(`SELECT id FROM athlete_profiles WHERE id=?1`).bind(athleteId).first();
      if(!athlete)return json(request,{ok:false,error:"Athlete not found"},404);

      const tag=await env.DB.prepare(`SELECT id,tag_type FROM tags WHERE id=?1`).bind(tagId).first();
      if(!tag)return json(request,{ok:false,error:"Tag not found"},404);
      if(tag.tag_type!=="person")
        return json(request,{ok:false,error:"Only person tags can be linked to athlete identities"},400);

      const existing=await env.DB.prepare(`
        SELECT athlete_id FROM athlete_tag_links WHERE athlete_id=?1 AND tag_id=?2
      `).bind(athleteId,tagId).first();
      if(existing)return json(request,{ok:true,already_exists:true});

      await env.DB.prepare(`
        INSERT INTO athlete_tag_links(athlete_id,tag_id,created_at)
        VALUES(?1,?2,?3)
      `).bind(athleteId,tagId,new Date().toISOString()).run();

      return json(request,{ok:true},201);
    }





    // ---------- ADMIN ROSTERS ----------
    if(url.pathname==="/api/admin/rosters" && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const rows=await env.DB.prepare(`
        SELECT r.*,
               COUNT(DISTINCT rp.id) AS player_count,
               COUNT(DISTINCT gr.gallery_id) AS gallery_count
        FROM rosters r
        LEFT JOIN roster_players rp ON rp.roster_id=r.id AND rp.status='active'
        LEFT JOIN gallery_rosters gr ON gr.roster_id=r.id
        GROUP BY r.id
        ORDER BY CASE WHEN r.status='active' THEN 0 ELSE 1 END,
                 COALESCE(r.school,''),COALESCE(r.sport,''),r.name
      `).all();
      return json(request,{ok:true,rosters:rows.results||[]});
    }

    if(url.pathname==="/api/admin/rosters" && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const b=await bodyJson(request);
      const name=cleanRosterField(b?.name,120);
      if(!name)return json(request,{ok:false,error:"Roster name is required"},400);

      const id=`roster-${crypto.randomUUID()}`;
      const now=new Date().toISOString();
      const school=cleanRosterField(b?.school,120)||null;
      const team=cleanRosterField(b?.team,120)||null;
      const sport=cleanRosterField(b?.sport,80)||null;
      const season=cleanRosterField(b?.season,50)||null;
      const notes=cleanRosterField(b?.notes,500)||null;

      await env.DB.prepare(`
        INSERT INTO rosters(id,name,school,team,sport,season,notes,status,created_at,updated_at)
        VALUES(?1,?2,?3,?4,?5,?6,?7,'active',?8,?8)
      `).bind(id,name,school,team,sport,season,notes,now).run();

      await logActivity(env,{
        eventType:"roster_created",
        metadata:{roster_id:id,name,school,team,sport,season}
      });
      return json(request,{ok:true,id},201);
    }

    const rosterRoute=url.pathname.match(/^\/api\/admin\/rosters\/([^/]+)$/);
    if(rosterRoute && request.method==="PATCH"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const id=decodeURIComponent(rosterRoute[1]);
      const current=await env.DB.prepare(`SELECT * FROM rosters WHERE id=?1`).bind(id).first();
      if(!current)return json(request,{ok:false,error:"Roster not found"},404);
      const b=await bodyJson(request);

      const name=b?.name===undefined?current.name:cleanRosterField(b.name,120);
      if(!name)return json(request,{ok:false,error:"Roster name is required"},400);
      const school=b?.school===undefined?current.school:(cleanRosterField(b.school,120)||null);
      const team=b?.team===undefined?current.team:(cleanRosterField(b.team,120)||null);
      const sport=b?.sport===undefined?current.sport:(cleanRosterField(b.sport,80)||null);
      const season=b?.season===undefined?current.season:(cleanRosterField(b.season,50)||null);
      const notes=b?.notes===undefined?current.notes:(cleanRosterField(b.notes,500)||null);
      const status=b?.status===undefined?current.status:String(b.status);
      if(!["active","archived"].includes(status))
        return json(request,{ok:false,error:"Invalid roster status"},400);
      const now=new Date().toISOString();

      await env.DB.prepare(`
        UPDATE rosters SET name=?1,school=?2,team=?3,sport=?4,season=?5,notes=?6,status=?7,updated_at=?8
        WHERE id=?9
      `).bind(name,school,team,sport,season,notes,status,now,id).run();
      return json(request,{ok:true,id,status});
    }

    const rosterPlayersRoute=url.pathname.match(/^\/api\/admin\/rosters\/([^/]+)\/players$/);
    if(rosterPlayersRoute && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const rosterId=decodeURIComponent(rosterPlayersRoute[1]);
      const roster=await env.DB.prepare(`SELECT * FROM rosters WHERE id=?1`).bind(rosterId).first();
      if(!roster)return json(request,{ok:false,error:"Roster not found"},404);
      const rows=await env.DB.prepare(`
        SELECT * FROM roster_players
        WHERE roster_id=?1
        ORDER BY CASE WHEN status='active' THEN 0 ELSE 1 END,
                 display_name,COALESCE(jersey_number,'')
      `).bind(rosterId).all();
      return json(request,{ok:true,roster,players:rows.results||[]});
    }

    if(rosterPlayersRoute && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const rosterId=decodeURIComponent(rosterPlayersRoute[1]);
      const roster=await env.DB.prepare(`SELECT * FROM rosters WHERE id=?1`).bind(rosterId).first();
      if(!roster)return json(request,{ok:false,error:"Roster not found"},404);
      const b=await bodyJson(request);

      let first=cleanRosterField(b?.first_name,80);
      let last=cleanRosterField(b?.last_name,80);
      let display=cleanRosterField(b?.display_name,100);
      if(display && (!first||!last)){
        const parsed=splitPlayerName(display);
        if(!first)first=parsed.first_name;
        if(!last)last=parsed.last_name;
      }
      if(!display)display=[first,last].filter(Boolean).join(" ");
      if(!first || !last || !display)
        return json(request,{ok:false,error:"First and last name are required"},400);

      const id=`rosterplayer-${crypto.randomUUID()}`;
      const now=new Date().toISOString();
      const jersey=cleanRosterField(b?.jersey_number,30)||null;
      const school=cleanRosterField(b?.school,120)||roster.school||null;
      const team=cleanRosterField(b?.team,120)||roster.team||null;
      const sport=cleanRosterField(b?.sport,80)||roster.sport||null;
      const season=cleanRosterField(b?.season,50)||roster.season||null;
      const athleteId=cleanRosterField(b?.athlete_id,100)||null;
      const notes=cleanRosterField(b?.notes,500)||null;

      if(athleteId){
        const athlete=await env.DB.prepare(`SELECT id FROM athlete_profiles WHERE id=?1`).bind(athleteId).first();
        if(!athlete)return json(request,{ok:false,error:"Athlete account not found"},400);
      }

      await env.DB.prepare(`
        INSERT INTO roster_players(
          id,roster_id,first_name,last_name,display_name,normalized_name,
          jersey_number,school,team,sport,season,athlete_id,notes,status,created_at,updated_at
        ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'active',?14,?14)
      `).bind(
        id,rosterId,first,last,display,normalizePersonTagLabel(display).toLowerCase(),
        jersey,school,team,sport,season,athleteId,notes,now
      ).run();

      return json(request,{ok:true,id},201);
    }

    const rosterPlayerRoute=url.pathname.match(/^\/api\/admin\/roster-players\/([^/]+)$/);
    if(rosterPlayerRoute && request.method==="PATCH"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const id=decodeURIComponent(rosterPlayerRoute[1]);
      const cur=await env.DB.prepare(`SELECT * FROM roster_players WHERE id=?1`).bind(id).first();
      if(!cur)return json(request,{ok:false,error:"Roster player not found"},404);
      const b=await bodyJson(request);

      const first=b?.first_name===undefined?cur.first_name:cleanRosterField(b.first_name,80);
      const last=b?.last_name===undefined?cur.last_name:cleanRosterField(b.last_name,80);
      const display=b?.display_name===undefined
        ? [first,last].filter(Boolean).join(" ")
        : cleanRosterField(b.display_name,100);
      if(!first||!last||!display)
        return json(request,{ok:false,error:"First and last name are required"},400);

      const jersey=b?.jersey_number===undefined?cur.jersey_number:(cleanRosterField(b.jersey_number,30)||null);
      const school=b?.school===undefined?cur.school:(cleanRosterField(b.school,120)||null);
      const team=b?.team===undefined?cur.team:(cleanRosterField(b.team,120)||null);
      const sport=b?.sport===undefined?cur.sport:(cleanRosterField(b.sport,80)||null);
      const season=b?.season===undefined?cur.season:(cleanRosterField(b.season,50)||null);
      const athleteId=b?.athlete_id===undefined?cur.athlete_id:(cleanRosterField(b.athlete_id,100)||null);
      const notes=b?.notes===undefined?cur.notes:(cleanRosterField(b.notes,500)||null);
      const status=b?.status===undefined?cur.status:String(b.status);
      if(!["active","inactive"].includes(status))
        return json(request,{ok:false,error:"Invalid player status"},400);
      const now=new Date().toISOString();

      await env.DB.prepare(`
        UPDATE roster_players
        SET first_name=?1,last_name=?2,display_name=?3,normalized_name=?4,
            jersey_number=?5,school=?6,team=?7,sport=?8,season=?9,
            athlete_id=?10,notes=?11,status=?12,updated_at=?13
        WHERE id=?14
      `).bind(
        first,last,display,normalizePersonTagLabel(display).toLowerCase(),jersey,school,team,sport,season,
        athleteId,notes,status,now,id
      ).run();
      return json(request,{ok:true,id,status});
    }

    if(rosterPlayerRoute && request.method==="DELETE"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const id=decodeURIComponent(rosterPlayerRoute[1]);
      const cur=await env.DB.prepare(`SELECT id FROM roster_players WHERE id=?1`).bind(id).first();
      if(!cur)return json(request,{ok:false,error:"Roster player not found"},404);
      const now=new Date().toISOString();
      await env.DB.prepare(`
        UPDATE roster_players SET status='inactive',updated_at=?1 WHERE id=?2
      `).bind(now,id).run();
      return json(request,{ok:true,id,status:"inactive"});
    }

    const rosterGalleryRoute=url.pathname.match(/^\/api\/admin\/rosters\/([^/]+)\/galleries$/);
    if(rosterGalleryRoute && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const rosterId=decodeURIComponent(rosterGalleryRoute[1]);
      const rows=await env.DB.prepare(`
        SELECT g.id,g.title,g.shoot_date
        FROM gallery_rosters gr JOIN galleries g ON g.id=gr.gallery_id
        WHERE gr.roster_id=?1
        ORDER BY COALESCE(g.shoot_date,g.created_at) DESC
      `).bind(rosterId).all();
      return json(request,{ok:true,galleries:rows.results||[]});
    }

    if(rosterGalleryRoute && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const rosterId=decodeURIComponent(rosterGalleryRoute[1]);
      const b=await bodyJson(request);
      const galleryId=cleanRosterField(b?.gallery_id,100);
      if(!galleryId)return json(request,{ok:false,error:"Gallery is required"},400);

      const roster=await env.DB.prepare(`SELECT id FROM rosters WHERE id=?1`).bind(rosterId).first();
      const gallery=await env.DB.prepare(`SELECT id FROM galleries WHERE id=?1`).bind(galleryId).first();
      if(!roster||!gallery)return json(request,{ok:false,error:"Roster or gallery not found"},404);

      await env.DB.prepare(`
        INSERT OR IGNORE INTO gallery_rosters(gallery_id,roster_id,created_at)
        VALUES(?1,?2,?3)
      `).bind(galleryId,rosterId,new Date().toISOString()).run();
      return json(request,{ok:true,roster_id:rosterId,gallery_id:galleryId});
    }

    const rosterGalleryDelete=url.pathname.match(/^\/api\/admin\/rosters\/([^/]+)\/galleries\/([^/]+)$/);
    if(rosterGalleryDelete && request.method==="DELETE"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const rosterId=decodeURIComponent(rosterGalleryDelete[1]);
      const galleryId=decodeURIComponent(rosterGalleryDelete[2]);
      await env.DB.prepare(`
        DELETE FROM gallery_rosters WHERE roster_id=?1 AND gallery_id=?2
      `).bind(rosterId,galleryId).run();
      return json(request,{ok:true,roster_id:rosterId,gallery_id:galleryId});
    }

    if(url.pathname==="/api/admin/player-tag-suggestions-v15" && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const status=cleanRosterField(url.searchParams.get("status"),30)||"pending";
      const rows=await env.DB.prepare(`
        SELECT pts.*,
               p.filename,p.preview_key,
               g.title AS gallery_title,g.shoot_date,
               rp.display_name AS roster_display_name,
               rp.athlete_id AS roster_athlete_id
        FROM player_tag_suggestions pts
        JOIN photos p ON p.id=pts.photo_id
        JOIN galleries g ON g.id=pts.gallery_id
        LEFT JOIN roster_players rp ON rp.id=pts.roster_player_id
        WHERE (?1='' OR pts.status=?1)
        ORDER BY pts.submitted_at DESC
        LIMIT 500
      `).bind(status).all();
      return json(request,{ok:true,suggestions:rows.results||[]});
    }

    const v15SuggestionAction=url.pathname.match(/^\/api\/admin\/player-tag-suggestions-v15\/([^/]+)\/(approve|reject)$/);
    if(v15SuggestionAction && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const suggestionId=decodeURIComponent(v15SuggestionAction[1]);
      const action=v15SuggestionAction[2];
      const b=await bodyJson(request).catch(()=>({}));

      const row=await env.DB.prepare(`
        SELECT pts.*,rp.athlete_id AS roster_athlete_id
        FROM player_tag_suggestions pts
        LEFT JOIN roster_players rp ON rp.id=pts.roster_player_id
        WHERE pts.id=?1
      `).bind(suggestionId).first();
      if(!row)return json(request,{ok:false,error:"Suggestion not found"},404);

      const now=new Date().toISOString();
      if(action==="reject"){
        await env.DB.prepare(`
          UPDATE player_tag_suggestions
          SET status='rejected',reviewed_at=?1,reviewed_by='admin'
          WHERE id=?2
        `).bind(now,suggestionId).run();
        await logActivity(env,{
          eventType:"player_tag_rejected",
          galleryId:row.gallery_id,photoId:row.photo_id,
          metadata:{suggestion_id:suggestionId,player_name:row.suggested_name}
        });
        return json(request,{ok:true,status:"rejected"});
      }

      let athleteId=cleanRosterField(b?.athlete_id,100)||row.roster_athlete_id||null;
      if(!athleteId){
        const candidates=await env.DB.prepare(`
          SELECT id FROM athlete_profiles
          WHERE verification_status='verified'
            AND LOWER(TRIM(player_name))=LOWER(TRIM(?1))
          LIMIT 3
        `).bind(row.suggested_name).all();
        if((candidates.results||[]).length===1)athleteId=candidates.results[0].id;
      }

      if(athleteId){
        const athlete=await env.DB.prepare(`
          SELECT id FROM athlete_profiles WHERE id=?1 AND verification_status='verified'
        `).bind(athleteId).first();
        if(!athlete)return json(request,{ok:false,error:"Verified athlete not found"},400);
      }

      await env.DB.prepare(`
        UPDATE player_tag_suggestions
        SET status='approved',approved_athlete_id=?1,reviewed_at=?2,reviewed_by='admin'
        WHERE id=?3
      `).bind(athleteId,now,suggestionId).run();

      if(athleteId){
        await env.DB.prepare(`
          INSERT OR IGNORE INTO photo_person_links(
            id,athlete_id,gallery_id,photo_id,membership_id,jersey_number,
            source,created_at,created_by
          ) VALUES(?1,?2,?3,?4,NULL,?5,'admin',?6,'admin')
        `).bind(
          `ppl-${crypto.randomUUID()}`,athleteId,row.gallery_id,row.photo_id,
          row.suggested_jersey_number||null,now
        ).run();

        if(row.roster_player_id){
          await env.DB.prepare(`
            UPDATE roster_players SET athlete_id=?1,updated_at=?2
            WHERE id=?3 AND athlete_id IS NULL
          `).bind(athleteId,now,row.roster_player_id).run();
        }
      }

      await logActivity(env,{
        eventType:"player_tag_approved",
        galleryId:row.gallery_id,photoId:row.photo_id,athleteId,
        metadata:{
          suggestion_id:suggestionId,
          player_name:row.suggested_name,
          school:row.suggested_school||null,
          jersey_number:row.suggested_jersey_number||null,
          linked_to_athlete:Boolean(athleteId)
        }
      });

      return json(request,{ok:true,status:"approved",athlete_id:athleteId});
    }

    // ---------- ADMIN PLAYER TAG SUGGESTIONS ----------
    if(url.pathname==="/api/admin/player-tag-suggestions" && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const status=String(url.searchParams.get("status")||"pending").trim();
      const rows=await env.DB.prepare(`
        SELECT pt.id AS photo_tag_id,pt.status,pt.created_at,
               t.id AS tag_id,t.label AS player_name,
               p.id AS photo_id,p.filename,p.preview_key,
               g.id AS gallery_id,g.title AS gallery_title,g.shoot_date
        FROM photo_tags pt
        JOIN tags t ON t.id=pt.tag_id
        JOIN photos p ON p.id=pt.photo_id
        JOIN galleries g ON g.id=pt.gallery_id
        WHERE pt.source='user_suggestion'
          AND t.tag_type='person'
          AND (?1='' OR pt.status=?1)
        ORDER BY pt.created_at DESC
        LIMIT 500
      `).bind(status).all();
      return json(request,{ok:true,suggestions:rows.results||[]});
    }

    const adminTagSuggestionAction=url.pathname.match(/^\/api\/admin\/player-tag-suggestions\/([^/]+)\/(approve|reject)$/);
    if(adminTagSuggestionAction && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const photoTagId=decodeURIComponent(adminTagSuggestionAction[1]);
      const action=adminTagSuggestionAction[2];
      const b=await bodyJson(request).catch(()=>({}));

      const row=await env.DB.prepare(`
        SELECT pt.id,pt.photo_id,pt.gallery_id,pt.tag_id,pt.status,
               t.label,t.normalized_label
        FROM photo_tags pt JOIN tags t ON t.id=pt.tag_id
        WHERE pt.id=?1 AND pt.source='user_suggestion' AND t.tag_type='person'
      `).bind(photoTagId).first();
      if(!row)return json(request,{ok:false,error:"Player tag suggestion not found"},404);

      const now=new Date().toISOString();
      if(action==="reject"){
        await env.DB.prepare(`
          UPDATE photo_tags SET status='rejected',reviewed_at=?1,reviewed_by='admin'
          WHERE id=?2
        `).bind(now,photoTagId).run();
        await logActivity(env,{
          eventType:"player_tag_rejected",galleryId:row.gallery_id,photoId:row.photo_id,
          metadata:{photo_tag_id:photoTagId,player_name:row.label}
        });
        return json(request,{ok:true,status:"rejected"});
      }

      let athleteId=String(b?.athlete_id||"").trim()||null;
      if(!athleteId){
        const matches=await env.DB.prepare(`
          SELECT id FROM athlete_profiles
          WHERE verification_status='verified'
            AND LOWER(TRIM(player_name))=LOWER(TRIM(?1))
          LIMIT 2
        `).bind(row.label).all();
        if((matches.results||[]).length===1)athleteId=matches.results[0].id;
      }

      await env.DB.prepare(`
        UPDATE photo_tags SET status='active',reviewed_at=?1,reviewed_by='admin'
        WHERE id=?2
      `).bind(now,photoTagId).run();

      if(athleteId){
        const athlete=await env.DB.prepare(`
          SELECT id FROM athlete_profiles WHERE id=?1 AND verification_status='verified'
        `).bind(athleteId).first();
        if(athlete){
          await env.DB.prepare(`
            INSERT OR IGNORE INTO athlete_tag_links(athlete_id,tag_id,created_at)
            VALUES(?1,?2,?3)
          `).bind(athleteId,row.tag_id,now).run();

          await env.DB.prepare(`
            INSERT OR IGNORE INTO photo_person_links(
              id,athlete_id,gallery_id,photo_id,membership_id,jersey_number,
              source,created_at,created_by
            ) VALUES(?1,?2,?3,?4,NULL,NULL,'admin',?5,'admin')
          `).bind(`ppl-${crypto.randomUUID()}`,athleteId,row.gallery_id,row.photo_id,now).run();
        }
      }

      await logActivity(env,{
        eventType:"player_tag_approved",galleryId:row.gallery_id,photoId:row.photo_id,athleteId,
        metadata:{photo_tag_id:photoTagId,player_name:row.label,linked_to_athlete:Boolean(athleteId)}
      });
      return json(request,{ok:true,status:"active",athlete_id:athleteId});
    }

    // ---------- ADMIN NOTIFICATION SETTINGS / REPORTS ----------
    if(url.pathname==="/api/admin/notification-settings" && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const row=await env.DB.prepare(`
        SELECT * FROM admin_notification_settings WHERE id=1
      `).first();
      return json(request,{ok:true,settings:row||null});
    }

    if(url.pathname==="/api/admin/notification-settings" && request.method==="PATCH"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const b=await bodyJson(request);
      const current=await env.DB.prepare(`
        SELECT * FROM admin_notification_settings WHERE id=1
      `).first();
      const email=b?.notification_email===undefined
        ? current?.notification_email||null
        : (String(b.notification_email||"").trim().toLowerCase()||null);
      if(email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return json(request,{ok:false,error:"Enter a valid notification email"},400);

      const pending=b?.pending_claim_alerts===undefined?Number(current?.pending_claim_alerts??1):(b.pending_claim_alerts?1:0);
      const purchase=b?.purchase_alerts===undefined?Number(current?.purchase_alerts??1):(b.purchase_alerts?1:0);
      const monthly=b?.monthly_statement_enabled===undefined?Number(current?.monthly_statement_enabled??1):(b.monthly_statement_enabled?1:0);
      const day=b?.monthly_statement_day===undefined?Number(current?.monthly_statement_day||1):Number(b.monthly_statement_day);
      if(!Number.isInteger(day)||day<1||day>28)
        return json(request,{ok:false,error:"Monthly statement day must be 1-28"},400);

      const now=new Date().toISOString();
      await env.DB.prepare(`
        INSERT INTO admin_notification_settings(
          id,notification_email,pending_claim_alerts,purchase_alerts,
          monthly_statement_enabled,monthly_statement_day,updated_at
        ) VALUES(1,?1,?2,?3,?4,?5,?6)
        ON CONFLICT(id) DO UPDATE SET
          notification_email=excluded.notification_email,
          pending_claim_alerts=excluded.pending_claim_alerts,
          purchase_alerts=excluded.purchase_alerts,
          monthly_statement_enabled=excluded.monthly_statement_enabled,
          monthly_statement_day=excluded.monthly_statement_day,
          updated_at=excluded.updated_at
      `).bind(email,pending,purchase,monthly,day,now).run();

      return json(request,{ok:true,settings:{
        notification_email:email,pending_claim_alerts:pending,purchase_alerts:purchase,
        monthly_statement_enabled:monthly,monthly_statement_day:day,updated_at:now
      }});
    }

    if(url.pathname==="/api/admin/reports/activity" && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const range=reportDateRange(url);
      if(!range)return json(request,{ok:false,error:"Invalid report date range"},400);

      const totals=await env.DB.prepare(`
        SELECT
          COUNT(*) AS activity_count,
          SUM(CASE WHEN event_type='login' THEN 1 ELSE 0 END) AS logins,
          COUNT(DISTINCT CASE WHEN event_type='login' THEN user_id END) AS unique_users,
          SUM(CASE WHEN event_type='account_registered' THEN 1 ELSE 0 END) AS new_accounts,
          SUM(CASE WHEN event_type='photo_rating' THEN 1 ELSE 0 END) AS ratings,
          SUM(CASE WHEN event_type='photo_claim_submitted' THEN 1 ELSE 0 END) AS claims_submitted,
          SUM(CASE WHEN event_type='photo_claim_approved' THEN 1 ELSE 0 END) AS claims_approved,
          SUM(CASE WHEN event_type='photo_claim_rejected' THEN 1 ELSE 0 END) AS claims_rejected,
          SUM(CASE WHEN event_type='photo_tag_added' THEN 1 ELSE 0 END) AS tags_added,
          SUM(CASE WHEN event_type='client_gallery_access_granted' THEN 1 ELSE 0 END) AS client_gallery_grants,
          SUM(CASE WHEN event_type='purchase_completed' THEN 1 ELSE 0 END) AS purchases,
          COALESCE(SUM(CASE WHEN event_type='purchase_completed' THEN amount_cents ELSE 0 END),0) AS revenue_cents
        FROM activity_log
        WHERE occurred_at>=?1 AND occurred_at<=?2
      `).bind(range.start,range.end).first();

      const eventCounts=await env.DB.prepare(`
        SELECT event_type,COUNT(*) AS count
        FROM activity_log
        WHERE occurred_at>=?1 AND occurred_at<=?2
        GROUP BY event_type
        ORDER BY count DESC,event_type
      `).bind(range.start,range.end).all();

      const topGalleries=await env.DB.prepare(`
        SELECT a.gallery_id,g.title,g.shoot_date,COUNT(*) AS activity_count,
               SUM(CASE WHEN a.event_type='photo_rating' THEN 1 ELSE 0 END) AS ratings,
               SUM(CASE WHEN a.event_type='purchase_completed' THEN 1 ELSE 0 END) AS purchases,
               COALESCE(SUM(CASE WHEN a.event_type='purchase_completed' THEN a.amount_cents ELSE 0 END),0) AS revenue_cents
        FROM activity_log a
        LEFT JOIN galleries g ON g.id=a.gallery_id
        WHERE a.occurred_at>=?1 AND a.occurred_at<=?2 AND a.gallery_id IS NOT NULL
        GROUP BY a.gallery_id,g.title,g.shoot_date
        ORDER BY activity_count DESC
        LIMIT 25
      `).bind(range.start,range.end).all();

      const fanFavorites=await env.DB.prepare(`
        SELECT r.gallery_id,g.title,r.photo_id,p.filename,
               COUNT(*) AS rating_count,ROUND(AVG(r.rating),2) AS average_rating
        FROM photo_ratings r
        JOIN galleries g ON g.id=r.gallery_id
        JOIN photos p ON p.id=r.photo_id
        WHERE r.created_at>=?1 AND r.created_at<=?2
        GROUP BY r.gallery_id,g.title,r.photo_id,p.filename
        HAVING COUNT(*)>0
        ORDER BY average_rating DESC,rating_count DESC
        LIMIT 25
      `).bind(range.start,range.end).all();

      const pendingClaims=await env.DB.prepare(`
        SELECT COUNT(*) AS count FROM photo_claims WHERE status='pending'
      `).first();

      const unreadAdminBatches=await env.DB.prepare(`
        SELECT COUNT(*) AS count FROM admin_email_batches WHERE status='pending'
      `).first();

      return json(request,{
        ok:true,range,
        totals:totals||{},
        event_counts:eventCounts.results||[],
        top_galleries:topGalleries.results||[],
        fan_favorites:fanFavorites.results||[],
        pending:{
          photo_claims:Number(pendingClaims?.count||0),
          admin_email_batches:Number(unreadAdminBatches?.count||0)
        }
      });
    }

    if(url.pathname==="/api/admin/reports/activity-log" && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const range=reportDateRange(url);
      if(!range)return json(request,{ok:false,error:"Invalid report date range"},400);
      const type=String(url.searchParams.get("type")||"").trim();
      const rows=await env.DB.prepare(`
        SELECT a.*,u.email,u.display_name,g.title AS gallery_title,p.filename
        FROM activity_log a
        LEFT JOIN user_accounts u ON u.id=a.user_id
        LEFT JOIN galleries g ON g.id=a.gallery_id
        LEFT JOIN photos p ON p.id=a.photo_id
        WHERE a.occurred_at>=?1 AND a.occurred_at<=?2
          AND (?3='' OR a.event_type=?3)
        ORDER BY a.occurred_at DESC
        LIMIT 500
      `).bind(range.start,range.end,type).all();
      return json(request,{ok:true,range,activity:rows.results||[]});
    }

    if(url.pathname==="/api/admin/email-batches" && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const status=String(url.searchParams.get("status")||"pending");
      const rows=await env.DB.prepare(`
        SELECT * FROM admin_email_batches
        WHERE status=?1
        ORDER BY created_at DESC
        LIMIT 200
      `).bind(status).all();
      return json(request,{ok:true,batches:rows.results||[]});
    }

    // ---------- ADMIN PLAYER / CLIENT ACCOUNTS ----------
    if(url.pathname==="/api/admin/accounts" && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const q=String(url.searchParams.get("q")||"").trim();
      const pattern=`%${q.replace(/[\\%_]/g,m=>"\\"+m)}%`;
      const rows=await env.DB.prepare(`
        SELECT u.id,u.email,u.display_name,u.account_status,u.created_at,u.updated_at,
               GROUP_CONCAT(DISTINCT r.role) AS roles
        FROM user_accounts u
        LEFT JOIN user_account_roles r ON r.user_id=u.id
        WHERE (?1='' OR u.email LIKE ?2 ESCAPE '\\' COLLATE NOCASE OR u.display_name LIKE ?2 ESCAPE '\\' COLLATE NOCASE)
        GROUP BY u.id
        ORDER BY u.display_name COLLATE NOCASE,u.email
        LIMIT 250
      `).bind(q,pattern).all();
      return json(request,{ok:true,accounts:(rows.results||[]).map(x=>({
        ...x,roles:String(x.roles||"").split(",").filter(Boolean)
      }))});
    }


    const accountStatusRoute=url.pathname.match(/^\/api\/admin\/accounts\/([^/]+)\/(deactivate|reactivate)$/);
    if(accountStatusRoute && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const userId=decodeURIComponent(accountStatusRoute[1]);
      const action=accountStatusRoute[2];
      const user=await env.DB.prepare(`SELECT id,email,display_name FROM user_accounts WHERE id=?1`).bind(userId).first();
      if(!user)return json(request,{ok:false,error:"Account not found"},404);

      const now=new Date().toISOString();
      if(action==="deactivate"){
        await env.DB.prepare(`
          UPDATE user_accounts SET account_status='suspended',updated_at=?1 WHERE id=?2
        `).bind(now,userId).run();
        await env.DB.prepare(`
          UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at,?1)
          WHERE user_id=?2 AND revoked_at IS NULL
        `).bind(now,userId).run();
        await logActivity(env,{eventType:"account_deactivated",userId,metadata:{admin:true}});
        return json(request,{ok:true,id:userId,status:"suspended"});
      }else{
        const athlete=await env.DB.prepare(`
          SELECT verification_status FROM athlete_profiles WHERE user_id=?1
        `).bind(userId).first();
        const newStatus=athlete?.verification_status==="verified"?"verified":"verified";
        await env.DB.prepare(`
          UPDATE user_accounts SET account_status=?1,updated_at=?2 WHERE id=?3
        `).bind(newStatus,now,userId).run();
        await logActivity(env,{eventType:"account_reactivated",userId,metadata:{admin:true}});
        return json(request,{ok:true,id:userId,status:newStatus});
      }
    }

    const accountDeleteRoute=url.pathname.match(/^\/api\/admin\/accounts\/([^/]+)$/);
    if(accountDeleteRoute && request.method==="DELETE"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const userId=decodeURIComponent(accountDeleteRoute[1]);
      const user=await env.DB.prepare(`SELECT id,email,display_name FROM user_accounts WHERE id=?1`).bind(userId).first();
      if(!user)return json(request,{ok:false,error:"Account not found"},404);

      const orderCheck=await env.DB.prepare(`
        SELECT COUNT(*) AS count FROM orders
        WHERE LOWER(COALESCE(customer_email,''))=LOWER(?1)
      `).bind(user.email||"").first().catch(()=>({count:0}));

      if(Number(orderCheck?.count||0)>0){
        return json(request,{
          ok:false,
          code:"PURCHASE_HISTORY_EXISTS",
          error:"This account has purchase history and cannot be deleted. Deactivate it instead."
        },409);
      }

      const athlete=await env.DB.prepare(`SELECT id FROM athlete_profiles WHERE user_id=?1`).bind(userId).first();
      if(athlete){
        await env.DB.prepare(`DELETE FROM photo_person_links WHERE athlete_id=?1`).bind(athlete.id).run();
        await env.DB.prepare(`DELETE FROM photo_claims WHERE athlete_id=?1`).bind(athlete.id).run();
        await env.DB.prepare(`DELETE FROM athlete_tag_links WHERE athlete_id=?1`).bind(athlete.id).run();
        await env.DB.prepare(`DELETE FROM athlete_jersey_numbers WHERE membership_id IN (SELECT id FROM athlete_memberships WHERE athlete_id=?1)`).bind(athlete.id).run();
        await env.DB.prepare(`DELETE FROM athlete_memberships WHERE athlete_id=?1`).bind(athlete.id).run();
        await env.DB.prepare(`DELETE FROM parent_athlete_links WHERE athlete_id=?1`).bind(athlete.id).run();
        await env.DB.prepare(`DELETE FROM athlete_profiles WHERE id=?1`).bind(athlete.id).run();
      }

      await env.DB.prepare(`DELETE FROM parent_athlete_links WHERE parent_user_id=?1`).bind(userId).run();
      await env.DB.prepare(`DELETE FROM client_gallery_entitlements WHERE user_id=?1`).bind(userId).run();
      await env.DB.prepare(`DELETE FROM athlete_profile_requests WHERE user_id=?1`).bind(userId).run();
      await env.DB.prepare(`DELETE FROM photo_claims WHERE user_id=?1`).bind(userId).run();
      await env.DB.prepare(`DELETE FROM photo_ratings WHERE user_id=?1`).bind(userId).run();
      await env.DB.prepare(`DELETE FROM user_notifications WHERE user_id=?1`).bind(userId).run();
      await env.DB.prepare(`DELETE FROM email_notification_batches WHERE user_id=?1`).bind(userId).run();
      await env.DB.prepare(`DELETE FROM notification_preferences WHERE user_id=?1`).bind(userId).run();
      await env.DB.prepare(`DELETE FROM user_login_activity WHERE user_id=?1`).bind(userId).run();
      await env.DB.prepare(`DELETE FROM account_sport_preferences WHERE user_id=?1`).bind(userId).run();
      await env.DB.prepare(`DELETE FROM user_account_roles WHERE user_id=?1`).bind(userId).run();
      await env.DB.prepare(`DELETE FROM auth_sessions WHERE user_id=?1`).bind(userId).run();
      await env.DB.prepare(`DELETE FROM auth_credentials WHERE user_id=?1`).bind(userId).run();

      await logActivity(env,{
        eventType:"account_deleted",
        metadata:{email:user.email||null,display_name:user.display_name||null}
      });
      await env.DB.prepare(`DELETE FROM user_accounts WHERE id=?1`).bind(userId).run();

      return json(request,{ok:true,id:userId,deleted:true});
    }

    const entitlementRoute=url.pathname.match(/^\/api\/admin\/accounts\/([^/]+)\/gallery-entitlements$/);
    if(entitlementRoute && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const userId=decodeURIComponent(entitlementRoute[1]);
      const rows=await env.DB.prepare(`
        SELECT e.*,g.title,g.shoot_date
        FROM client_gallery_entitlements e
        JOIN galleries g ON g.id=e.gallery_id
        WHERE e.user_id=?1
        ORDER BY e.granted_at DESC
      `).bind(userId).all();
      return json(request,{ok:true,entitlements:rows.results||[]});
    }

    if(entitlementRoute && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const userId=decodeURIComponent(entitlementRoute[1]);
      const b=await bodyJson(request);
      const galleryId=String(b?.gallery_id||"").trim();
      if(!galleryId)return json(request,{ok:false,error:"gallery_id is required"},400);

      const user=await env.DB.prepare(`SELECT id FROM user_accounts WHERE id=?1`).bind(userId).first();
      if(!user)return json(request,{ok:false,error:"Account not found"},404);
      const gallery=await env.DB.prepare(`SELECT id FROM galleries WHERE id=?1`).bind(galleryId).first();
      if(!gallery)return json(request,{ok:false,error:"Gallery not found"},404);

      const now=new Date().toISOString();
      const existing=await env.DB.prepare(`
        SELECT id FROM client_gallery_entitlements WHERE user_id=?1 AND gallery_id=?2
      `).bind(userId,galleryId).first();

      const canDownload=b?.can_download_all===false?0:1;
      const canPrint=b?.can_order_prints===false?0:1;
      const note=String(b?.note||"").trim().slice(0,500)||null;

      if(existing){
        await env.DB.prepare(`
          UPDATE client_gallery_entitlements
          SET can_download_all=?1,can_order_prints=?2,status='active',granted_at=?3,granted_by='admin',
              revoked_at=NULL,note=?4
          WHERE id=?5
        `).bind(canDownload,canPrint,now,note,existing.id).run();
        const grantGallery=await env.DB.prepare(`SELECT title FROM galleries WHERE id=?1`).bind(galleryId).first();
        await queueNotification(env,{
          userId,type:"gallery_access_granted",galleryId,
          title:`Gallery access granted: ${grantGallery?.title||"Your gallery"}`,
          message:"31 ACTION has granted your account access to this client gallery.",
          sourceKey:`gallery-access:${userId}:${galleryId}`
        });
        await logActivity(env,{
          eventType:"client_gallery_access_granted",userId,galleryId,
          metadata:{can_download_all:Boolean(canDownload),can_order_prints:Boolean(canPrint),updated:true}
        });
        return json(request,{ok:true,id:existing.id,updated:true});
      }

      const id=`entitlement-${crypto.randomUUID()}`;
      await env.DB.prepare(`
        INSERT INTO client_gallery_entitlements(
          id,user_id,gallery_id,can_download_all,can_order_prints,status,granted_at,granted_by,revoked_at,note
        ) VALUES(?1,?2,?3,?4,?5,'active',?6,'admin',NULL,?7)
      `).bind(id,userId,galleryId,canDownload,canPrint,now,note).run();

      await env.DB.prepare(`
        INSERT OR IGNORE INTO user_account_roles(user_id,role,created_at,created_by)
        VALUES(?1,'client',?2,'admin')
      `).bind(userId,now).run();

      const grantGallery=await env.DB.prepare(`SELECT title FROM galleries WHERE id=?1`).bind(galleryId).first();
      await queueNotification(env,{
        userId,type:"gallery_access_granted",galleryId,
        title:`Gallery access granted: ${grantGallery?.title||"Your gallery"}`,
        message:"31 ACTION has granted your account access to this client gallery.",
        sourceKey:`gallery-access:${userId}:${galleryId}`
      });
      await logActivity(env,{
        eventType:"client_gallery_access_granted",userId,galleryId,
        metadata:{can_download_all:Boolean(canDownload),can_order_prints:Boolean(canPrint)}
      });
      return json(request,{ok:true,id},201);
    }

    const entitlementRevoke=url.pathname.match(/^\/api\/admin\/accounts\/([^/]+)\/gallery-entitlements\/([^/]+)\/revoke$/);
    if(entitlementRevoke && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const userId=decodeURIComponent(entitlementRevoke[1]);
      const entitlementId=decodeURIComponent(entitlementRevoke[2]);
      const now=new Date().toISOString();
      await env.DB.prepare(`
        UPDATE client_gallery_entitlements
        SET status='revoked',revoked_at=?1
        WHERE id=?2 AND user_id=?3
      `).bind(now,entitlementId,userId).run();
      return json(request,{ok:true,id:entitlementId,status:"revoked"});
    }

    const parentLinkRoute=url.pathname.match(/^\/api\/admin\/accounts\/([^/]+)\/parent-links$/);
    if(parentLinkRoute && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const parentUserId=decodeURIComponent(parentLinkRoute[1]);
      const b=await bodyJson(request);
      const athleteId=String(b?.athlete_id||"").trim();
      if(!athleteId)return json(request,{ok:false,error:"athlete_id is required"},400);

      const now=new Date().toISOString();
      const existing=await env.DB.prepare(`
        SELECT id FROM parent_athlete_links WHERE parent_user_id=?1 AND athlete_id=?2
      `).bind(parentUserId,athleteId).first();

      if(existing){
        await env.DB.prepare(`
          UPDATE parent_athlete_links SET status='approved',approved_at=?1,approved_by='admin',note=?2
          WHERE id=?3
        `).bind(now,String(b?.note||"").slice(0,500)||null,existing.id).run();
        return json(request,{ok:true,id:existing.id,status:"approved"});
      }

      const id=`parentlink-${crypto.randomUUID()}`;
      await env.DB.prepare(`
        INSERT INTO parent_athlete_links(id,parent_user_id,athlete_id,status,created_at,approved_at,approved_by,note)
        VALUES(?1,?2,?3,'approved',?4,?4,'admin',?5)
      `).bind(id,parentUserId,athleteId,now,String(b?.note||"").slice(0,500)||null).run();

      await env.DB.prepare(`
        INSERT OR IGNORE INTO user_account_roles(user_id,role,created_at,created_by)
        VALUES(?1,'parent',?2,'admin')
      `).bind(parentUserId,now).run();

      return json(request,{ok:true,id,status:"approved"},201);
    }

    // ---------- ADMIN PLAYER ACCOUNT / ATHLETE REQUEST REVIEW ----------
    if(url.pathname==="/api/admin/athlete-profile-requests" && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const status=String(url.searchParams.get("status")||"pending");
      const rows=await env.DB.prepare(`
        SELECT r.id,r.user_id,r.requested_player_name,r.requested_sport,r.requested_team,
               r.requested_jersey_numbers,r.status,r.submitted_at,r.reviewed_at,r.reviewed_by,r.review_note,
               u.email,u.display_name,u.account_status
        FROM athlete_profile_requests r
        JOIN user_accounts u ON u.id=r.user_id
        WHERE r.status=?1
        ORDER BY r.submitted_at
      `).bind(status).all();
      return json(request,{ok:true,requests:(rows.results||[]).map(r=>({
        ...r,requested_jersey_numbers:parseJson(r.requested_jersey_numbers,[])
      }))});
    }

    const athleteRequestReview=url.pathname.match(/^\/api\/admin\/athlete-profile-requests\/([^/]+)\/(approve|reject)$/);
    if(athleteRequestReview && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const requestId=decodeURIComponent(athleteRequestReview[1]);
      const action=athleteRequestReview[2];
      const b=await bodyJson(request);
      const reqRow=await env.DB.prepare(`
        SELECT r.*,u.email,u.display_name
        FROM athlete_profile_requests r
        JOIN user_accounts u ON u.id=r.user_id
        WHERE r.id=?1
      `).bind(requestId).first();
      if(!reqRow)return json(request,{ok:false,error:"Athlete request not found"},404);
      if(reqRow.status!=="pending")
        return json(request,{ok:false,error:`This request is already ${reqRow.status}`},409);

      const now=new Date().toISOString();
      const note=String(b?.review_note||"").trim().slice(0,500)||null;

      if(action==="reject"){
        await env.DB.prepare(`
          UPDATE athlete_profile_requests
          SET status='rejected',reviewed_at=?1,reviewed_by='admin',review_note=?2
          WHERE id=?3
        `).bind(now,note,requestId).run();
        return json(request,{ok:true,id:requestId,status:"rejected"});
      }

      let athlete=await env.DB.prepare(`SELECT id FROM athlete_profiles WHERE user_id=?1`)
        .bind(reqRow.user_id).first();
      let athleteId=athlete?.id||`athlete-${crypto.randomUUID()}`;

      if(athlete){
        await env.DB.prepare(`
          UPDATE athlete_profiles
          SET player_name=?1,verification_status='verified',verified_at=?2,verified_by='admin',updated_at=?2
          WHERE id=?3
        `).bind(reqRow.requested_player_name,now,athleteId).run();
      }else{
        await env.DB.prepare(`
          INSERT INTO athlete_profiles(
            id,user_id,player_name,verification_status,verified_at,verified_by,created_at,updated_at
          ) VALUES(?1,?2,?3,'verified',?4,'admin',?4,?4)
        `).bind(athleteId,reqRow.user_id,reqRow.requested_player_name,now).run();
      }

      let membershipId=null;
      if(reqRow.requested_sport){
        const existingMembership=await env.DB.prepare(`
          SELECT id FROM athlete_memberships
          WHERE athlete_id=?1 AND sport=?2
            AND COALESCE(team,'')=COALESCE(?3,'')
          LIMIT 1
        `).bind(athleteId,reqRow.requested_sport,reqRow.requested_team||null).first();

        membershipId=existingMembership?.id||`membership-${crypto.randomUUID()}`;
        if(!existingMembership){
          await env.DB.prepare(`
            INSERT INTO athlete_memberships(id,athlete_id,sport,team,active,created_at,updated_at)
            VALUES(?1,?2,?3,?4,1,?5,?5)
          `).bind(
            membershipId,athleteId,reqRow.requested_sport,
            reqRow.requested_team||null,now
          ).run();
        }

        const jerseys=parseJson(reqRow.requested_jersey_numbers,[]);
        for(const number of Array.isArray(jerseys)?jerseys:[]){
          const jersey=String(number??"").trim();
          if(!jersey)continue;
          const exists=await env.DB.prepare(`
            SELECT id FROM athlete_jersey_numbers
            WHERE membership_id=?1 AND jersey_number=?2
          `).bind(membershipId,jersey).first();
          if(!exists){
            await env.DB.prepare(`
              INSERT INTO athlete_jersey_numbers(
                id,membership_id,jersey_number,active,created_at,updated_at
              ) VALUES(?1,?2,?3,1,?4,?4)
            `).bind(`jersey-${crypto.randomUUID()}`,membershipId,jersey.slice(0,30),now).run();
          }
        }
      }

      const sportPrefs=await env.DB.prepare(`
        SELECT sport,custom_sport FROM account_sport_preferences WHERE user_id=?1
      `).bind(reqRow.user_id).all();
      for(const pref of sportPrefs.results||[]){
        const sportName=pref.sport==="other"?(pref.custom_sport||"Other"):pref.sport;
        if(!sportName)continue;
        const exists=await env.DB.prepare(`
          SELECT id FROM athlete_memberships
          WHERE athlete_id=?1 AND LOWER(sport)=LOWER(?2)
            AND COALESCE(team,'')=COALESCE(?3,'')
          LIMIT 1
        `).bind(athleteId,sportName,reqRow.requested_team||null).first();
        if(!exists){
          await env.DB.prepare(`
            INSERT INTO athlete_memberships(id,athlete_id,sport,team,active,created_at,updated_at)
            VALUES(?1,?2,?3,?4,1,?5,?5)
          `).bind(`membership-${crypto.randomUUID()}`,athleteId,sportName,reqRow.requested_team||null,now).run();
        }
      }

      await env.DB.prepare(`
        UPDATE athlete_profile_requests
        SET status='approved',reviewed_at=?1,reviewed_by='admin',review_note=?2
        WHERE id=?3
      `).bind(now,note,requestId).run();

      await env.DB.prepare(`
        UPDATE user_accounts
        SET account_status='verified',display_name=COALESCE(display_name,?1),updated_at=?2
        WHERE id=?3
      `).bind(reqRow.requested_player_name,now,reqRow.user_id).run();

      return json(request,{
        ok:true,id:requestId,status:"approved",
        user_id:reqRow.user_id,athlete_id:athleteId,membership_id:membershipId
      });
    }

    // ---------- ADMIN ATHLETE IDENTITIES / CLAIMS ----------
    if(url.pathname==="/api/admin/athletes" && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const rows=await env.DB.prepare(`
        SELECT ap.id,ap.user_id,ap.player_name,ap.verification_status,ap.verified_at,
               ua.email,ua.display_name,ua.account_status,
               ap.created_at,ap.updated_at
        FROM athlete_profiles ap
        JOIN user_accounts ua ON ua.id=ap.user_id
        ORDER BY ap.player_name COLLATE NOCASE
      `).all();

      const athletes=[];
      for(const row of rows.results||[]){
        const memberships=await env.DB.prepare(`
          SELECT * FROM athlete_memberships WHERE athlete_id=?1 ORDER BY sport,team
        `).bind(row.id).all();
        for(const m of memberships.results||[]){
          const jerseys=await env.DB.prepare(`
            SELECT id,jersey_number,active FROM athlete_jersey_numbers
            WHERE membership_id=?1 ORDER BY jersey_number
          `).bind(m.id).all();
          m.jersey_numbers=jerseys.results||[];
        }
        athletes.push({...row,memberships:memberships.results||[]});
      }
      return json(request,{ok:true,athletes});
    }

    if(url.pathname==="/api/admin/athletes" && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const b=await bodyJson(request);
      const email=String(b?.email||"").trim().toLowerCase();
      const playerName=String(b?.player_name||"").trim();
      if(!email||!playerName)return json(request,{ok:false,error:"email and player_name required"},400);

      const now=new Date().toISOString();
      const userId=b?.user_id||`user-${crypto.randomUUID()}`;
      const athleteId=b?.athlete_id||`athlete-${crypto.randomUUID()}`;

      await env.DB.prepare(`
        INSERT INTO user_accounts(id,email,display_name,account_status,created_at,updated_at)
        VALUES(?1,?2,?3,'verified',?4,?4)
        ON CONFLICT(email) DO UPDATE SET
          display_name=excluded.display_name,
          updated_at=excluded.updated_at
      `).bind(userId,email,String(b?.display_name||playerName).slice(0,200),now).run();

      const user=await env.DB.prepare(`SELECT id FROM user_accounts WHERE email=?1`).bind(email).first();

      await env.DB.prepare(`
        INSERT INTO athlete_profiles(id,user_id,player_name,verification_status,verified_at,verified_by,created_at,updated_at)
        VALUES(?1,?2,?3,'verified',?4,'admin',?4,?4)
        ON CONFLICT(user_id) DO UPDATE SET
          player_name=excluded.player_name,
          verification_status='verified',
          verified_at=excluded.verified_at,
          verified_by='admin',
          updated_at=excluded.updated_at
      `).bind(athleteId,user.id,playerName.slice(0,200),now).run();

      const athlete=await env.DB.prepare(`SELECT id FROM athlete_profiles WHERE user_id=?1`).bind(user.id).first();
      return json(request,{ok:true,user_id:user.id,athlete_id:athlete.id},201);
    }

    const athleteMembership=url.pathname.match(/^\/api\/admin\/athletes\/([^/]+)\/memberships$/);
    if(athleteMembership && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const athleteId=decodeURIComponent(athleteMembership[1]);
      const b=await bodyJson(request);
      const sport=String(b?.sport||"").trim();
      const team=String(b?.team||"").trim();
      if(!sport)return json(request,{ok:false,error:"sport required"},400);
      const now=new Date().toISOString();
      const id=`membership-${crypto.randomUUID()}`;
      await env.DB.prepare(`
        INSERT INTO athlete_memberships(id,athlete_id,sport,team,active,created_at,updated_at)
        VALUES(?1,?2,?3,?4,1,?5,?5)
      `).bind(id,athleteId,sport.slice(0,120),team.slice(0,200)||null,now).run();
      return json(request,{ok:true,id},201);
    }

    const membershipJerseys=url.pathname.match(/^\/api\/admin\/athlete-memberships\/([^/]+)\/jerseys$/);
    if(membershipJerseys && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const membershipId=decodeURIComponent(membershipJerseys[1]);
      const b=await bodyJson(request);
      const nums=Array.isArray(b?.jersey_numbers)?b.jersey_numbers:[b?.jersey_number];
      const clean=[...new Set(nums.map(x=>String(x??"").trim()).filter(Boolean))];
      if(!clean.length)return json(request,{ok:false,error:"At least one jersey number required"},400);
      const now=new Date().toISOString();
      const ids=[];
      for(const number of clean){
        const existing=await env.DB.prepare(`
          SELECT id FROM athlete_jersey_numbers WHERE membership_id=?1 AND jersey_number=?2
        `).bind(membershipId,number).first();
        if(existing){ids.push(existing.id);continue}
        const id=`jersey-${crypto.randomUUID()}`;
        await env.DB.prepare(`
          INSERT INTO athlete_jersey_numbers(id,membership_id,jersey_number,active,created_at,updated_at)
          VALUES(?1,?2,?3,1,?4,?4)
        `).bind(id,membershipId,number.slice(0,30),now).run();
        ids.push(id);
      }
      return json(request,{ok:true,ids},201);
    }

    if(url.pathname==="/api/admin/photo-claims" && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const status=url.searchParams.get("status")||"pending";
      const rows=await env.DB.prepare(`
        SELECT pc.*,ap.player_name,ua.email,am.sport,am.team,p.filename,g.title AS gallery_title
        FROM photo_claims pc
        JOIN athlete_profiles ap ON ap.id=pc.athlete_id
        JOIN user_accounts ua ON ua.id=pc.user_id
        JOIN photos p ON p.id=pc.photo_id
        JOIN galleries g ON g.id=pc.gallery_id
        LEFT JOIN athlete_memberships am ON am.id=pc.membership_id
        WHERE pc.status=?1
        ORDER BY pc.submitted_at
      `).bind(status).all();
      return json(request,{ok:true,claims:rows.results||[]});
    }

    const claimReview=url.pathname.match(/^\/api\/admin\/photo-claims\/([^/]+)\/(approve|reject)$/);
    if(claimReview && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const claimId=decodeURIComponent(claimReview[1]);
      const action=claimReview[2];
      const b=await bodyJson(request);
      const claim=await env.DB.prepare(`SELECT * FROM photo_claims WHERE id=?1`).bind(claimId).first();
      if(!claim)return json(request,{ok:false,error:"Claim not found"},404);
      const now=new Date().toISOString();

      if(action==="approve"){
        await env.DB.prepare(`
          UPDATE photo_claims SET status='approved',reviewed_at=?1,reviewed_by='admin',review_note=?2 WHERE id=?3
        `).bind(now,String(b?.review_note||"").slice(0,500)||null,claimId).run();
        const claimGallery=await env.DB.prepare(`
          SELECT g.title FROM galleries g WHERE g.id=?1
        `).bind(claim.gallery_id).first();
        await queueNotification(env,{
          userId:claim.user_id,type:"claim_approved",galleryId:claim.gallery_id,
          photoId:claim.photo_id,athleteId:claim.athlete_id,
          title:`Photo claim approved${claimGallery?.title?` in ${claimGallery.title}`:""}`,
          message:"A photo you claimed has been verified as you.",
          sourceKey:`claim-approved:${claimId}`
        });
        await logActivity(env,{
          eventType:"photo_claim_approved",userId:claim.user_id,
          galleryId:claim.gallery_id,photoId:claim.photo_id,athleteId:claim.athlete_id,
          metadata:{claim_id:claimId}
        });

        const existing=await env.DB.prepare(`
          SELECT id FROM photo_person_links WHERE photo_id=?1 AND athlete_id=?2
        `).bind(claim.photo_id,claim.athlete_id).first();

        if(!existing){
          await env.DB.prepare(`
            INSERT INTO photo_person_links(
              id,athlete_id,gallery_id,photo_id,membership_id,jersey_number,source,created_at,created_by
            ) VALUES(?1,?2,?3,?4,?5,?6,'approved_claim',?7,'admin')
          `).bind(
            `personlink-${crypto.randomUUID()}`,claim.athlete_id,claim.gallery_id,claim.photo_id,
            claim.membership_id||null,claim.jersey_number||null,now
          ).run();
        }
      }else{
        await env.DB.prepare(`
          UPDATE photo_claims SET status='rejected',reviewed_at=?1,reviewed_by='admin',review_note=?2 WHERE id=?3
        `).bind(now,String(b?.review_note||"").slice(0,500)||null,claimId).run();
        const claimGallery=await env.DB.prepare(`
          SELECT g.title FROM galleries g WHERE g.id=?1
        `).bind(claim.gallery_id).first();
        await queueNotification(env,{
          userId:claim.user_id,type:"claim_rejected",galleryId:claim.gallery_id,
          photoId:claim.photo_id,athleteId:claim.athlete_id,
          title:`Photo claim reviewed${claimGallery?.title?` in ${claimGallery.title}`:""}`,
          message:"A photo claim was not approved.",
          sourceKey:`claim-rejected:${claimId}`
        });
        await logActivity(env,{
          eventType:"photo_claim_rejected",userId:claim.user_id,
          galleryId:claim.gallery_id,photoId:claim.photo_id,athleteId:claim.athlete_id,
          metadata:{claim_id:claimId}
        });
      }
      return json(request,{ok:true,id:claimId,status:action==="approve"?"approved":"rejected"});
    }

    const athleteEventPhotos=url.pathname.match(/^\/api\/admin\/athletes\/([^/]+)\/galleries\/([^/]+)\/photos$/);
    if(athleteEventPhotos && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const athleteId=decodeURIComponent(athleteEventPhotos[1]);
      const galleryId=decodeURIComponent(athleteEventPhotos[2]);
      const rows=await env.DB.prepare(`
        SELECT ppl.*,p.filename,p.preview_key
        FROM photo_person_links ppl
        JOIN photos p ON p.id=ppl.photo_id
        WHERE ppl.athlete_id=?1 AND ppl.gallery_id=?2
        ORDER BY p.sort_order
      `).bind(athleteId,galleryId).all();
      return json(request,{ok:true,photos:(rows.results||[]).map(x=>({...x,
        preview_url:x.preview_key?`/api/preview/${encodeURIComponent(x.preview_key)}`:null
      }))});
    }

    if(url.pathname==="/api/admin/photo-person-links" && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const b=await bodyJson(request);
      const athleteId=String(b?.athlete_id||"");
      const galleryId=String(b?.gallery_id||"");
      const photoId=String(b?.photo_id||"");
      if(!athleteId||!galleryId||!photoId)
        return json(request,{ok:false,error:"athlete_id, gallery_id and photo_id required"},400);

      const photo=await env.DB.prepare(`SELECT id FROM photos WHERE id=?1 AND gallery_id=?2`).bind(photoId,galleryId).first();
      if(!photo)return json(request,{ok:false,error:"Photo not found in this gallery"},404);

      const existing=await env.DB.prepare(`
        SELECT id FROM photo_person_links WHERE photo_id=?1 AND athlete_id=?2
      `).bind(photoId,athleteId).first();
      if(existing)return json(request,{ok:true,id:existing.id,already_exists:true});

      const now=new Date().toISOString();
      const id=`personlink-${crypto.randomUUID()}`;
      await env.DB.prepare(`
        INSERT INTO photo_person_links(
          id,athlete_id,gallery_id,photo_id,membership_id,jersey_number,source,created_at,created_by
        ) VALUES(?1,?2,?3,?4,?5,?6,'admin',?7,'admin')
      `).bind(
        id,athleteId,galleryId,photoId,b?.membership_id||null,
        String(b?.jersey_number||"").slice(0,30)||null,now
      ).run();
      return json(request,{ok:true,id},201);
    }

    // ---------- ADMIN PORTFOLIO LIST ----------
    if(url.pathname==="/api/admin/portfolio" && request.method==="GET"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const rows=await env.DB.prepare(`
        SELECT id,category,title,filename,original_key,preview_key,status,sort_order,is_cover,
               home_enabled,home_order,crop_desktop,crop_mobile,cover_crop_desktop,cover_crop_mobile,
               alt_text,caption,location,search_tags,
               seo_title,seo_description,created_at,updated_at
        FROM portfolio_items
        ORDER BY CASE WHEN status='active' THEN 0 ELSE 1 END,category,sort_order,created_at
      `).all();
      return json(request,{ok:true,items:(rows.results||[]).map(x=>({...x,
        preview_url:`/api/preview/${encodeURIComponent(x.preview_key)}`,
        crop_desktop:parseJson(x.crop_desktop),crop_mobile:parseJson(x.crop_mobile)
      }))});
    }

    // ---------- ADMIN PORTFOLIO UPLOAD ----------
    const poOrig=url.pathname.match(/^\/api\/admin\/portfolio\/([^/]+)\/original\/(.+)$/);
    if(poOrig && request.method==="PUT"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const id=safePart(decodeURIComponent(poOrig[1])),filename=safePart(decodeURIComponent(poOrig[2]));
      const key=`portfolio/originals/${id}/${filename}`;
      await env.ORIGINALS.put(key,request.body,{httpMetadata:{contentType:request.headers.get("Content-Type")||"image/jpeg"}});
      return json(request,{ok:true,key});
    }
    const poPrev=url.pathname.match(/^\/api\/admin\/portfolio\/([^/]+)\/preview\/(.+)$/);
    if(poPrev && request.method==="PUT"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const id=safePart(decodeURIComponent(poPrev[1])),filename=safePart(decodeURIComponent(poPrev[2]));
      const key=`portfolio/previews/${id}/${filename}`;
      await env.PREVIEWS.put(key,request.body,{httpMetadata:{contentType:request.headers.get("Content-Type")||"image/jpeg"}});
      return json(request,{ok:true,key});
    }
    if(url.pathname==="/api/admin/portfolio" && request.method==="POST"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const b=await bodyJson(request);
      if(!b?.id || !b?.category || !b?.filename || !b?.original_key || !b?.preview_key)
        return json(request,{ok:false,error:"id, category, filename, original_key and preview_key required"},400);
      if(!["sports","portraits","events","other"].includes(b.category))
        return json(request,{ok:false,error:"Invalid category"},400);
      const now=new Date().toISOString();
      await env.DB.prepare(`
        INSERT INTO portfolio_items(id,category,title,filename,original_key,preview_key,status,sort_order,is_cover,
          home_enabled,home_order,crop_desktop,crop_mobile,alt_text,caption,location,search_tags,seo_title,seo_description,created_at,updated_at)
        VALUES(?1,?2,?3,?4,?5,?6,'active',?7,0,0,0,NULL,NULL,?8,?9,?10,?11,?12,?13,?14,?14)
      `).bind(
        b.id,b.category,b.title||null,b.filename,b.original_key,b.preview_key,Number(b.sort_order||0),
        b.alt_text||null,b.caption||null,b.location||null,b.search_tags||null,b.seo_title||null,b.seo_description||null,now
      ).run();
      return json(request,{ok:true,id:b.id},201);
    }
    const poItem=url.pathname.match(/^\/api\/admin\/portfolio\/([^/]+)$/);
    if(poItem && request.method==="PATCH"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const id=decodeURIComponent(poItem[1]),b=await bodyJson(request),current=await env.DB.prepare(`SELECT * FROM portfolio_items WHERE id=?1`).bind(id).first();
      if(!current)return json(request,{ok:false,error:"Portfolio item not found"},404);
      const category=["sports","portraits","events","other"].includes(b?.category)?b.category:current.category;
      const status=["active","archived"].includes(b?.status)?b.status:current.status;
      const sortOrder=Number.isFinite(Number(b?.sort_order))?Number(b.sort_order):current.sort_order;
      const isCover=b?.is_cover===undefined?current.is_cover:(b.is_cover?1:0);
      const homeEnabled=b?.home_enabled===undefined?current.home_enabled:(b.home_enabled?1:0);
      const homeOrder=Number.isFinite(Number(b?.home_order))?Number(b.home_order):current.home_order;
      const cropDesktop=b?.crop_desktop===undefined?current.crop_desktop:JSON.stringify(b.crop_desktop);
      const cropMobile=b?.crop_mobile===undefined?current.crop_mobile:JSON.stringify(b.crop_mobile);
      const coverCropDesktop=b?.cover_crop_desktop===undefined?current.cover_crop_desktop:JSON.stringify(b.cover_crop_desktop);
      const coverCropMobile=b?.cover_crop_mobile===undefined?current.cover_crop_mobile:JSON.stringify(b.cover_crop_mobile);
      const title=b?.title===undefined?current.title:String(b.title||"").slice(0,200);
      const altText=b?.alt_text===undefined?current.alt_text:String(b.alt_text||"").slice(0,500);
      const caption=b?.caption===undefined?current.caption:String(b.caption||"").slice(0,1200);
      const location=b?.location===undefined?current.location:String(b.location||"").slice(0,300);
      const searchTags=b?.search_tags===undefined?current.search_tags:String(b.search_tags||"").slice(0,800);
      const seoTitle=b?.seo_title===undefined?current.seo_title:String(b.seo_title||"").slice(0,200);
      const seoDescription=b?.seo_description===undefined?current.seo_description:String(b.seo_description||"").slice(0,500);
      if(isCover){
        await env.DB.batch([
          env.DB.prepare(`UPDATE portfolio_items SET is_cover=0 WHERE category=?1 AND id<>?2`).bind(category,id),
          env.DB.prepare(`UPDATE legacy_portfolio_settings SET is_cover=0 WHERE category=?1`).bind(category)
        ]);
      }
      await env.DB.prepare(`
        UPDATE portfolio_items SET category=?1,status=?2,sort_order=?3,is_cover=?4,home_enabled=?5,home_order=?6,
          crop_desktop=?7,crop_mobile=?8,cover_crop_desktop=?9,cover_crop_mobile=?10,
          title=?11,alt_text=?12,caption=?13,location=?14,search_tags=?15,
          seo_title=?16,seo_description=?17,updated_at=?18 WHERE id=?19
      `).bind(
        category,status,sortOrder,isCover,homeEnabled,homeOrder,cropDesktop,cropMobile,
        coverCropDesktop,coverCropMobile,title,altText,caption,location,searchTags,
        seoTitle,seoDescription,new Date().toISOString(),id
      ).run();
      return json(request,{ok:true,id});
    }
    if(poItem && request.method==="DELETE"){
      const auth=requireAdmin(request,env); if(auth)return auth;
      const id=decodeURIComponent(poItem[1]),b=await bodyJson(request);
      if(b?.confirm!=="DELETE")return json(request,{ok:false,error:'Permanent deletion requires confirm: "DELETE"'},400);
      const item=await env.DB.prepare(`SELECT original_key,preview_key FROM portfolio_items WHERE id=?1`).bind(id).first();
      if(!item)return json(request,{ok:false,error:"Portfolio item not found"},404);
      await Promise.all([env.ORIGINALS.delete(item.original_key),env.PREVIEWS.delete(item.preview_key)]);
      await env.DB.prepare(`DELETE FROM portfolio_items WHERE id=?1`).bind(id).run();
      return json(request,{ok:true,id,deleted:true});
    }

    // ---------- ADMIN GALLERIES ----------
    if(url.pathname==="/api/admin/galleries" && request.method==="GET"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const rows=await env.DB.prepare(`
        SELECT
          g.id,g.title,g.shoot_date,g.status,g.created_at,g.updated_at,g.archived_at,
          g.cover_photo_id,g.cover_crop_desktop,g.cover_crop_mobile,
          cp.preview_key AS cover_preview_key,
          COUNT(p.id) AS photo_count
        FROM galleries g
        LEFT JOIN photos p ON p.gallery_id=g.id
        LEFT JOIN photos cp ON cp.id=g.cover_photo_id AND cp.gallery_id=g.id
        GROUP BY g.id
        ORDER BY CASE WHEN g.archived_at IS NULL THEN 0 ELSE 1 END,COALESCE(g.shoot_date,g.created_at) DESC
      `).all();
      const galleries=(rows.results||[]).map(g=>({
        ...g,
        cover_crop_desktop:safeJsonParse(g.cover_crop_desktop,null),
        cover_crop_mobile:safeJsonParse(g.cover_crop_mobile,null),
        cover_preview_url:g.cover_preview_key
          ? `/api/preview/${encodeURIComponent(g.cover_preview_key)}`
          : null
      }));
      return json(request,{ok:true,galleries});
    }

    const adminGalleryDetail=url.pathname.match(/^\/api\/admin\/galleries\/([^/]+)\/photos$/);
    if(adminGalleryDetail && request.method==="GET"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const id=decodeURIComponent(adminGalleryDetail[1]);
      const gallery=await env.DB.prepare(`
        SELECT
          g.id,g.title,g.shoot_date,g.status,g.archived_at,
          g.cover_photo_id,g.cover_crop_desktop,g.cover_crop_mobile,
          cp.preview_key AS cover_preview_key
        FROM galleries g
        LEFT JOIN photos cp ON cp.id=g.cover_photo_id AND cp.gallery_id=g.id
        WHERE g.id=?1
      `).bind(id).first();
      if(!gallery)return json(request,{ok:false,error:"Gallery not found"},404);
      gallery.cover_crop_desktop=safeJsonParse(gallery.cover_crop_desktop,null);
      gallery.cover_crop_mobile=safeJsonParse(gallery.cover_crop_mobile,null);
      gallery.cover_preview_url=gallery.cover_preview_key
        ? `/api/preview/${encodeURIComponent(gallery.cover_preview_key)}`
        : null;
      const photos=await env.DB.prepare(`
        SELECT id,filename,original_key,preview_key,width,height,sort_order
        FROM photos WHERE gallery_id=?1 ORDER BY sort_order,filename
      `).bind(id).all();
      return json(request,{ok:true,gallery,photos:(photos.results||[]).map(p=>({...p,preview_url:`/api/preview/${encodeURIComponent(p.preview_key)}`}))});
    }

    const adminPhotoDelete=url.pathname.match(/^\/api\/admin\/photos\/([^/]+)$/);
    if(adminPhotoDelete && request.method==="DELETE"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const photoId=decodeURIComponent(adminPhotoDelete[1]);
      const photo=await env.DB.prepare(`SELECT id,gallery_id,original_key,preview_key FROM photos WHERE id=?1`).bind(photoId).first();
      if(!photo)return json(request,{ok:false,error:"Photo not found"},404);
      const purchases=await env.DB.prepare(`SELECT COUNT(*) AS c FROM order_items WHERE photo_id=?1`).bind(photoId).first();
      if(Number(purchases?.c||0)>0)return json(request,{ok:false,error:"This photo has purchase records and cannot be deleted. Archive the gallery or keep the photo available for fulfillment."},409);
      await Promise.all([env.ORIGINALS.delete(photo.original_key),env.PREVIEWS.delete(photo.preview_key)]);
      await env.DB.batch([
        env.DB.prepare(`DELETE FROM favorites WHERE photo_id=?1`).bind(photoId),
        env.DB.prepare(`DELETE FROM photos WHERE id=?1`).bind(photoId)
      ]);
      return json(request,{ok:true,id:photoId,deleted:true});
    }

    if(url.pathname==="/api/admin/galleries" && request.method==="POST"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const b=await bodyJson(request);if(!b||!String(b.title||"").trim())return json(request,{ok:false,error:"Shoot title is required"},400);
      const id=safePart(b.id)||uid("gallery"),title=String(b.title).trim().slice(0,200),shootDate=b.shoot_date||null,
        status=["draft","published","private"].includes(b.status)?b.status:"draft",now=new Date().toISOString();
      await env.DB.prepare(`INSERT INTO galleries(id,title,shoot_date,status,created_at,updated_at,archived_at) VALUES(?1,?2,?3,?4,?5,?5,NULL)`)
        .bind(id,title,shootDate,status,now).run();
      return json(request,{ok:true,gallery:{id,title,shoot_date:shootDate,status}},201);
    }
    const galleryCoverMatch=url.pathname.match(/^\/api\/admin\/galleries\/([^/]+)\/cover$/);
    if(galleryCoverMatch && request.method==="PATCH"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const id=decodeURIComponent(galleryCoverMatch[1]);
      const b=await bodyJson(request)||{};

      const gallery=await env.DB.prepare(`
        SELECT id FROM galleries WHERE id=?1
      `).bind(id).first();
      if(!gallery)return json(request,{ok:false,error:"Gallery not found"},404);

      let coverPhotoId=b.cover_photo_id===null?null:String(b.cover_photo_id||"").trim()||null;

      if(coverPhotoId){
        const photo=await env.DB.prepare(`
          SELECT id FROM photos WHERE id=?1 AND gallery_id=?2
        `).bind(coverPhotoId,id).first();
        if(!photo){
          return json(request,{
            ok:false,
            error:"Cover photo must belong to this gallery."
          },400);
        }
      }

      function normalizeCoverCrop(crop){
        if(crop===null || crop===undefined)return null;
        const x=Math.max(0,Math.min(100,Number(crop.x)||0));
        const y=Math.max(0,Math.min(100,Number(crop.y)||0));
        const w=Math.max(1,Math.min(100,Number(crop.w)||100));
        const h=Math.max(1,Math.min(100,Number(crop.h)||100));
        return {x,y,w,h,excluded:Boolean(crop.excluded)};
      }

      const desktop=normalizeCoverCrop(b.cover_crop_desktop);
      const mobile=normalizeCoverCrop(b.cover_crop_mobile);
      const now=new Date().toISOString();

      await env.DB.prepare(`
        UPDATE galleries
        SET cover_photo_id=?1,
            cover_crop_desktop=?2,
            cover_crop_mobile=?3,
            updated_at=?4
        WHERE id=?5
      `).bind(
        coverPhotoId,
        desktop?JSON.stringify(desktop):null,
        mobile?JSON.stringify(mobile):null,
        now,
        id
      ).run();

      return json(request,{
        ok:true,
        id,
        cover_photo_id:coverPhotoId,
        cover_crop_desktop:desktop,
        cover_crop_mobile:mobile
      });
    }

    const archiveMatch=url.pathname.match(/^\/api\/admin\/galleries\/([^/]+)\/archive$/);
    if(archiveMatch && request.method==="PATCH"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const id=decodeURIComponent(archiveMatch[1]),b=await bodyJson(request),archived=Boolean(b?.archived),now=new Date().toISOString();
      await env.DB.prepare(`UPDATE galleries SET archived_at=?1,updated_at=?2 WHERE id=?3`).bind(archived?now:null,now,id).run();
      return json(request,{ok:true,id,archived});
    }
    const galleryDelete=url.pathname.match(/^\/api\/admin\/galleries\/([^/]+)$/);
    if(galleryDelete && request.method==="DELETE"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const id=decodeURIComponent(galleryDelete[1]),b=await bodyJson(request);
      if(b?.confirm!=="DELETE")return json(request,{ok:false,error:'Permanent deletion requires confirm: "DELETE"'},400);
      const gallery=await env.DB.prepare(`SELECT id FROM galleries WHERE id=?1`).bind(id).first();
      if(!gallery)return json(request,{ok:false,error:"Gallery not found"},404);
      const purchases=await env.DB.prepare(`
        SELECT COUNT(*) AS c FROM order_items oi JOIN photos p ON p.id=oi.photo_id WHERE p.gallery_id=?1
      `).bind(id).first();
      if(Number(purchases?.c||0)>0)return json(request,{ok:false,error:"This gallery has purchase records and cannot be permanently deleted. Archive it instead."},409);
      const [od,pd]=await Promise.all([deletePrefix(env.ORIGINALS,`originals/${safePart(id)}/`),deletePrefix(env.PREVIEWS,`previews/${safePart(id)}/`)]);
      await env.DB.batch([
        env.DB.prepare(`DELETE FROM favorites WHERE photo_id IN (SELECT id FROM photos WHERE gallery_id=?1)`).bind(id),
        env.DB.prepare(`DELETE FROM access_grants WHERE gallery_id=?1`).bind(id),
        env.DB.prepare(`DELETE FROM photos WHERE gallery_id=?1`).bind(id),
        env.DB.prepare(`DELETE FROM galleries WHERE id=?1`).bind(id)
      ]);
      return json(request,{ok:true,id,deleted:true,originalsDeleted:od,previewsDeleted:pd});
    }
    const origMatch=url.pathname.match(/^\/api\/admin\/galleries\/([^/]+)\/original\/(.+)$/);
    if(origMatch && request.method==="PUT"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const gid=safePart(decodeURIComponent(origMatch[1])),fn=safePart(decodeURIComponent(origMatch[2])),key=`originals/${gid}/${fn}`;
      await env.ORIGINALS.put(key,request.body,{httpMetadata:{contentType:request.headers.get("Content-Type")||"image/jpeg"}});
      return json(request,{ok:true,key});
    }
    const prevMatch=url.pathname.match(/^\/api\/admin\/galleries\/([^/]+)\/preview\/(.+)$/);
    if(prevMatch && request.method==="PUT"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const gid=safePart(decodeURIComponent(prevMatch[1])),fn=safePart(decodeURIComponent(prevMatch[2])),key=`previews/${gid}/${fn}`;
      await env.PREVIEWS.put(key,request.body,{httpMetadata:{contentType:request.headers.get("Content-Type")||"image/jpeg"}});
      return json(request,{ok:true,key});
    }
    if(url.pathname==="/api/admin/photos" && request.method==="POST"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const b=await bodyJson(request);if(!b?.gallery_id||!b?.filename||!b?.original_key||!b?.preview_key)
        return json(request,{ok:false,error:"gallery_id, filename, original_key and preview_key are required"},400);
      const id=b.id||uid("photo");
      await env.DB.prepare(`INSERT INTO photos(id,gallery_id,filename,original_key,preview_key,width,height,sort_order,created_at)
        VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)`)
        .bind(id,b.gallery_id,b.filename,b.original_key,b.preview_key,b.width||null,b.height||null,Number(b.sort_order||0),new Date().toISOString()).run();
      await queueClientGalleryPhotoNotifications(env,b.gallery_id,id);
      return json(request,{ok:true,id},201);
    }
    const statusMatch=url.pathname.match(/^\/api\/admin\/galleries\/([^/]+)\/status$/);
    if(statusMatch && request.method==="PATCH"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const id=decodeURIComponent(statusMatch[1]),b=await bodyJson(request);
      if(!["draft","published","private"].includes(b?.status))return json(request,{ok:false,error:"Invalid status"},400);
      await env.DB.prepare(`UPDATE galleries SET status=?1,updated_at=?2 WHERE id=?3`).bind(b.status,new Date().toISOString(),id).run();
      return json(request,{ok:true,id,status:b.status});
    }

    // ---------- ADMIN FREE ACCESS ----------
    if(url.pathname==="/api/admin/access-grants" && request.method==="POST"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const b=await bodyJson(request);if(!b?.email||!b?.gallery_id)return json(request,{ok:false,error:"email and gallery_id are required"},400);
      const id=uid("grant");
      await env.DB.prepare(`INSERT INTO access_grants(id,email,gallery_id,access_type,expires_at,created_at)
        VALUES(?1,lower(?2),?3,?4,?5,?6)`)
        .bind(id,String(b.email).trim(),b.gallery_id,b.access_type||"full_digital",b.expires_at||null,new Date().toISOString()).run();
      return json(request,{ok:true,id},201);
    }
    if(url.pathname==="/api/admin/access-grants" && request.method==="GET"){
      const auth=requireAdmin(request,env);if(auth)return auth;
      const rows=await env.DB.prepare(`SELECT id,email,gallery_id,access_type,expires_at,created_at FROM access_grants ORDER BY created_at DESC`).all();
      return json(request,{ok:true,grants:rows.results||[]});
    }

    return json(request,{ok:false,error:"Route not found"},404);
  }
};
