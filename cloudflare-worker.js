const REPO = "TechArtService/tehart-catalog";
const BRANCH = "main";
const INDEX_PATH = "index.html";
const enc = new TextEncoder();

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "https://techartservice.ru", "Access-Control-Allow-Headers": "Authorization, Content-Type", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Vary": "Origin" }
  });
}
function b64u(bytes) {
  let s = ""; for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
}
async function sign(payload, secret) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), {name:"HMAC",hash:"SHA-256"}, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", key, enc.encode(payload)));
}
async function makeToken(secret) {
  const payload = btoa(JSON.stringify({ exp: Date.now() + 8*60*60*1000 })).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
  return payload + "." + await sign(payload, secret);
}
async function authorized(request, env) {
  const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i,"");
  const [payload, sig] = token.split(".");
  if (!payload || !sig || sig !== await sign(payload, env.ADMIN_PASSWORD)) return false;
  try { return JSON.parse(atob(payload.replace(/-/g,"+").replace(/_/g,"/"))).exp > Date.now(); } catch { return false; }
}
async function gh(path, env, options = {}) {
  const r = await fetch("https://api.github.com/repos/" + REPO + "/contents/" + path, {
    ...options,
    headers: {
      "Authorization": "Bearer " + env.GITHUB_TOKEN,
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "TechArt-Admin",
      ...(options.headers || {})
    }
  });
  const body = await r.json();
  if (!r.ok) throw new Error("GitHub HTTP " + r.status + ": " + JSON.stringify(body));
  return body;
}
async function readCatalog(env) {
  const file = await gh(INDEX_PATH + "?ref=" + BRANCH, env);
  const binary = atob(file.content.replace(/\n/g,""));
  const html = new TextDecoder().decode(Uint8Array.from(binary, c => c.charCodeAt(0)));
  const match = html.match(/const products = (\[.*?\]);\s*\n/s);
  if (!match) throw new Error("Не удалось найти массив products в index.html");
  return { html, products: JSON.parse(match[1]), sha: file.sha };
}
function statusActive(v) {
  const s = String(v ?? "").toLowerCase();
  return !s || /active|актив|размещ|опублик/.test(s);
}
function clean(v) { return v == null ? "" : String(v).trim(); }
function normalizePhoto(value) {
  const raw = clean(value);
  if (!raw) return "";
  try {
    const u = new URL(raw);
    const host = u.hostname.toLowerCase();
    if ((host === "avito.ru" || host === "www.avito.ru") && u.pathname.startsWith("/autoload/")) {
      u.protocol = "https:";
      u.hostname = "www.avito.ru";
      return u.toString();
    }
    return raw;
  } catch { return raw; }
}
function normalize(row) {
  const id = clean(row.AvitoId || row.id || row.ID);
  if (!id) return null;
  const photos = clean(row.ImageUrls || row.photos).split("|").map(normalizePhoto).filter(Boolean);
  const title = clean(row.Title || row.title);
  const p = {
    id, title, price: clean(row.Price || row.price),
    brand: clean(row.Brand || row.brand), model: clean(row.Model || row.model),
    diameter: clean(row.RimDiameter || row.diameter),
    holes: clean(row.RimBolts || row.holes),
    pcd: clean(row.RimBoltsDiameter || row.pcd),
    dia: clean(row.RimDIA || row.dia),
    et: clean(row.RimOffset || row.et),
    width: clean(row.RimWidth || row.width),
    quantity: clean(row.Quantity || row.quantity),
    status: statusActive(row.AvitoStatus || row.status) ? "active" : "inactive",
    description: clean(row.Description || row.description),
    photos,
    url: "https://www.avito.ru/" + id
  };
  return p;
}
function diff(oldProducts, incoming) {
  const old = new Map(oldProducts.map(p=>[String(p.id),p]));
  const next = new Map(incoming.map(p=>[String(p.id),p]));
  const added=[], changed=[], unchanged=[];
  for (const p of incoming) {
    const prev=old.get(p.id);
    if (!prev) added.push(p);
    else if (JSON.stringify(prev)!==JSON.stringify(p)) changed.push({before:prev,after:p});
    else unchanged.push(p);
  }
  const inactive=[];
  for (const p of oldProducts) if (!next.has(String(p.id))) inactive.push({...p,status:"inactive"});
  return {added,changed,unchanged,inactive,total:incoming.length};
}
async function handle(request, env) {
  if (request.method === "OPTIONS") return new Response(null, {status:204, headers:{"Access-Control-Allow-Origin":"https://techartservice.ru","Access-Control-Allow-Headers":"Authorization, Content-Type","Access-Control-Allow-Methods":"GET, POST, OPTIONS","Access-Control-Max-Age":"86400","Vary":"Origin"}});
  const url = new URL(request.url);
  if (url.pathname === "/api/login" && request.method === "POST") {
    if (!env.ADMIN_PASSWORD) return json({error:"Не задан секрет ADMIN_PASSWORD"},500);
    const body=await request.json();
    if (!body.password || body.password !== env.ADMIN_PASSWORD) return json({error:"Неверный пароль"},401);
    return json({token:await makeToken(env.ADMIN_PASSWORD)});
  }
  if (!url.pathname.startsWith("/api/")) return fetch(request);
  if (!await authorized(request,env)) return json({error:"Требуется вход"},401);
  if (url.pathname === "/api/avito-auth-check" && request.method === "POST") {
    const clientId = env.AVITO_PERSONAL_CLIENT_ID;
    const clientSecret = env.AVITO_PERSONAL_CLIENT_SECRET;
    if (!clientId || !clientSecret) {
      return json({ok:false, stage:"configuration", error:"Не заданы AVITO_PERSONAL_CLIENT_ID и/или AVITO_PERSONAL_CLIENT_SECRET"},500);
    }

    const tokenResponse = await fetch("https://api.avito.ru/token/", {
      method:"POST",
      headers:{"Content-Type":"application/x-www-form-urlencoded","Accept":"application/json"},
      body:new URLSearchParams({
        grant_type:"client_credentials",
        client_id:clientId,
        client_secret:clientSecret
      })
    });
    if (!tokenResponse.ok) {
      return json({ok:false,stage:"token",httpStatus:tokenResponse.status,error:"Avito не выдал токен. Проверьте ключи и доступ приложения."},502);
    }
    const tokenData = await tokenResponse.json();
    if (!tokenData.access_token) {
      return json({ok:false,stage:"token",error:"В ответе Avito отсутствует access_token"},502);
    }

    const accountResponse = await fetch("https://api.avito.ru/core/v1/accounts/self", {
      headers:{"Authorization":"Bearer "+tokenData.access_token,"Accept":"application/json"}
    });
    if (!accountResponse.ok) {
      return json({ok:false,stage:"account",httpStatus:accountResponse.status,error:"Токен получен, но запрос профиля не прошёл."},502);
    }
    const account = await accountResponse.json();

    const itemsResponse = await fetch("https://api.avito.ru/core/v1/items?per_page=1", {
      headers:{"Authorization":"Bearer "+tokenData.access_token,"Accept":"application/json"}
    });
    if (!itemsResponse.ok) {
      return json({ok:false,stage:"items",httpStatus:itemsResponse.status,accountCheck:"ok",error:"Профиль доступен, но чтение объявлений не разрешено или завершилось ошибкой."},502);
    }
    const items = await itemsResponse.json();
    const list = Array.isArray(items.resources) ? items.resources : (Array.isArray(items.items) ? items.items : []);
    return json({
      ok:true,
      stage:"complete",
      tokenExpiresIn:Number(tokenData.expires_in)||86400,
      accountId:account.id||account.user_id||null,
      accountCheck:"ok",
      itemsCheck:"ok",
      sampleCount:list.length,
      responseKeys:Object.keys(items)
    });
  }
  if (url.pathname === "/api/resolve-photos" && request.method === "POST") {
    const body = await request.json();
    if (!Array.isArray(body.urls) || body.urls.length < 1 || body.urls.length > 10) {
      return json({error:"Передайте от 1 до 10 ссылок"},400);
    }
    const results = await Promise.all(body.urls.map(async (raw) => {
      const input = clean(raw);
      try {
        let target = new URL(input);
        const allowed = (u) => {
          const h = u.hostname.toLowerCase();
          return (h === "avito.ru" || h.endsWith(".avito.ru") || h === "avito.st" || h.endsWith(".avito.st")) &&
            (u.protocol === "https:" || u.protocol === "http:") && !u.username && !u.password;
        };
        if (!allowed(target)) return {input, resolved:input, ok:false, error:"Недопустимый домен"};
        if (!target.pathname.startsWith("/autoload/")) {
          return {input, resolved:input, ok:/\.img\.avito\.st$/i.test(target.hostname), error:/\.img\.avito\.st$/i.test(target.hostname) ? "" : "Это не прямая ссылка CDN"};
        }
        let response;
        for (let i=0; i<6; i++) {
          response = await fetch(target.toString(), {
            method:"GET", redirect:"manual",
            headers:{"Range":"bytes=0-31","User-Agent":"Mozilla/5.0 (compatible; TechArtImageResolver/1.0)"}
          });
          if (![301,302,303,307,308].includes(response.status)) break;
          const location = response.headers.get("Location");
          if (!location) break;
          const next = new URL(location,target);
          if (!allowed(next)) return {input, resolved:input, ok:false, error:"Редирект на внешний домен заблокирован"};
          target = next;
        }
        const type = response?.headers.get("Content-Type") || "";
        const ok = !!response && response.status >= 200 && response.status < 300 &&
          /^image\//i.test(type) && /\.img\.avito\.st$/i.test(target.hostname);
        try { await response?.body?.cancel(); } catch {}
        return {input, resolved:ok ? target.toString() : input, ok, status:response?.status || 0, contentType:type, error:ok ? "" : "Avito не вернул доступную прямую ссылку на изображение"};
      } catch(e) {
        return {input, resolved:input, ok:false, error:e.message};
      }
    }));
    return json({results});
  }
  if (url.pathname === "/api/image-check" && request.method === "POST") {
    const body = await request.json();
    if (!Array.isArray(body.urls) || body.urls.length < 1 || body.urls.length > 3) {
      return json({error:"Передайте от 1 до 3 ссылок"},400);
    }
    const results = await Promise.all(body.urls.map(async (raw) => {
      try {
        let target = new URL(String(raw));
        const allowed = (u) => {
          const h = u.hostname.toLowerCase();
          return (h === "avito.ru" || h.endsWith(".avito.ru") || h === "avito.st" || h.endsWith(".avito.st")) &&
            (u.protocol === "https:" || u.protocol === "http:") && !u.username && !u.password;
        };
        if (!allowed(target)) return {input:raw,error:"Недопустимый домен или протокол"};
        let response;
        for (let i=0; i<6; i++) {
          response = await fetch(target.toString(), {
            method:"GET", redirect:"manual",
            headers:{"Range":"bytes=0-31","User-Agent":"Mozilla/5.0 (compatible; TechArtImageCheck/1.0)"}
          });
          if (![301,302,303,307,308].includes(response.status)) break;
          const location = response.headers.get("Location");
          if (!location) break;
          const next = new URL(location,target);
          if (!allowed(next)) return {input:raw,status:response.status,error:"Перенаправление на внешний домен заблокировано",redirect:next.hostname};
          target = next;
        }
        if (!response) return {input:raw,error:"Не удалось выполнить запрос"};
        const result = {
          input:raw, status:response.status, finalUrl:target.toString(),
          contentType:response.headers.get("Content-Type") || "",
          contentLength:response.headers.get("Content-Length") || "",
          contentRange:response.headers.get("Content-Range") || ""
        };
        try { await response.body?.cancel(); } catch {}
        return result;
      } catch(e) {
        return {input:raw,error:e.message};
      }
    }));
    return json({results});
  }
  if (url.pathname === "/api/catalog" && request.method === "GET") {
    const c=await readCatalog(env); return json({count:c.products.length,products:c.products});
  }
  if (url.pathname === "/api/preview" && request.method === "POST") {
    const body=await request.json();
    if (!Array.isArray(body.rows) || body.rows.length===0) return json({error:"В файле не найдены строки объявлений"},400);
    const incoming=body.rows.map(normalize).filter(Boolean);
    const c=await readCatalog(env);
    return json(diff(c.products,incoming));
  }
  if (url.pathname === "/api/apply" && request.method === "POST") {
    const body=await request.json();
    if (!Array.isArray(body.rows) || !body.confirm) return json({error:"Нет подтверждения или данных"},400);
    const incoming=body.rows.map(normalize).filter(Boolean);
    if (!incoming.length) return json({error:"Нет объявлений для импорта"},400);
    const c=await readCatalog(env);
    const changes=diff(c.products,incoming);
    const merged=new Map(c.products.map(p=>[String(p.id),p]));
    for (const p of incoming) merged.set(p.id,p);
    for (const p of changes.inactive) merged.set(p.id,p);
    const products=[...merged.values()];
    const replacement="const products = "+JSON.stringify(products)+";";
    const html=c.html.replace(/const products = \[.*?\];/s,replacement);
    const content=btoa(unescape(encodeURIComponent(html)));
    const result=await gh(INDEX_PATH,env,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify({
      message:"Обновление каталога из Excel Авито",
      content,sha:c.sha,branch:BRANCH
    })});
    return json({status:"OK",commit:result.commit.sha,added:changes.added.length,changed:changes.changed.length,inactivated:changes.inactive.length,total:products.length});
  }
  return json({error:"Неизвестный API маршрут"},404);
}
export default {
  async fetch(request, env) {
    try { return await handle(request,env); }
    catch(e) { return json({error:e.message},500); }
  }
};