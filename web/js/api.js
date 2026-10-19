// HTTP qatı: cookie sessiyası (HttpOnly, JS görmür) + X-CSRF-Token başlığı.
let csrf = null;
export function setCsrf(v) { csrf = v; }

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.message || `HTTP ${status}`);
    this.status = status; this.code = body?.error; this.body = body;
  }
}

export async function api(method, path, body) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (csrf && method !== "GET") headers["X-CSRF-Token"] = csrf;
  const resp = await fetch(path, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin", cache: "no-store",
  });
  let data = null;
  try { data = await resp.json(); } catch { /* boş cavab */ }
  if (!resp.ok) throw new ApiError(resp.status, data);
  return data;
}
export const get = (p) => api("GET", p);
export const post = (p, b = {}) => api("POST", p, b);
export const put = (p, b) => api("PUT", p, b);
export const patch = (p, b) => api("PATCH", p, b);
export const del = (p, b) => api("DELETE", p, b);
