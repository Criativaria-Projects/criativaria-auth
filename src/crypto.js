// HMAC-SHA256 signing via Web Crypto — same token format used across
// Criativaria staging gates: base64url(payload).base64url(signature)

function b64urlEncode(input) {
  const str = input instanceof ArrayBuffer ? String.fromCharCode(...new Uint8Array(input)) : input
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

function b64urlDecode(str) {
  return atob(str.replace(/-/g, '+').replace(/_/g, '/'))
}

async function getKey(secret) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  )
}

export async function sign(payload, secret, durationMs) {
  const data = b64urlEncode(JSON.stringify({ ...payload, exp: Date.now() + durationMs }))
  const key = await getKey(secret)
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data))
  return `${data}.${b64urlEncode(sig)}`
}

export async function verify(token, secret) {
  try {
    if (!token) return null
    const dot = token.lastIndexOf('.')
    if (dot < 0) return null
    const data = token.slice(0, dot)
    const sig = token.slice(dot + 1)
    const key = await getKey(secret)
    const sigBytes = Uint8Array.from(b64urlDecode(sig), (c) => c.charCodeAt(0))
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(data))
    if (!valid) return null
    const payload = JSON.parse(b64urlDecode(data))
    if (payload.exp < Date.now()) return null
    return payload
  } catch {
    return null
  }
}
