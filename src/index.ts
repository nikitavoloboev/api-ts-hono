import { Hono } from "hono"
import { cors } from "hono/cors"
import { env } from "cloudflare:workers"

type Env = {
  Bindings: {
    GOOGLE_CLOUD_SERVICE_ACCOUNT_KEY: string
    BUCKET_NAME: string
  }
}

const app = new Hono<Env>()

app.use("*", cors())

function base64urlEncode(data: string): string {
  return Buffer.from(data)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "")
}

async function importPrivateKey(pem: string): Promise<CryptoKey> {
  const pemContents = pem.replace(
    /-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s+/g,
    ""
  )
  const binaryDer = atob(pemContents)
  const binaryDerArray = new Uint8Array(binaryDer.length)
  for (let i = 0; i < binaryDer.length; i++) {
    binaryDerArray[i] = binaryDer.charCodeAt(i)
  }
  return crypto.subtle.importKey(
    "pkcs8",
    binaryDerArray,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  )
}

async function sign(data: string, privateKeyPem: string): Promise<string> {
  const privateKey = await importPrivateKey(privateKeyPem)
  const encoder = new TextEncoder()
  const encodedData = encoder.encode(data)
  const signature = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    privateKey,
    encodedData
  )
  return base64urlEncode(Buffer.from(signature).toString("base64"))
}

interface TokenResponse {
  access_token: string
}

app.post("/upload", async (c) => {
  try {
    const formData = await c.req.formData()
    const file = formData.get("image") as File | null
    if (!file) {
      return c.text("Missing image file", 400)
    }
    const serviceAccountKey = JSON.parse(c.env.GOOGLE_CLOUD_SERVICE_ACCOUNT_KEY)
    const clientEmail = serviceAccountKey.client_email
    const privateKey = serviceAccountKey.private_key
    const header = { alg: "RS256", typ: "JWT" }
    const payload = {
      iss: clientEmail,
      scope: "https://www.googleapis.com/auth/devstorage.read_write",
      aud: "https://oauth2.googleapis.com/token",
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    }
    const encodedHeader = base64urlEncode(JSON.stringify(header))
    const encodedPayload = base64urlEncode(JSON.stringify(payload))
    const unsignedToken = `${encodedHeader}.${encodedPayload}`
    const signature = await sign(unsignedToken, privateKey)
    const jwt = `${unsignedToken}.${signature}`
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
    })
    if (!tokenResponse.ok) {
      throw new Error("Failed to get access token")
    }
    const tokenData = (await tokenResponse.json()) as TokenResponse
    const accessToken = tokenData.access_token
    const bucketName = c.env.BUCKET_NAME
    const objectName = `images/${Date.now()}-${file.name}`
    const metadata = { name: objectName, contentType: file.type }
    const boundary =
      "----WebKitFormBoundary" +
      crypto
        .getRandomValues(new Uint32Array(4))
        .map((n) => parseInt(n.toString(36), 36))
        .join("")
    const encoder = new TextEncoder()
    const metadataPart = `--${boundary}\r\nContent-Type: application/json\r\n\r\n${JSON.stringify(
      metadata
    )}\r\n`
    const filePart = `--${boundary}\r\nContent-Type: ${file.type}\r\n\r\n`
    const endPart = `\r\n--${boundary}--`
    const metadataBytes = encoder.encode(metadataPart)
    const fileHeaderBytes = encoder.encode(filePart)
    const fileContent = await file.arrayBuffer()
    const endBytes = encoder.encode(endPart)
    const body = new Uint8Array(
      metadataBytes.length +
        fileHeaderBytes.length +
        fileContent.byteLength +
        endBytes.length
    )
    let offset = 0
    body.set(metadataBytes, offset)
    offset += metadataBytes.length
    body.set(fileHeaderBytes, offset)
    offset += fileHeaderBytes.length
    body.set(new Uint8Array(fileContent), offset)
    offset += fileContent.byteLength
    body.set(endBytes, offset)
    const uploadResponse = await fetch(
      `https://storage.googleapis.com/upload/storage/v1/b/${bucketName}/o?uploadType=multipart&predefinedAcl=publicRead`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": `multipart/related; boundary=${boundary}`,
        },
        body,
      }
    )
    if (!uploadResponse.ok) {
      throw new Error("Failed to upload image")
    }
    const publicUrl = `https://storage.googleapis.com/${bucketName}/${objectName}`
    return c.text(`Image uploaded successfully: ${publicUrl}`)
  } catch (error) {
    console.error(error)
    return c.text("Internal Server Error", 500)
  }
})

export default app
