import * as jose from 'jose'

export const GA_SCOPES = 'https://www.googleapis.com/auth/analytics.readonly'
export const GSC_SCOPES = 'https://www.googleapis.com/auth/webmasters.readonly'

/**
 * Fetches data from a Google API using a service account JWT.
 * @param url - The Google API endpoint
 * @param scope - The requested OAuth scope(s)
 * @param options - Additional fetch options
 * @returns The JSON response from the API
 */
export async function googleApiFetch(
  url: string,
  scope: string,
  options: RequestInit = {},
): Promise<any> {
  const config = useRuntimeConfig()
  const serviceAccountKey = config.googleServiceAccountKey

  if (!serviceAccountKey) {
    throw createError({
      statusCode: 500,
      statusMessage: 'GOOGLE_SERVICE_ACCOUNT_KEY not configured',
    })
  }

  let key: any
  try {
    key = JSON.parse(serviceAccountKey)
  } catch (_e) {
    throw createError({
      statusCode: 500,
      statusMessage: 'Failed to parse GOOGLE_SERVICE_ACCOUNT_KEY',
    })
  }

  // Create JWT for Google API authentication
  const jwt = await new jose.SignJWT({
    iss: key.client_email,
    scope: scope,
    aud: 'https://oauth2.googleapis.com/token',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
  })
    .setProtectedHeader({ alg: 'RS256' })
    .sign(await jose.importPKCS8(key.private_key, 'RS256'))

  // Exchange JWT for access token
  const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  })

  if (!tokenResponse.ok) {
    const errorData = await tokenResponse.json()
    throw createError({
      statusCode: tokenResponse.status,
      statusMessage: `Google Auth Error: ${errorData.error_description || errorData.error}`,
    })
  }

  const { access_token } = await tokenResponse.json()

  // Make the actual API request
  const response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      Authorization: `Bearer ${access_token}`,
    },
  })

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}))
    throw createError({
      statusCode: response.status,
      statusMessage: `Google API Error (${response.status}): ${errorData.error?.message || response.statusText}`,
    })
  }

  return response.json()
}
