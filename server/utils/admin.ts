import type { H3Event } from 'h3'

/**
 * Ensures the request is from an admin by checking the x-admin-token header.
 * @param event - H3 event
 * @throws 401 Unauthorized if the token is missing or invalid
 */
export async function requireAdmin(event: H3Event): Promise<void> {
  const config = useRuntimeConfig()
  const adminToken = config.adminToken || process.env.ADMIN_TOKEN

  if (!adminToken) {
    throw createError({
      statusCode: 500,
      statusMessage: 'ADMIN_TOKEN not configured',
    })
  }

  const token = getHeader(event, 'x-admin-token')

  if (!token || token !== adminToken) {
    throw createError({
      statusCode: 401,
      statusMessage: 'Unauthorized: Admin access required',
    })
  }
}
