import fs from "node:fs";
import { BASE_API_URL } from "./api.js";
import { z } from "zod";

const VANTA_API_SCOPE = "vanta-api.all:read";

interface OAuthCredentials {
  client_id: string;
  client_secret: string;
}

interface TokenInfo {
  token: string;
  expiresAt: number;
}

let currentToken: TokenInfo | null = null;

const TokenResponseSchema = z.object({
  access_token: z.string(),
  expires_in: z.number(),
  token_type: z.string(),
});

/**
 * Loads OAuth credentials from environment variables.
 * Supports VANTA_CLIENT_ID and VANTA_CLIENT_SECRET env vars directly,
 * or falls back to a JSON file specified by VANTA_ENV_FILE.
 * @throws {Error} If credentials cannot be found or are invalid.
 * @returns {OAuthCredentials} The loaded and validated credentials.
 */
function loadCredentials(): OAuthCredentials {
  const clientId = process.env.VANTA_CLIENT_ID;
  const clientSecret = process.env.VANTA_CLIENT_SECRET;

  if (clientId && clientSecret) {
    return { client_id: clientId, client_secret: clientSecret };
  }

  const envFile = process.env.VANTA_ENV_FILE;
  if (!envFile) {
    throw new Error(
      "Credentials required: set VANTA_CLIENT_ID and VANTA_CLIENT_SECRET, or set VANTA_ENV_FILE to a JSON credentials file",
    );
  }

  const CredentialsSchema = z.object({
    client_id: z.string(),
    client_secret: z.string(),
  });

  try {
    const data = fs.readFileSync(envFile, "utf8");
    const parsed = CredentialsSchema.parse(JSON.parse(data));
    return parsed;
  } catch (error) {
    throw new Error(
      `Failed to load credentials from ${envFile}: ${String(error)}`,
    );
  }
}

/**
 * Fetches a new OAuth token from the Vanta API using client credentials.
 * Validates the response using a Zod schema.
 * @throws {Error} If the fetch fails or the response is invalid.
 * @returns {Promise<TokenInfo>} The token and its expiration time.
 */
async function fetchNewToken(): Promise<TokenInfo> {
  const credentials = loadCredentials();

  const response = await fetch(`${BASE_API_URL}/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      client_id: credentials.client_id,
      client_secret: credentials.client_secret,
      grant_type: "client_credentials",
      scope: VANTA_API_SCOPE,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(
      `OAuth token request failed: ${response.status.toString()} ${response.statusText} - ${errorText}`,
    );
  }

  const tokenResponse = TokenResponseSchema.parse(await response.json());

  const expiresAt = Date.now() + tokenResponse.expires_in * 1000 - 60000; // Subtract 1 minute buffer

  return {
    token: tokenResponse.access_token,
    expiresAt,
  };
}

/**
 * Checks if the provided token is expired based on its expiration timestamp.
 * @param {TokenInfo} tokenInfo - The token information to check.
 * @returns {boolean} True if the token is expired, false otherwise.
 */
function isTokenExpired(tokenInfo: TokenInfo): boolean {
  return Date.now() >= tokenInfo.expiresAt;
}

/**
 * Retrieves a valid OAuth token, refreshing it if necessary.
 * @returns {Promise<string>} The valid OAuth token.
 */
export async function getValidToken(): Promise<string> {
  if (!currentToken || isTokenExpired(currentToken)) {
    currentToken = await fetchNewToken();
  }

  return currentToken.token;
}

/**
 * Forces a refresh of the OAuth token, retrieving a new one from the API.
 * @returns {Promise<string>} The new OAuth token.
 */
export async function refreshToken(): Promise<string> {
  currentToken = await fetchNewToken();
  return currentToken.token;
}

/**
 * Initializes the OAuth token by ensuring a valid token is available.
 */
export async function initializeToken(): Promise<void> {
  await getValidToken();
}
