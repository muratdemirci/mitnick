/**
 * npm registry API client.
 *
 * Fetches package metadata from the public npm registry,
 * validates responses with zod, and maps them to RegistryMetadata.
 */

import { z } from 'zod';
import semver from 'semver';
import type { RegistryMetadata, MaintainerInfo } from '../core/types.js';
import { fetchJson, type HttpResult } from '../utils/http.js';
import { logger } from '../utils/logger.js';

// ─── Constants ────────────────────────────────────────────

const NPM_REGISTRY = 'https://registry.npmjs.org';

// ─── Zod Schemas ──────────────────────────────────────────

const MaintainerSchema = z.object({
  name: z.string(),
  email: z.string().optional(),
});

const VersionInfoSchema = z.object({
  version: z.string(),
  dist: z.object({
    tarball: z.string().url(),
    shasum: z.string().optional(),
    integrity: z.string().optional(),
  }),
});

const PackageDocumentSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  'dist-tags': z.record(z.string(), z.string()).default({}),
  versions: z.record(z.string(), VersionInfoSchema),
  time: z.record(z.string(), z.string()).optional(),
  maintainers: z.array(MaintainerSchema).optional(),
  license: z.string().optional(),
  homepage: z.string().optional(),
  repository: z
    .union([z.string(), z.object({ url: z.string() }).transform((r) => r.url)])
    .optional(),
});

type PackageDocument = z.infer<typeof PackageDocumentSchema>;

// ─── Result Types ─────────────────────────────────────────

export interface RegistrySuccess {
  readonly ok: true;
  readonly metadata: RegistryMetadata;
  readonly tarballUrl: string;
}

export interface RegistryError {
  readonly ok: false;
  readonly error: RegistryErrorKind;
  readonly message: string;
}

export type RegistryResult = RegistrySuccess | RegistryError;

export type RegistryErrorKind =
  | 'not_found'
  | 'version_not_found'
  | 'rate_limited'
  | 'network_error'
  | 'validation_error';

// ─── Client ───────────────────────────────────────────────

/**
 * Encode a package name for use in registry URLs.
 * Scoped packages (@scope/name) become %40scope%2Fname.
 */
function encodePackageName(name: string): string {
  return name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

/**
 * Resolve a version specifier to a concrete version string.
 *
 * Supports:
 * - Exact versions: "4.19.2"
 * - Dist-tags: "latest", "next"
 * - Semver ranges: "^4.0.0", "~4.17.0", ">=4.0.0 <5.0.0"
 *
 * If no version is given, resolves to the `latest` dist-tag.
 */
function resolveVersion(
  doc: PackageDocument,
  requestedVersion: string | undefined,
): string | undefined {
  if (requestedVersion !== undefined) {
    // Direct version match
    if (requestedVersion in doc.versions) {
      return requestedVersion;
    }

    // Check dist-tags (e.g., "latest", "next")
    const tagged = doc['dist-tags'][requestedVersion];
    if (tagged !== undefined) {
      return tagged;
    }

    // Try semver range resolution
    const availableVersions = Object.keys(doc.versions);
    const maxSatisfying = semver.maxSatisfying(availableVersions, requestedVersion);
    if (maxSatisfying !== null) {
      return maxSatisfying;
    }

    return undefined;
  }

  // Default to latest
  return doc['dist-tags']['latest'];
}

/**
 * Map a validated registry document to our internal RegistryMetadata type.
 *
 * Uses Object.assign to conditionally add optional fields, avoiding
 * assignment of `undefined` (required by exactOptionalPropertyTypes).
 */
function toMetadata(doc: PackageDocument, version: string): RegistryMetadata {
  const maintainers: readonly MaintainerInfo[] =
    doc.maintainers?.map((m): MaintainerInfo => {
      if (m.email !== undefined) {
        return { name: m.name, email: m.email };
      }
      return { name: m.name };
    }) ?? [];

  const result: RegistryMetadata = {
    name: doc.name,
    version,
    maintainers,
    versions: Object.keys(doc.versions),
    timeMap: doc.time ?? {},
    distTags: doc['dist-tags'],
    ...(doc.description !== undefined ? { description: doc.description } : {}),
    ...(doc.license !== undefined ? { license: doc.license } : {}),
    ...(doc.homepage !== undefined ? { homepage: doc.homepage } : {}),
    ...(typeof doc.repository === 'string' ? { repository: doc.repository } : {}),
    ...(doc.time?.[version] !== undefined ? { publishedAt: doc.time[version] } : {}),
  };

  return result;
}

/**
 * Fetch package metadata from the npm registry.
 *
 * @param packageName - The npm package name (supports scoped packages)
 * @param version - Optional version or dist-tag. Defaults to "latest".
 */
export async function fetchPackageMetadata(
  packageName: string,
  version?: string,
): Promise<RegistryResult> {
  const encodedName = encodePackageName(packageName);
  const url = `${NPM_REGISTRY}/${encodedName}`;

  logger.debug(`Fetching registry metadata for ${packageName}`, { url });

  const result: HttpResult<unknown> = await fetchJson(url, {
    headers: {
      // Abbreviated metadata is faster; we need full doc for time/maintainers
      Accept: 'application/json',
    },
    timeout: 15_000,
  });

  if (!result.ok) {
    logger.debug(`Registry request failed: ${result.message}`);

    switch (result.error) {
      case 'not_found':
        return {
          ok: false,
          error: 'not_found',
          message: `Package "${packageName}" not found on npm registry`,
        };
      case 'rate_limited':
        return {
          ok: false,
          error: 'rate_limited',
          message: 'npm registry rate limit exceeded. Please retry later.',
        };
      case 'timeout':
      case 'network':
      case 'server_error':
      case 'parse_error':
        return {
          ok: false,
          error: 'network_error',
          message: `Failed to fetch package metadata: ${result.message}`,
        };
    }
  }

  // Validate shape with zod
  const parsed = PackageDocumentSchema.safeParse(result.data);
  if (!parsed.success) {
    logger.debug('Registry response validation failed', {
      errors: parsed.error.issues.map((i) => i.message),
    });
    return {
      ok: false,
      error: 'validation_error',
      message: `Invalid registry response: ${parsed.error.issues.map((i) => i.message).join(', ')}`,
    };
  }

  const doc = parsed.data;
  const resolvedVersion = resolveVersion(doc, version);

  if (resolvedVersion === undefined) {
    return {
      ok: false,
      error: 'version_not_found',
      message: `Version "${version ?? 'latest'}" not found for package "${packageName}"`,
    };
  }

  const versionInfo = doc.versions[resolvedVersion];
  if (versionInfo === undefined) {
    return {
      ok: false,
      error: 'version_not_found',
      message: `Version "${resolvedVersion}" not found for package "${packageName}"`,
    };
  }

  const metadata = toMetadata(doc, resolvedVersion);

  logger.debug(`Resolved ${packageName}@${resolvedVersion}`, {
    tarball: versionInfo.dist.tarball,
  });

  return {
    ok: true,
    metadata,
    tarballUrl: versionInfo.dist.tarball,
  };
}
