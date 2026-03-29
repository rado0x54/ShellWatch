import { watch, type FSWatcher } from "node:fs";
import type { SshKeyRepository } from "../db/repositories/key-repo.js";
import { type ScannedKey, scanKeyDirectory } from "./key-scanner.js";

/**
 * Provides private key content for SSH connections.
 * Implemented by KeyDirectoryWatcher (production) and InMemoryKeyProvider (tests).
 */
export interface PrivateKeyProvider {
  getPrivateKey(fingerprint: string): string | undefined;
}

/** Checks whether a file-based key is currently available on disk. */
export interface KeyAvailability {
  isAvailable(fingerprint: string): boolean;
}

/**
 * Watches a directory for SSH key files and keeps the database in sync.
 *
 * - On startup: scans the directory and upserts discovered keys into the DB
 * - At runtime: watches for file additions/removals and updates availability
 * - Keys that disappear from the filesystem become unavailable but stay in the DB
 * - Non-key files are silently ignored
 */
export class KeyDirectoryWatcher implements PrivateKeyProvider, KeyAvailability {
  private available = new Map<string, ScannedKey>();
  private watcher: FSWatcher | null = null;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private directory: string,
    private keyRepo: SshKeyRepository,
  ) {}

  /** Perform initial scan and start watching for changes. */
  async start(): Promise<ScannedKey[]> {
    const keys = await this.sync();
    this.startWatching();
    return keys;
  }

  /** Stop watching the directory. */
  stop(): void {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
  }

  /** Get private key content by fingerprint. Returns undefined if unavailable. */
  getPrivateKey(fingerprint: string): string | undefined {
    return this.available.get(fingerprint)?.privateKeyContent;
  }

  /** Check if a key is currently available (file exists in directory). */
  isAvailable(fingerprint: string): boolean {
    return this.available.has(fingerprint);
  }

  /** Get all currently available keys. */
  getAvailableKeys(): ScannedKey[] {
    return Array.from(this.available.values());
  }

  /** Scan directory, update DB and availability map. Returns newly discovered keys. */
  private async sync(): Promise<ScannedKey[]> {
    const scanned = scanKeyDirectory(this.directory);

    // Update availability map
    const newFingerprints = new Set(scanned.map((k) => k.fingerprint));
    this.available.clear();
    for (const key of scanned) {
      this.available.set(key.fingerprint, key);
    }

    // Upsert new keys into the database
    const existingKeys = await this.keyRepo.findAll();
    const existingFingerprints = new Set(existingKeys.map((k) => k.fingerprint));

    for (const key of scanned) {
      if (!existingFingerprints.has(key.fingerprint)) {
        await this.keyRepo.create({
          id: key.filename.replace(/\.pem$/, ""),
          label: key.filename,
          type: "file",
          publicKey: key.publicKeyOpenSsh,
          fingerprint: key.fingerprint,
        });
      }
    }

    return scanned;
  }

  private startWatching(): void {
    try {
      this.watcher = watch(this.directory, () => {
        // Debounce: editors may trigger multiple events for a single save
        if (this.debounceTimer) clearTimeout(this.debounceTimer);
        this.debounceTimer = setTimeout(() => {
          this.debounceTimer = null;
          this.sync().catch(() => {
            // Scan errors are non-fatal — directory may be temporarily unavailable
          });
        }, 500);
      });
      this.watcher.on("error", () => {
        // Watcher errors are non-fatal
      });
    } catch {
      // fs.watch may fail on some platforms/directories — continue without watching
    }
  }
}

/**
 * Simple in-memory key provider for tests.
 * Pre-loaded with keys, no filesystem watching.
 */
export class InMemoryKeyProvider implements PrivateKeyProvider {
  private byFingerprint = new Map<string, string>();

  constructor(keys: Array<{ fingerprint: string; privateKeyContent: string }>) {
    for (const key of keys) {
      this.byFingerprint.set(key.fingerprint, key.privateKeyContent);
    }
  }

  getPrivateKey(fingerprint: string): string | undefined {
    return this.byFingerprint.get(fingerprint);
  }
}
