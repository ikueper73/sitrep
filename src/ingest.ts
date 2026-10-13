import { kev } from "./sources/kev";
import type { Fetcher, SourceAdapter } from "./sources/types";
import { getSourceState, recordFetchError, recordFetchSuccess, upsertItems } from "./store";

export const adapters: SourceAdapter[] = [kev];

export type IngestOutcome =
  | { source: string; status: "not-modified" }
  | { source: string; status: "ok"; fetched: number; written: number }
  | { source: string; status: "error"; error: string };

/**
 * Runs every adapter independently: one failing source is recorded in
 * source_state and never stops the others.
 */
export async function runIngestion(
  db: D1Database,
  fetcher: Fetcher = fetch,
  sources: SourceAdapter[] = adapters,
  now: () => string = () => new Date().toISOString(),
): Promise<IngestOutcome[]> {
  return Promise.all(
    sources.map(async (adapter): Promise<IngestOutcome> => {
      try {
        const state = await getSourceState(db, adapter.id);
        const result = await adapter.fetch(fetcher, state);
        if (result.status === "not-modified") {
          await recordFetchSuccess(db, adapter.id, now(), null);
          return { source: adapter.id, status: "not-modified" };
        }
        const written = await upsertItems(db, result.items, now());
        await recordFetchSuccess(db, adapter.id, now(), result);
        return { source: adapter.id, status: "ok", fetched: result.items.length, written };
      } catch (err) {
        const error = err instanceof Error ? err.message : String(err);
        console.error(`ingest ${adapter.id} failed: ${error}`);
        try {
          await recordFetchError(db, adapter.id, now(), error);
        } catch (e) {
          console.error(`ingest ${adapter.id}: could not record error: ${e}`);
        }
        return { source: adapter.id, status: "error", error };
      }
    }),
  );
}
