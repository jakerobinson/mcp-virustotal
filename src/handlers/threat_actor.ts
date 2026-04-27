import { z } from 'zod';
import { queryVirusTotal } from '../utils/api.js';
import { GetThreatActorFilesArgsSchema } from '../schemas/index.js';
import { logToFile } from '../utils/logging.js';

async function resolveCollectionId(nameOrId: string): Promise<{ id: string; name: string; altNames: string[] }> {
    // If it already looks like a collection ID (contains '--'), use it directly
    if (nameOrId.includes('--')) {
        return { id: nameOrId, name: nameOrId, altNames: [] };
    }

    logToFile(`Searching for threat actor collection: ${nameOrId}`);
    const response = await queryVirusTotal(
        `/collections`,
        'get',
        undefined,
        { filter: nameOrId, limit: 10 }
    );

    const collections: any[] = response?.data || [];

    // Find the best match: prefer exact alt_name match, then partial
    const needle = nameOrId.toLowerCase();
    let best: any = null;

    for (const col of collections) {
        const altNames: string[] = col?.attributes?.alt_names || [];
        const colName: string = col?.attributes?.name || '';
        const allNames = [colName, ...altNames].map((n: string) => n.toLowerCase());

        if (allNames.some((n: string) => n === needle)) {
            best = col;
            break;
        }
        if (!best && allNames.some((n: string) => n.includes(needle))) {
            best = col;
        }
    }

    if (!best && collections.length > 0) {
        best = collections[0];
    }

    if (!best) {
        throw new Error(`No threat actor collection found matching: ${nameOrId}`);
    }

    return {
        id: best.id,
        name: best?.attributes?.name || best.id,
        altNames: best?.attributes?.alt_names || [],
    };
}

export async function handleGetThreatActorFiles(args: z.infer<typeof GetThreatActorFilesArgsSchema>) {
    const { threat_actor_id, limit, cursor } = args;

    const { id: collectionId, name, altNames } = await resolveCollectionId(threat_actor_id);
    logToFile(`Resolved "${threat_actor_id}" to collection: ${collectionId}`);

    const params: Record<string, string | number | boolean> = { limit };
    if (cursor) params.cursor = cursor;

    const response = await queryVirusTotal(
        `/collections/${encodeURIComponent(collectionId)}/relationships/files`,
        'get',
        undefined,
        params
    );

    const files: any[] = response?.data || [];
    const meta = response?.meta || {};

    const displayName = name !== collectionId ? name : threat_actor_id;
    const lines: string[] = [
        `Threat Actor: ${displayName}`,
        altNames.length ? `Also known as: ${altNames.join(', ')}` : '',
        `Collection ID: ${collectionId}`,
        `Files: ${meta?.count !== undefined ? meta.count : files.length} total`,
        '',
        'SHA256 Hashes:',
    ].filter(l => l !== '');

    for (const file of files) {
        const sha256 = file?.attributes?.sha256 || file?.id || 'Unknown';
        const name = file?.attributes?.meaningful_name || file?.attributes?.names?.[0] || '';
        const stats = file?.attributes?.last_analysis_stats;
        const malicious = stats?.malicious ?? '?';
        const total = stats ? Object.values(stats as Record<string, number>).reduce((a, b) => a + b, 0) : '?';
        lines.push(`  • ${sha256}${name ? `  [${name}]` : ''}  detections: ${malicious}/${total}`);
    }

    if (meta?.cursor) {
        lines.push('', `More results available. Use cursor: ${meta.cursor}`);
    }

    return {
        content: [{ type: 'text' as const, text: lines.join('\n') }],
    };
}
