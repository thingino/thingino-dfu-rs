/* The prebuilt-release picker's grouping, kept pure so it can be tested without a
 * page: thingino-firmware publishes its images as GitHub releases tagged
 * `<branch>-<date>` (`firmware-2026-08-14` for the stable line, `master-2026-08-25`
 * for a master build marked prerelease, and so on per branch). Tags that are not
 * shaped like that (`ccache`, `update_cache`, the build caches) carry no images a
 * user should flash and are skipped. */

const FIRMWARE_TAG = /^([a-z][a-z0-9_.-]*?)-(\d{4}-\d{2}-\d{2})$/;

/* The menu offers two branches (decided 2026-09-03): `master`, whose
 * builds are the `master-<date>` tags, and `ciao`, the branch the stable line is built
 * from, whose builds are the `firmware-<date>` tags (the releases API's
 * `target_commitish` for them is `ciao`). Every other branch's builds are hidden. */
export const BRANCHES = [
    { name: 'master', prefix: 'master' },
    { name: 'ciao', prefix: 'firmware' },
];

/* Chosen by default. */
export const DEFAULT_BRANCH = 'master';

/* `firmware-2026-08-14` -> `firmware`; `master-2026-08-25` -> `master`; anything not
 * shaped `<branch>-<date>` -> null. */
export function branchOf(tag) {
    const m = FIRMWARE_TAG.exec(String(tag || ''));
    return m ? m[1] : null;
}

/* The menu entry a tag belongs to: `master-2026-08-25` -> `master`,
 * `firmware-2026-08-14` -> `ciao`, anything else -> null. */
export function menuBranchOf(tag) {
    const prefix = branchOf(tag);
    const entry = BRANCHES.find((b) => b.prefix === prefix);
    return entry ? entry.name : null;
}

/* The date half of a tag, which is what the release menu shows once the branch is
 * chosen: `master-2026-08-25` -> `2026-08-25`. */
export function dateOf(tag) {
    const m = FIRMWARE_TAG.exec(String(tag || ''));
    return m ? m[2] : String(tag || '');
}

/* Group a releases-API listing by menu branch, newest first inside each (the API
 * lists newest first); drafts, non-firmware tags and every branch outside BRANCHES
 * are dropped. Returns `{ branches, byBranch }` where `branches` is BRANCHES' order
 * restricted to the branches that have builds, and `byBranch[name]` is an array of
 * `{ tag, prerelease, assets }`. */
export function groupByBranch(releases) {
    const byBranch = {};
    for (const r of releases || []) {
        if (!r || r.draft) continue;
        const branch = menuBranchOf(r.tag_name);
        if (!branch) continue;
        (byBranch[branch] = byBranch[branch] || []).push({
            tag: r.tag_name,
            prerelease: !!r.prerelease,
            assets: r.assets || [],
        });
    }
    const branches = BRANCHES.map((b) => b.name).filter((name) => byBranch[name]);
    return { branches, byBranch };
}

/* What the release menu prints for one entry: the date, and "(prerelease)" when the
 * release is marked so on GitHub, which every non-stable branch build is. */
export function releaseLabel(entry, prereleaseWord) {
    return dateOf(entry.tag) + (entry.prerelease ? ' (' + (prereleaseWord || 'prerelease') + ')' : '');
}
