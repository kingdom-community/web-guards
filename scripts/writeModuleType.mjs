// The package is ESM ("type": "module"), so the CommonJS build needs a
// package.json of its own saying otherwise — and the ESM build needs one saying
// so explicitly, because a future change to the root field must not silently
// reinterpret already-built files.
import {mkdirSync, writeFileSync} from 'node:fs';

const flavour = process.argv[2];
const type = flavour === 'cjs' ? 'commonjs' : 'module';
const directory = new URL(`../dist/${flavour}/`, import.meta.url);

mkdirSync(directory, {recursive: true});
writeFileSync(new URL('package.json', directory), `${JSON.stringify({type}, null, 2)}\n`);
