import {defineConfig} from 'vitest/config';

export default defineConfig({
    test: {
        // Node, not jsdom: every module here is server-side and none of them
        // touches a DOM.
        environment: 'node',
        include: ['test/**/*.test.ts']
    }
});
