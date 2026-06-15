import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
    },
    rules: {
      // React 19 experimental rule that flags `setLoading(true)` inside the
      // useEffect body of a list-fetch hook. The pattern is idiomatic and
      // the official escape hatch (React Compiler) isn't in this project.
      // Keep the rule's intent (avoid cascading renders) as a soft suggestion
      // via code review rather than a build-blocker.
      'react-hooks/set-state-in-effect': 'off',
    },
  },
])
