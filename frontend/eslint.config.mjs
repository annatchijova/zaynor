import { defineConfig, globalIgnores } from "eslint/config";
import nextCoreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypeScript from "eslint-config-next/typescript";

export default defineConfig([
  ...nextCoreWebVitals,
  ...nextTypeScript,
  {
    files: ["src/**/*.{ts,tsx}"],
    ignores: ["src/lib/api/http-api-client.ts"],
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector: "CallExpression[callee.name='fetch']",
          message: "Use ZaynorApiClient. Only HttpApiClient may call fetch().",
        },
        {
          selector: "CallExpression[callee.property.name='fetch']",
          message: "Use ZaynorApiClient. Only HttpApiClient may call fetch().",
        },
      ],
    },
  },
  globalIgnores([".next/**", "coverage/**"]),
]);
