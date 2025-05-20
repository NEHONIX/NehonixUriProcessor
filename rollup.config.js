import typescript from "@rollup/plugin-typescript";
import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import dts from "rollup-plugin-dts";
import { readFileSync } from "fs";

const pkg = JSON.parse(
  readFileSync(new URL("./package.json", import.meta.url), "utf8")
);

export default [
  // ESM build
  {
    input: "src/index.ts",
    output: {
      file: "dist/index.esm.js",
      format: "es",
      sourcemap: true,
      exports: "named",
    },
    plugins: [
      resolve(),
      commonjs(),
      typescript({ tsconfig: "./tsconfig.json" }),
    ],
    external: [
      ...Object.keys(pkg.dependencies || {}),
      ...Object.keys(pkg.peerDependencies || {}),
    ],
  },
  // CommonJS build - Fixed configuration
  {
    input: "src/index.ts",
    output: {
      file: "dist/index.cjs",
      format: "cjs",
      sourcemap: true,
      exports: "auto", // Changed from "named" to "auto"
      esModule: false, // Added to ensure proper CJS behavior
    },
    plugins: [
      resolve(),
      commonjs(),
      typescript({
        tsconfig: "./tsconfig.json",
        declaration: false, // Prevent duplicate declarations
      }),
    ],
    external: [
      ...Object.keys(pkg.dependencies || {}),
      ...Object.keys(pkg.peerDependencies || {}),
    ],
  },
  // TypeScript declarations
  {
    input: "src/index.ts",
    output: {
      file: "dist/index.d.ts",
      format: "es",
    },
    plugins: [dts()],
    external: ["nehonix-uri-processor"],
  },
];
