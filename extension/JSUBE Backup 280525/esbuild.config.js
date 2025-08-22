import * as esbuild from "esbuild";

esbuild.build({
  entryPoints: ['UBE_Stage1.js'],
  bundle: true,
  platform: 'browser',
  format: 'esm',
  outfile: 'dist/bundle.js',
  //minify
}).catch(() => process.exit(1));