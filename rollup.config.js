import babel from 'rollup-plugin-babel';
import resolve from 'rollup-plugin-node-resolve';
import commonjs from 'rollup-plugin-commonjs';
import json from 'rollup-plugin-json';

export default [{
  input: 'src/index.js',
  output: {
    sourcemap: true,
    format: 'iife',
    file: 'dist/manage-generate-request.js',
  },
  treeshake: true,
  plugins: [
    json(),
    resolve({
      jsnext: true,
      main: true,
      browser: true
    }),
    commonjs(),
    babel({
      exclude: 'node_modules/**',
      plugins: [],
    }),
  ],
}];
