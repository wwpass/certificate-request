
module.exports = {
  presets: [
    [
      '@babel/preset-env'
    ],
  ],
  env: {
    rollup: {
      presets: [
        ['@babel/preset-env', {modules: false, targets: {node: 'current'}}]
      ]
    },
    test: {
      presets: [['@babel/preset-env', {targets: {node: 'current'}}]],
      plugins: ['rewire']
    }
  }
}
