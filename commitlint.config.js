// Conventional Commits — https://www.conventionalcommits.org
// Les types reconnus alimentent le changelog (cliff.toml) : feat, fix, perf, refactor, docs, chore(deps).
export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [2, 'always', ['build', 'chore', 'ci', 'docs', 'feat', 'fix', 'perf', 'refactor', 'revert', 'style', 'test']],
    'header-max-length': [2, 'always', 100],
    // Les corps de message contiennent souvent des URL longues (Dependabot, liens de tickets)
    'body-max-line-length': [0],
    'footer-max-line-length': [0],
  },
}
