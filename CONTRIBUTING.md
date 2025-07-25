# Contributing to Namada

Thank you for the interest in contributing to Namada!

All contributors are expected to adhere to the [Code of Conduct](CODE_OF_CONDUCT.md).

Any contributions such as issue reports, pull requests  for code or documentation, or feature requests are welcome. Please note that the code should be kept up-to-date with the documentation.

## Opening a pull request

Every pull request should start with an issue. A pull request should be as atomic as reasonably possible. Please use the Github's syntax in the PR's description to link the issue (e.g. `closes #123`).

### Changelog

To track changes in Namada and provide a nicely formatted change log with the releases, we utilize the [unclog CLI tool](https://github.com/informalsystems/unclog). Please do not modify the [change log](CHANGELOG.md) in your PRs, this file will be updated by the repository maintainers.

With every PR, please make a separate commit that adds a record in the `.changelog` directory with a section that this PR belongs to together with a high-level description of the change.

The section should either be one of the following choices:

- `CI`
- `bug-fixes`
- `docs`
- `features`
- `improvements`
- `testing`
- `SDK`

To add a change log entry using `unclog`, you can fill in the following command (prefer to use the issue number, for which the `--pull-request` argument may be omitted):

```shell
unclog add \
  --id           <branch name (omit owner name before the /)> \
  --section      <section name> \
  # only include one of --issue-no or --pull-request
  --issue-no     <issue number> \
  --pull-request <PR number> \
  --message      <message>
```

The message should be a high-level description of the changes that should explain the scope of the change and affected components to Namada's users (while git commit messages should target developers).

Aim to make the changelog description readable and understandable for people using Namada in plain English, assuming no familiarity with the code, dependencies and other low-level details, and explain not just *what* has changed, but also *why* it's changed.

If none of the sections fit, new sections may be added. To find the existing section names, you can use e.g.:

```shell
for i in $(ls -d .changelog/*/*/); do basename "$i"; done | sort | uniq
```

#### SDK Changelog

The Namada SDK is exposed to any developer building upon Namada. Thus, any change made to a public facing function is a breaking change, and therefore should be documented in the Changelog under the `SDK` section.

The message should outline the exact API change, along with a small section describing *how* and *why* the component was changed. This should give motivation and context to any developer building upon Namada on how they can update their code to the next version.

## Development priorities


If you’d like to follow the development or contribute with new or unimplemented features, we recommend to check [the issues](https://github.com/namada-net/namada/issues) that are in current focus of the ledger team.
