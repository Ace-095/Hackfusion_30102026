# Two-developer setup and GitHub workflow

The existing repository is `https://github.com/Ace-095/Hackfusion_30102026`.
`main` is the shared integration branch. Do not push directly to `main`; use
reviewed pull requests. The repository owner must invite the second developer on
GitHub (Settings → Collaborators), and the collaborator must accept before
cloning. Do not share passwords or access tokens in Git, fixtures or chat.

## First-time setup — both developers

1. Clone the repository using your own configured GitHub authentication:

   ```sh
   git clone https://github.com/Ace-095/Hackfusion_30102026.git
   cd Hackfusion_30102026
   ```

2. Install Python 3.11 and follow the Linux or Windows setup instructions in
   [README.md](README.md), including creating your own local virtual environment.
3. Run `python -m pytest` and confirm the tests pass locally.
4. Read [the ownership and milestone plan](docs/DEVELOPMENT.md), the
   [contract review notes](docs/CONTRACTS.md), and the full frozen specification
   once supplied. Review and approve contracts together **before** independent
   implementation begins. The current contracts are draft, not spec-verified.

## Working on changes

The following commands are for the developers' own local clones. Use one branch
per developer, created from an up-to-date `main`:

```sh
git checkout main
git pull origin main
# Developer A chooses feature/accounts-ownership; Developer B chooses
# feature/security-engine. Use only your own branch name below.
git checkout -b feature/accounts-ownership
```

Developer B substitutes `feature/security-engine` in the last command. Implement
small changes in your assigned modules. Before publishing, run `python -m pytest`,
review `git status` and `git diff`, and confirm there are no secrets or generated
scan artifacts in the changes. Then commit and push **your own** branch:

```sh
git add <your-changed-files>
git commit -m "Describe the change"
git push -u origin feature/accounts-ownership
```

Developer B substitutes `feature/security-engine` in the push command. Open a
pull request on GitHub from your branch into `main`, describe the change and test
results, request the other developer's review, and wait for Linux and Windows CI
to pass before merging. Keep PRs small. If the shared contracts need changes
after approval, agree on them together in a shared PR first.

To incorporate changes from `main` into your own feature branch:

```sh
git fetch origin
git merge origin/main
python -m pytest
git push
```

Resolve conflicts before pushing; ask the other developer when shared contracts
or their owned modules are affected. Never commit secrets, real target data,
virtual environments, generated reports, or evidence. Fixture data must be
synthetic and results labeled as fixtures.

## Repository owner checklist

- [ ] Invite the other developer; confirm their access after acceptance.
- [ ] Agree on module ownership and supply the complete v3.2 specification.
- [ ] Enable branch protection or a ruleset for `main` if available: require PR
      review and passing `Tests` checks on both operating systems. The workflow
      runs on pushes and pull requests, but this document does not enable rules.
- [ ] Both developers review and approve contracts before marking them frozen.

Neither collaborator access nor branch protection can be confirmed merely from
these files. Do not relax safety requirements to meet a deadline.
