<!-- tags: security-research, supply-chain, git -->
<!-- date: 2026-04-01 -->
# Git Commit Forgery: Why Your Repository Trust Model Is Security Theater

*A technical explainer on git's fundamental lack of commit attribution verification, written for engineers and DevOps practitioners. Anyone can create commits attributed to anyone else. Your organization probably knows this and does nothing about it anyway.*

---

## The Thesis

Git has no mechanism to verify that a commit actually came from the person whose name and email appear in the log. `git log` is a list of claims, not a list of facts. You can create a commit attributed to Linus Torvalds, the President, or your CEO on your laptop right now in thirty seconds using only built-in git commands. The commit will be indistinguishable from a legitimate one. If you push it to a repository your organization owns, it will sit there indefinitely — cryptographically valid, properly formatted, and completely fraudulent.

This piece walks through how git authorship actually works, demonstrates real forgery examples, explains why the existing "solutions" (GPG signing, SSH signing, GitHub's "Verified" badge) fail in practice, and argues that the entire git trust model is predicated on an assumption that makes it worthless: that the committer is honest. Supply chain attacks exploit exactly that assumption.

---

## How Git Authorship Actually Works

When you run `git commit`, git doesn't verify your identity. It doesn't check a certificate. It doesn't phone home to an identity service. It reads your local git config — specifically `user.name` and `user.email` — and uses those values in the commit object.

That's it.

The commit object is a plaintext structure:

```
commit 1234abcd5678efgh...
Author: Alice Engineer <alice@company.com>
Committer: Alice Engineer <alice@company.com>
Date: Thu Apr 3 14:22:15 2026 +0000

Fix database migration script
```

These fields are not signed by default. They're not cryptographically bound to anything. They're just text. Git will construct a SHA-1 hash of this object (including the author line) to create the commit ID, but the hash doesn't prove authenticity — it proves consistency. If you change a single character in the commit message, the hash changes. But if you have permission to write to the repository, you can forge the entire history.

The critical point: **there is no verification step**. Git trusts that the person running `git commit` is who they claim to be. It trusts the operating system to enforce user permissions. It does not verify your identity against any external system.

---

## Working Examples: Forging Commits

### Example 1: Change Your Attribution and Commit

The simplest case. You want to commit something as someone else.

```bash
# Your normal identity
$ git config user.name
Alice Engineer
$ git config user.email
alice@company.com

# Temporarily change it
$ git config user.name "Bob Smith"
$ git config user.email "bob@company.com"

# Make a change and commit
$ echo "suspicious code" >> important_file.py
$ git add important_file.py
$ git commit -m "Refactor authentication logic"

# Check the log
$ git log --oneline -1
a1b2c3d Refactor authentication logic

$ git log --format="%h %an %ae %s" -1
a1b2c3d Bob Smith bob@company.com Refactor authentication logic
```

From the repository's perspective, Bob Smith just committed this change. Bob's email is `bob@company.com`. There is no way to tell from the commit object that Alice actually ran `git commit`. No audit trail. No timestamp of who was logged in. No system logs that git bothered to check. If Bob didn't push this himself, he probably has no idea it exists.

### Example 2: The --author Override

You don't even need to reconfigure git. The `--author` flag lets you specify authorship on a per-commit basis:

```bash
$ git commit --author "Charlie Davis <charlie@company.com>" -m "Update dependencies"

$ git log --format="%h %an %ae %s" -1
f7g8h9i Charlie Davis charlie@company.com Update dependencies
```

Charlie did not run this command. Their name is now in the commit log forever.

### Example 3: Forge the Committer (Not Just the Author)

Git tracks two identities: the original author (who created the change) and the committer (who applied it). In a normal workflow, both are the same. But you can forge both separately.

```bash
# Set committer separately
$ GIT_COMMITTER_NAME="Diana Chen" GIT_COMMITTER_EMAIL="diana@company.com" \
  git commit --author "Ethan Hall <ethan@company.com>" -m "Patch security issue"

$ git log --format="%h %an %ae %cn %ce %s" -1
b3c4d5e Ethan Hall ethan@company.com Diana Chen diana@company.com Patch security issue
```

Now the commit claims Ethan wrote it and Diana applied it (perhaps in a rebase or merge). Both are lies if a third person ran this command. Good luck untangling the story from a commit log.

### Example 4: Backdate Commits

Forge not just the author, but the timestamp:

```bash
$ GIT_AUTHOR_DATE="Thu Apr 1 12:00:00 2026 +0000" \
  GIT_COMMITTER_DATE="Thu Apr 1 12:00:00 2026 +0000" \
  git commit --author "Frank Green <frank@company.com>" -m "Feature shipped on April 1"

$ git log --format="%h %an %ai %s" -1
c9d0e1f Frank Green 2026-04-01 12:00:00 +0000 Feature shipped on April 1
```

The commit appears to have been created three days ago, even though you just ran the command. Timeline attacks become possible — you can insert backdated commits into the history to hide when something was actually introduced, or to falsify a timeline of development.

---

## The Trust Model Assumption

All of these attacks work because git assumes the committer is honest. Specifically:

1. **No authentication:** Git doesn't verify your identity. It trusts the operating system.
2. **No authorization checks:** Once you have push access to a repository, git doesn't verify that each individual commit you're pushing is actually yours.
3. **No logging:** Git doesn't log who ran `git commit`. It doesn't log the timestamp of the CLI invocation. It logs the committed timestamp and author — both of which you just forged.

This assumption is fine in a personal repository. It's fine in a small team where everyone trusts everyone. It's catastrophic in:

- **Supply chain attacks:** A compromised CI/CD pipeline can push malicious commits attributed to trusted maintainers.
- **Insider threats:** A disgruntled employee can commit changes attributed to their manager or a security team member.
- **Incident response:** When a security incident occurs, you can't prove who actually made a commit. The log is not evidence.

---

## Why Git Signing Exists (And Why Almost Nobody Uses It)

Git has a solution: commit signing with GPG or SSH keys. The idea is sound: cryptographically sign the commit object so that only the holder of a private key could have created it.

### How it works (the theory):

```bash
# Enable signing by default
$ git config commit.gpgsign true

# Generate or import a GPG key (or use an SSH key with git 2.34+)
$ gpg --gen-key

# Commit (now signed)
$ git commit -m "Signed change"

# Verify the signature
$ git log --show-signature -1
commit a1b2c3d...
gpg: Signature made Thu Apr 3 14:22:15 2026 UTC
gpg: Good signature from "Alice Engineer <alice@company.com>"
```

The signature is cryptographically bound to the commit object. Change a single character in the message or author field, and the signature breaks. Forge an author field without the private key, and the signature is invalid. In theory, this is the solution.

### Why it doesn't work in practice:

**1. Nobody enforces it.** GitHub, GitLab, and Gitea all have the capability to require signed commits on protected branches. Most organizations don't enable this. Why?

- **Operational friction:** Every developer needs to configure a GPG key (or SSH signing key), keep it secure, and have it available during commit. In a large organization, this is a support burden.
- **Key management is hard:** If a developer's laptop is stolen, the private key is stolen. If the key is lost, the developer can't sign commits. If the key expires, commits stop working. Managing hundreds of developer keys across an organization is not trivial.
- **Legacy tooling doesn't support it:** Older CI/CD systems, custom deployment scripts, and third-party services often can't sign commits. You'd have to update everything.

**2. The "Verified" badge is cosmetic.** GitHub displays a green "Verified" checkmark next to signed commits. Most developers and reviewers don't look for it. Most organizations don't require it. It's decoration.

```
✓ Verified — This commit was signed with a verified signature.
```

That's a UI element. It's not enforced. A reviewer can merge an unsigned commit and nobody will stop them.

**3. Key compromise is invisible.** If an attacker steals a developer's GPG key (or SSH key), they can sign commits that appear to come from that developer. The signature is cryptographically valid. There is no way to tell from the signature alone that the key was compromised. Only the developer will know — if they check their own signing key activity, which they probably don't.

**4. The signature doesn't cover the whole story.** Signing proves "someone with this private key signed this commit." It doesn't prove that the author email is correct (you can sign a commit with a different author email in the same command). It doesn't prove authorization — just cryptographic authenticity.

---

## GitHub's Verified Badge: Theater, Not Trust

GitHub shows a "Verified" badge if:

- The commit is signed with a GPG key that's registered in GitHub.
- Or the commit was signed with an SSH key registered in GitHub (GitHub Enterprise, git 2.34+).
- Or GitHub knows the committer's email address (for web-based commits made through GitHub's UI).

The third category is the catch: **GitHub will mark commits as "Verified" if they were made through the web UI, even though the person who clicked "Commit" might not be the person logged in.**

More fundamentally: **the badge tells you nothing about authorization.** If an attacker has commit access to your repository (through compromised credentials, an insider threat, or a CI pipeline compromise), they can sign commits with a legitimate key. The signature is valid. The badge is green. The commit is fraudulent.

Example: A CI/CD system that has a valid, registered deploy key pushes a malicious commit. The signature is valid. The badge is green. The commit appears legitimate. Nobody questions it.

The badge answers the question "Was this signed?" It does not answer "Did the claimed author actually create this change?" or "Was this change authorized?"

---

## How This Enables Supply Chain Attacks

Commit forgery is the foundation of several real attack patterns:

### Attack 1: Compromised CI/CD Pipeline

An attacker gains access to your deployment system. They push a malicious commit to your repository, attributing it to a trusted maintainer whose GPG key is registered (either using a stolen key, or if signing isn't enforced, just with their name and email).

```bash
# Attacker with access to CI/CD system
$ git config user.name "Alice Engineer"
$ git config user.email "alice@company.com"
$ echo "backdoor code" >> src/auth.py
$ git commit -m "Security patch"
$ git push
```

The commit appears to be from Alice. Her name is in the log. If signing isn't enforced, there's no signature to verify. If signing is enforced and Alice's key is registered, the attacker could have stolen the key. Either way, the malicious code is in the repository, and the provenance claim is false.

### Attack 2: Insider Threat Attribution Fraud

An employee with legitimate commit access wants to cover their tracks. They commit malicious code but attribute it to a colleague or a bot account.

```bash
$ git commit --author "deployment-bot <bot@company.com>" -m "Update config"
```

Later, when the malicious code is discovered, the team looks at the log and sees the deployment bot committed it. The actual person is hidden. Incident response is hampered.

### Attack 3: Backdated Exploits in Public Repositories

An attacker with commit access to a popular open-source project commits a vulnerability, but backdates the commit to a timestamp that looks like it was part of a historical refactor.

```bash
$ GIT_AUTHOR_DATE="Thu Jan 15 09:30:00 2025 +0000" \
  GIT_COMMITTER_DATE="Thu Jan 15 09:30:00 2025 +0000" \
  git commit --author "Maintainer <maintainer@example.com>" -m "Refactor parser"
```

Later, when the vulnerability is discovered, the blame log suggests the vulnerability has been in the code for months, implying it was not intentional. The true timeline is hidden. The attacker appears to have been working on the project long before they actually gained access.

---

## What Vigilant Mode Is (And Why Nobody Uses It)

Git has a lesser-known option: "vigilant mode" in GPG signing. If you enable it with `commit.gpgsign=true` and `push.gpgsign=true`, every commit and push signature is verified locally before being accepted.

It looks like a defense. It's not.

**Vigilant mode doesn't prevent forgery.** It prevents you from creating unsigned commits on your own machine. That's a nice hygiene check, but it doesn't solve the core problem: an attacker with repository access doesn't need to create commits on your machine. They create them on their own machine (or a compromised CI system) and push them.

Vigilant mode is strictly a personal setting. It doesn't prevent anyone else from creating and pushing forged commits. It just makes sure *you* don't accidentally commit unsigned changes.

---

## What Would Actually Fix This

### 1. Mandatory Branch Protection with Signature Requirements

Enforce signed commits at the repository level, not the client level.

```bash
# GitHub API example (or use the web UI)
$ curl -X PATCH \
  -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/repos/owner/repo/branches/main/protection \
  -d '{
    "required_status_checks": {"strict": true, "contexts": ["ci/build"]},
    "required_pull_request_reviews": {"required_approving_review_count": 1},
    "require_code_owner_review": true,
    "dismiss_stale_reviews": false,
    "require_commit_signatures": true,
    "enforce_admins": true
  }'
```

This enforces that all commits merged to `main` must be signed. Unsigned commits cannot be merged. Forged commits without a valid signature are rejected automatically.

**But:** This requires that every developer has a working GPG or SSH key setup, and it still doesn't protect against stolen or compromised keys.

### 2. Key Management Infrastructure

Use a secrets management system (Vault, AWS KMS, Azure Key Vault) to manage signing keys.

- Keys are generated and stored centrally, never on individual developer machines.
- Signing happens through an API, not a local CLI tool.
- Audit logs track every signature operation.
- Keys can be rotated, revoked, and monitored for unusual activity.

This moves the trust boundary from "each developer's laptop" to "the organization's key management system." It's more secure, but it's also much more complex to implement.

### 3. SSH Signing (The Easier Path)

Git 2.34+ supports SSH key signing, which is easier to manage than GPG:

```bash
$ git config commit.gpgsign true
$ git config gpg.format ssh
$ git config user.signingkey ~/.ssh/id_ed25519.pub

$ git commit -m "Signed with SSH"
```

SSH keys are already managed in many organizations (for deployments, access control, etc.). Reusing them for commit signing is operationally simpler than deploying GPG infrastructure. The signature is still cryptographically valid and can be branch-protected in the same way.

### 4. Audit and Monitoring

Even if signing isn't enforced everywhere, log and monitor:

- Who created commits (by analyzing the OS-level audit logs, not the git log).
- Which commits are signed and which aren't.
- When signing keys are used.
- Unusual commit patterns (e.g., commits from accounts that normally don't commit, commits from unusual IP addresses if using remote signing).

This doesn't prevent forgery, but it makes detection possible.

---

## The Core Problem: Trust Assumptions

Here's the deeper issue. Git's model assumes:

1. **The committer is honest.** They will not forge authorship or attribution.
2. **The repository is secure.** Only authorized people have push access.
3. **The infrastructure is honest.** CI/CD systems, deployment machines, and git servers won't be compromised.

None of these assumptions are valid in the real world. Supply chain attacks exploit exactly these assumptions. A compromised CI pipeline is still "authorized" to push to the repository. A compromised developer machine still has legitimate SSH keys. An insider still has legitimate access.

Git signing adds a fourth level of protection (cryptographic verification of authorship), but only if it's:

1. **Enabled globally** (requires key management and operational overhead)
2. **Enforced on protected branches** (requires repository configuration)
3. **Actually monitored** (requires audit logs and review procedures)
4. **Used with secure key management** (requires infrastructure that most organizations don't have)

Most organizations have zero of these. They have local git config on developer machines and hope nobody abuses it. That's the default state of git security.

---

## Conclusion

Anyone can create a commit attributed to anyone else. You can do it in thirty seconds with the commands in this post. Your repository probably contains commits from people who didn't actually create them — not because attackers are on your system, but because git's default state is to trust you.

The solution isn't better detection or blame logs. Commit forgery isn't a detection problem — a forged commit is indistinguishable from a legitimate one until it's signed. The solution is enforcing signing at the repository level and managing keys centrally. But that requires operational infrastructure, process changes, and upfront investment that most organizations don't make.

Until then, your git history is not an audit trail. It's a list of claims. Every commit is a claim about who created it, when they created it, and what they changed. If those claims are never verified, they're just storytelling.

The architecture of git — which makes every developer's laptop a perfectly valid place to create repository history — was designed for a world without supply chain attacks. We don't live in that world anymore.

---

*Last updated: April 2026*

## References

- [Git Documentation: git-commit](https://git-scm.com/docs/git-commit)
- [Git Documentation: Signing Commits with GPG](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work)
- [GitHub: About commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
- [GitHub: Signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)
- [GitHub: Require signed commits](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-signed-commits)
- [GitLab: Sign commits with GPG](https://docs.gitlab.com/ee/user/project/repository/gpg_signed_commits/)
- [Gitea: Commit Signing](https://docs.gitea.io/en-us/commit-signature/)
- [SANS Internet Storm Center: Git Commit Forgery](https://isc.sans.edu/forums/diary/Git+Commit+Forgery/28701/)
- [Git Security — Supply Chain Vulnerabilities](https://cheatsheetseries.owasp.org/cheatsheets/Git_Cheat_Sheet.html)
- [Noma Security: Supply Chain Attacks via Git Repositories](https://noma.security/blog/git-repositories-supply-chain/)
- [The New Stack: Why Git Signing Is Not Enough](https://thenewstack.io/why-git-signing-is-not-enough/)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
