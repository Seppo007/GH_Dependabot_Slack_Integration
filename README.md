# GitHub Actions Dependabot Alert POC

A POC to fetch dependabot alerts via github actions + node script and log it to a slack webhook

## How to use
Inkove the ```reportVulsToSlack``` script via node:
```sh
node reportVulsToSlack.js <repository-owner> <repository-name> <github-private-access-token> <slack-webhook-url>
```

#### Arguments:
- repository-owner: Name of the owner of the repository
- repository-name: Name of the repository
- github-private-access-token: A GitHub Private Access Token with at least permission to _public_repo_ and _security_events_
- slack-webhook-url: A Slack webhook url the report should be send to