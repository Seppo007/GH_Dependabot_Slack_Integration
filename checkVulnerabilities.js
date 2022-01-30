const https = require('https');
const graphql = require('graphql-request');

vulnerabilityReportFor = async (owner, repo, githubAccessToken) => {
    var endpoint = "https://api.github.com/graphql";

    const graphQLClient = new graphql.GraphQLClient(endpoint, {
        headers: { authorization: "bearer " + githubAccessToken, }
    });

    const query = graphql.gql`{
        repository(name: "${repo}", owner: "${owner}") {
            vulnerabilityAlerts(first: 100) {
                nodes {
                    securityAdvisory {
                        publishedAt
                    }
                    securityVulnerability {
                        package {
                            name
                        }
                        firstPatchedVersion {
                            identifier
                        }
                        severity
                    }
                    vulnerableRequirements
                }
            }
        }
    }`;

    return sortedVulnerabiliyEntriesFrom(await graphQLClient.request(query));
}

const severityRanking = {
    LOW: 0,
    MODERATE: 1,
    HIGH: 2,
    CRITICAL: 3
};

const severityColor = {
    LOW: '#99c140',
    MODERATE: '#e7b416',
    HIGH: '#db7b2b',
    CRITICAL: '#cc3232'
}

const sortBySeverity = (vulnerabilities) => vulnerabilities.sort(
    (entryA, entryB) => severityRanking[entryB.severity] - severityRanking[entryA.severity]
);

const sortedVulnerabiliyEntriesFrom = (response) => {
    const responseEntries = response.repository.vulnerabilityAlerts.nodes;
    const vulnerabilities = responseEntries.map(entry => (
        {
            "severity": entry.securityVulnerability.severity,
            "packageName": entry.securityVulnerability.package.name,
            "vulnerableSince": entry.securityAdvisory.publishedAt,
            "currentVersion": entry.vulnerableRequirements,
            "patchedVersion": entry.securityVulnerability.firstPatchedVersion.identifier
        }
    ));
    return sortBySeverity(vulnerabilities);
}

const sendSlackMessage = (slackWebhookEndpoint, messageBody) => {

    const slackAttachments = messageBody.map((vulnerability) => {
        return {
            fallback: vulnerability.packageName,
            text: vulnerability.packageName,
            color: severityColor[vulnerability.severity],
            fields: [{
                title: vulnerability.severity,
                value: 'besteht seit: ' + new Date(vulnerability.vulnerableSince).toLocaleDateString('de-DE', { day: "2-digit", month: "2-digit", year: "numeric" }) +
                    '\nverwendete Version: ' + vulnerability.currentVersion +
                    '\nsichere Version: ' + vulnerability.patchedVersion,
                short: false
            }]
        }
    });

    const slackNotification = {
        'username': 'Dependabot Vulnerability Reporter', // This will appear as user name who posts the message
        'text': 'Found the following vulnerabilities in ' + process.env.github_repo + ':', // text
        'icon_emoji': ':male-detective:', // User icon, you can also use custom icons here
        'attachments': slackAttachments,
    };

    const requestOptions = {
        method: 'POST',
        header: {
            'Content-Type': 'application/json'
        }
    };

    return new Promise((resolve, reject) => {
        const request = https.request(slackWebhookEndpoint, requestOptions, (res) => {
            let response = '';

            res.on('data', (d) => {
                response += d;
            });

            res.on('end', () => {
                resolve(response);
            })
        });

        request.on('error', (e) => {
            reject(e);
        });

        request.write(JSON.stringify(slackNotification));
        request.end();
    });
}

var owner = process.argv[2];
var repo = process.argv[3];
var githubAccessToken = process.argv[4];
var slackWebhookEndpoint = process.argv[5];

vulnerabilityReportFor(owner, repo, githubAccessToken)
    .then((vulnerabilites) =>
        sendSlackMessage(slackWebhookEndpoint, vulnerabilites)
            .then(() => console.log('succesfully send slack notification'), (e) => console.log('could not send slack message because of:', e)),
        (e) => console.log("could not fetch vulnerabilities because of:", e));