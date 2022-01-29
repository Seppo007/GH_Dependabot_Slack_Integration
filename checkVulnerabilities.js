const graphql = require('graphql-request');

async function fetchVulnerabilities() {
    var token = "";
    var endpoint = "https://api.github.com/graphql";

    const graphQLClient = new graphql.GraphQLClient(endpoint, {
        headers: { authorization: "bearer " + token, }
    });

    const query = graphql.gql`{
        repository(name: "GHDependabotAlertsPOC", owner: "Seppo007") {
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

    return createVulnerabilityLogEntries(await graphQLClient.request(query));
}

const severityRanking = {
    LOW: 0,
    MODERATE: 2,
    HIGH: 3,
    CRITICAL: 4
};

const sortBySeverity = (vulnerabilities) => vulnerabilities.sort(
    (entryA, entryB) => severityRanking[entryB.severity] - severityRanking[entryA.severity]
);

const createVulnerabilityLogEntries = (response) => {
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

fetchVulnerabilities().then((vulnerabilites) => console.log(vulnerabilites), () => console.log("could not fetch"));