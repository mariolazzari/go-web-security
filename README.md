# Learn web security in Go

## OWASP

### Learning Goals

Understand the most common web security vulnerabilities and how they work.

- Learn to use security resources and techniques like [STRIDE](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html#threat-identification) and the [OWASP Top 10](https://top10.owasp.org/2025/0x00_2025-Introduction/).
- Gain hands-on experience fixing insecure code in a Go app.

### Why web security

As soon as your app is publicly reachable, automated bots can scan it for weaknesses. Even a small app can be a target. Just because you don't have many users doesn't mean data exposure is "something to worry about later." Security is non-negotiable, no matter your scale.
Most successful attacks exploit simple, sloppy mistakes:

- Weak authentication
- Insecure defaults
- Forgotten debug routes
- Outdated dependencies

```sh
go run ./cmd/seed
go run ./cmd/server
```

### Security consequences

Everyone says "security is the most important thing," but what are the real consequences of getting it wrong?

Sometimes companies get away with sloppy security... and sometimes they don't. When things go wrong, the consequences extend far beyond the engineering resources spent to fix the vulnerable code. For example:

- A SQL injection exposes 10,000 email addresses and order histories.
  - Your engineering team investigates the breach and closes the vulnerability.
  - Your legal and privacy teams determine whether affected users or regulators must be notified.
  - Your customer support team handles a flood of worried users.
  - Your company loses customer trust and future sales.

- An XSS bug lets an attacker run code in users' browsers. The attacker may steal sensitive data or act as those users.
  - Your security team investigates which accounts were affected and cuts off the attacker's access.
  - Your support team helps users restore control of their accounts.

### OWASP top 10

[OWASP](https://owasp.org/) (the Open Worldwide Application Security Project) publishes a new list of critical web application security risks every few years. The [OWASP Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/) combines contributed application-testing data with a survey of security practitioners. It's based on real-world data!

- A01: Broken Access Control – Users can do things they shouldn't be allowed to do.
- A02: Security Misconfiguration – The system is deployed or configured in an unsafe way.
- A03: Software Supply Chain Failures – Vulnerabilities enter through outdated or compromised third-party libraries or build tools.
- A04: Cryptographic Failures – Sensitive data is exposed because cryptographic protections are missing or misused.
- A05: Injection – Untrusted input is treated as executable instructions.
- A06: Insecure Design – The system's design lacks the controls needed to resist attacks.
- A07: Authentication Failures – The system doesn't reliably verify who a user is.
- A08: Software or Data Integrity Failures – The application trusts software or data without verifying its integrity.
- A09: Security Logging and Alerting Failures – Attacks happen without triggering the records or alerts needed for a response.
- A10: Mishandling of Exceptional Conditions – Unexpected conditions expose details, bypass controls, or leave the system in a bad state.

#### NoSniff

Missing browser security headers are a concrete example of A02: Security Misconfiguration. One of the simplest headers to add is [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options): nosniff.

This header tells browsers to respect a response's declared [Content-Type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Type) instead of guessing from its contents.

This helps prevent security vulnerabilities related to MIME sniffing. For example, without nosniff, a browser might treat attacker-controlled content as executable code despite its declared type!

Bearly Secure composes global middleware around its main [http.Handler](https://pkg.go.dev/net/http#Handler). Middleware can set the header before passing the request to the next handler, which applies the policy to both application routes and static files.

```go
func setNoSniff(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
```

### How Attackers Think

When attackers target a web application, they're usually after:

- Money: Theft through payments, refunds, or extortion
- Data: Email addresses, names, and credentials to abuse or sell
- Access: Control of powerful accounts or admin panels
- Disruption: Making a service unreliable for notoriety or competitive advantage

Attackers don't have to use your front-end interface or obey its client-side restrictions. They can interact with your back end directly. Just because your website's UI hides the "Delete All Users" button for non-admins doesn't mean an attacker can't send a direct DELETE request to your /users endpoint using curl or Postman.
