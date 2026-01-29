n this room, we will examine [CVE-2025-68613](https://nvd.nist.gov/vuln/detail/CVE-2025-68613), a critical vulnerability in [n8n](https://n8n.io/) that was published on December 19, 2025, with a CVSS score of 9.9.

n8n is an open-source workflow automation platform designed to visually connect applications and services for task automation. Users build workflows composed of nodes, with each node representing an action such as making an API request, processing data, or sending an email. n8n is frequently used to automate repetitive operational tasks and to integrate security tools and SaaS platforms. Below is a simple example workflow that allows us to schedule an HTTP GET request to the NVD CVE API, format the output using JavaScript, and then send the report via email and to a Slack channel.

![n8n example workflow](https://tryhackme-images.s3.amazonaws.com/user-uploads/62ff64c3c859dc0042b2b9f6/room-content/62ff64c3c859dc0042b2b9f6-1766583898233.png)

The n8n platform is commonly deployed in three primary configurations:

- Self-hosted instances: Organizations deploy n8n on-premises or in private cloud environments for full control and data sovereignty
- Cloud-hosted (n8n.cloud): Managed service offering with shared infrastructure
- Internal automation tools: Deployed within corporate networks to automate business processes between internal and external systems

Versions 0.211.0 through 1.120.3 contain a critical Remote Code Execution (RCE) vulnerability within the workflow expression evaluation system. If exploited, this flaw enables an authenticated attacker to execute system-level commands, potentially leading to data breaches, service disruptions, or full system compromise, all with the privileges assigned to the n8n process.

In this room, we will discuss the technical aspects of this vulnerability, demonstrate exploitation via web browser, and explore detection strategies.

This vulnerability has been addressed in versions 1.120.4, 1.121.1, and 1.122.0. To ensure system security, it is essential to update to one of these patched versions.

Answer the questions below

Let’s dive into the technical details.

# Technical background

Before exploring the exploit, let’s review n8n. It is built on Node.js, using JavaScript for platform internals and user workflow logic. Its architecture includes:

- Workflow Execution Engine: The core computational component responsible for orchestrating node-based workflow execution
- Expression Evaluation System: Processes dynamic expressions wrapped in double curly braces `{{ }}` that are evaluated as JavaScript code during workflow execution
- Code Nodes: Allow users to write custom JavaScript or Python code as workflow steps, extending platform capabilities
- 400+ Native Integrations: Pre-built connectors to various APIs and services that form the nodes in workflows

The vulnerability resides in n8n’s workflow expression evaluation system, where expressions supplied by authenticated users during workflow configuration are evaluated in an insecure execution context. The core security flaw is an expression injection vulnerability that enables authenticated attackers to execute arbitrary JavaScript code with the privileges of the n8n process. Specifically:

- n8n processes user input wrapped in double curly braces `{{ }}` as JavaScript code without adequate sandboxing or input validation.
- The expression evaluator lacks proper context isolation, allowing attackers to escape the intended evaluation sandbox.
- Authentication provides no meaningful protection against this vulnerability, as any authenticated user can exploit it.

Consider the following working payload from [wioui](https://github.com/wioui/n8n-CVE-2025-68613-exploit).

`{{ (function(){ return this.process.mainModule.require('child_process').execSync('id').toString() })() }}`

Inside of all these layers of curly braces, you can see `(function(){ ... })()`. This pattern creates and immediately executes an anonymous function. The attacker would try to encapsulate some complex logic while maintaining the execution context. For easier reading, the anonymous function is shown below:

```js
function () {
    return this.process.mainModule.require('child_process').execSync('id').toString()
}
```

Let’s take a closer look to better understand this exploit. When `function () { ... }` is called, it starts to execute the `return` statement. If you are not familiar with functions, the `return` statement returns a value, which requires evaluating the expression that comes after it. In this case, evaluation starts with `this`.

The exploit uses `this.process.mainModule`. Let’s break this down:

- `this` refers to the global object in the Node.js execution context
- `process` is a Node.js global object providing access to system processes
- `mainModule` references the root module of the Node.js application

This aims to bypass typical JavaScript sandbox restrictions by accessing Node.js internals (the root module), which should be unavailable to user expressions. It should be noted that if proper sandboxing is in place, it would isolate the expression execution context from the Node.js runtime environment.

Now that the `mainModule` object is reached, we see `.require('child_process')`. This uses `require()`, i.e., Node.js’s module loading function, in order to load `child_process`, a core Node.js module for executing system commands. It should be noted that user expressions should never have access to Node.js’s module system, especially dangerous modules like `child_process`.

Reaching this far, it is a trivial task to execute system functions. This example payload uses `.execSync('id')` to run the `id` command on the host system. Remember that the `id` command displays user identity information (UID, GID, groups).

Now that we have executed `id` on the target system, it is time to retrieve the output. This payload uses `.toString()` to convert the Buffer output from `execSync()` to a readable string, i.e., `id`’s output.

Security boundary breach: User expressions should never have access to Node.js’s module system, especially dangerous modules like child_process

You can now see why we mentioned that the attacker will encapsulate complex logic within the anonymous function; it involves one call after another, until they are literally running commands on the vulnerable system. To summarize, the context escalation chain went as follows:

- It starts within the expression evaluator’s intended sandbox
- Then it escalates to the Node.js global context via `this`
- Furthermore, it escalates to module system access via `process.mainModule.require`
- Finally, it escalates to system command execution via `child_process`

uid=1000(node) gid=1000(node) groups=1000(node)\n