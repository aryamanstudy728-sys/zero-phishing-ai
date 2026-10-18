# Test fixtures - Sample phishing email

# Raw email with phishing indicators
PHISHING_EMAIL_RAW = b"""Received: from mail.phisher.com (mail.phisher.com [192.0.2.1])
	by mx.google.com with ESMTPS id x123
	for <victim@gmail.com>
	(version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
	Mon, 26 Sep 2026 10:00:00 -0700 (PDT)
Received-SPF: fail (google.com: domain of paypal@phisher.com does not designate 192.0.2.1 as permitted sender) client-ip=192.0.2.1;
Authentication-Results: mx.google.com;
	spf=fail (google.com: domain of paypal@phisher.com does not designate 192.0.2.1 as permitted sender) smtp.mailfrom=paypal@phisher.com;
	dkim=fail header.d=phisher.com;
	dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com
From: "PayPal Security" <paypal@phisher.com>
To: victim@gmail.com
Subject: URGENT: Your PayPal account has been limited
Date: Mon, 26 Sep 2026 10:00:00 -0700
Message-ID: <phish-123@phisher.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset=UTF-8

Your PayPal account has been limited due to suspicious activity.

We require you to verify your identity immediately to restore access.
Click here: http://paypal-verify.phisher.com/login

If you do not verify within 24 hours, your account will be permanently closed.

PayPal Security Team

--boundary123
Content-Type: text/html; charset=UTF-8

<html>
<body>
<p>Your PayPal account has been limited due to suspicious activity.</p>
<p>We require you to verify your identity immediately to restore access.</p>
<p><a href="http://paypal-verify.phisher.com/login">Click here to verify</a></p>
<p>If you do not verify within 24 hours, your account will be permanently closed.</p>
<p>PayPal Security Team</p>
</body>
</html>
--boundary123--
"""

# Legitimate email raw
LEGIT_EMAIL_RAW = b"""Received: from mail.google.com (mail.google.com [142.250.100.25])
	by mx.google.com with ESMTPS id x456
	for <user@gmail.com>
	(version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
	Mon, 26 Sep 2026 10:00:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of newsletter@company.com designates 142.250.100.25 as permitted sender) client-ip=142.250.100.25;
Authentication-Results: mx.google.com;
	spf=pass (google.com: domain of newsletter@company.com designates 142.250.100.25 as permitted sender) smtp.mailfrom=newsletter@company.com;
	dkim=pass header.d=company.com;
	dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=company.com
From: "Company Newsletter" <newsletter@company.com>
To: user@gmail.com
Subject: Your Weekly Update - September 26, 2026
Date: Mon, 26 Sep 2026 10:00:00 -0700
Message-ID: <legit-456@company.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary456"

--boundary456
Content-Type: text/plain; charset=UTF-8

Here's your weekly newsletter with company updates and upcoming events.

Read more: https://company.com/newsletter/sep-26

Thanks,
The Company Team

--boundary456
Content-Type: text/html; charset=UTF-8

<html>
<body>
<p>Here's your weekly newsletter with company updates and upcoming events.</p>
<p><a href="https://company.com/newsletter/sep-26">Read more</a></p>
<p>Thanks,<br>The Company Team</p>
</body>
</html>
--boundary456--
"""

# BEC (Business Email Compromise) email
BEC_EMAIL_RAW = b"""Received: from mail.ceo-imposter.com (mail.ceo-imposter.com [198.51.100.1])
	by mx.google.com with ESMTPS id x789
	for <finance@victim.com>
	(version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
	Mon, 26 Sep 2026 10:00:00 -0700 (PDT)
Received-SPF: fail (google.com: domain of ceo@ceo-imposter.com does not designate 198.51.100.1 as permitted sender) client-ip=198.51.100.1;
Authentication-Results: mx.google.com;
	spf=fail (google.com: domain of ceo@ceo-imposter.com does not designate 198.51.100.1 as permitted sender) smtp.mailfrom=ceo@ceo-imposter.com;
	dkim=fail header.d=ceo-imposter.com;
	dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=victim.com
From: "John Smith, CEO" <ceo@ceo-imposter.com>
To: finance@victim.com
Subject: URGENT: Wire Transfer Required - Confidential
Date: Mon, 26 Sep 2026 10:00:00 -0700
Message-ID: <bec-789@ceo-imposter.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

I need you to process an urgent wire transfer of $45,000 to our new vendor.
This is highly confidential and time-sensitive.

Account: 123456789
Routing: 987654321
Amount: $45,000.00
Reference: INV-2026-001

Please confirm once completed. Do not discuss with anyone.

Sent from my iPhone
John Smith
CEO, Victim Corp
"""