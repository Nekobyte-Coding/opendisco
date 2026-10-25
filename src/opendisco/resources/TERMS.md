# OpenDisco Terms of Use

Version {version}. Effective when accepted.

## Summary

This summary is a plain-English overview only. It does not replace the full Terms below, which control.

- OpenDisco is free, open-source software, provided "as is", with no warranty of any kind.
- OpenDisco scans networks, logs into devices and changes them: it updates firmware, edits, uploads and restores configs, changes logins and reboots devices. Any of that can brick a radio, cut off a remote site or take subscribers offline. The User accepts all of that risk.
- Nekobyte-Coding, Michael Froehlke and the project's contributors are not responsible for any bricked or damaged equipment, outage, lost revenue, tower climb or other loss, and the User agrees not to hold them liable for it.
- The User will use OpenDisco lawfully, never maliciously, and only on networks and devices the User owns or is expressly authorized to scan and administer.
- If anyone makes a claim against those people because of the User's use of OpenDisco, the User covers it.
- Anyone who does not agree must not use OpenDisco.

## 1. Definitions

In these Terms:

- "OpenDisco" means OpenDisco: Open Discovery Tool for Ubiquiti Devices, the software published at github.com/Nekobyte-Coding/opendisco, in every version and form distributed by Nekobyte-Coding, including its installers, packages and apps, the command-line tool included in them, its updates and documentation, and the data it downloads.
- "The User" means the person using OpenDisco and any organization on whose behalf they use it.
- "The Protected Parties" means Nekobyte-Coding (the GitHub account that publishes OpenDisco), Michael Froehlke (its author and copyright holder), and the project's contributors. The protection these Terms give them extends to their heirs, successors and assigns.
- "Equipment" includes any radio, antenna, router, switch, access point, console, computer, phone or other device, and its firmware, configuration and data.
- "Including" means including without limitation.

These Terms are an agreement between the User and Michael Froehlke, who publishes OpenDisco through the Nekobyte-Coding account.

## 2. Acceptance

By selecting "I agree", or by installing, opening or otherwise using OpenDisco, the User accepts these Terms and agrees to be bound by them. Anyone who does not agree must not use OpenDisco, and must close it and remove it.

The person accepting confirms that they have read these Terms, that they are at least the age of majority where they live, and that they are able to enter into a binding agreement. A person accepting on behalf of an employer, client or other organization confirms that they have the authority to bind it, and that organization is bound too. A person without that authority is personally bound.

Selecting "I agree" has the same effect as signing a written agreement.

## 3. OpenDisco's license and these Terms

OpenDisco's source code is open source under the Apache License, Version 2.0, set out in its LICENSE file. These Terms are the terms for using OpenDisco as built and distributed by Nekobyte-Coding: the installers, packages and apps on the repository's Releases page, the app's built-in updates, and any app store listing. They sit alongside the Apache License and do not restrict, amend or take away any right it grants. Where the two conflict about those rights, the Apache License controls.

Sections 7 (Disclaimer of Warranty) and 8 (Limitation of Liability) of the Apache License already provide OpenDisco on an "AS IS" basis and exclude the contributors' liability. These Terms are consistent with those sections, and add the User's own agreements about risk, lawful use, indemnity and release.

## 4. No warranty: OpenDisco is provided "as is"

OPENDISCO IS PROVIDED "AS IS" AND "AS AVAILABLE", WITH ALL FAULTS AND WITHOUT WARRANTY OF ANY KIND. TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE PROTECTED PARTIES DISCLAIM ALL WARRANTIES AND CONDITIONS, WHETHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING ANY WARRANTY OR CONDITION OF MERCHANTABILITY, SATISFACTORY QUALITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT, QUIET ENJOYMENT, ACCURACY OR COMPATIBILITY, AND ANY WARRANTY ARISING FROM A COURSE OF DEALING OR USAGE OF TRADE.

In particular, the Protected Parties do not warrant that:

- OpenDisco will work correctly, without interruption or error, or with any particular equipment, firmware, operating system or network;
- scan results, device identification, status, issues, diagnostics, latency or any other result is accurate, complete or current;
- CVE and vulnerability information is accurate, complete or current, or that a device shown without issues is secure;
- firmware information, such as the latest release, its date, size or checksum, or whether updating is advisable, is accurate or current;
- any firmware update, config change, login change, reboot or other action will succeed or leave the equipment working;
- OpenDisco, its downloads and its updates are free of defects, vulnerabilities or harmful code;
- any defect will be fixed.

No advice or information from any Protected Party, in OpenDisco, its documentation or anywhere else, creates any warranty.

## 5. Assumption of all risk

OpenDisco is a powerful network tool. It sends discovery probes, sweeps subnets, can scan all 65,535 TCP ports of a device, listens to network traffic, adds temporary addresses and tagged VLAN interfaces to the computer with administrator rights, and logs into equipment over SSH and HTTPS. It changes equipment: it updates firmware, edits, uploads and restores configs, changes logins, reboots devices and blinks their LEDs. Its safeguards, such as backups before changes, checksum and model checks and confirmation prompts, reduce some risks but do not remove them, and can fail. Its device steps follow manufacturer documentation and firmware scripts, which can be wrong, can change without notice, and can behave differently on a particular model, hardware revision or firmware.

THE USER USES OPENDISCO ENTIRELY AT THE USER'S OWN RISK AND ACCEPTS ALL RISK ARISING FROM ITS USE, INCLUDING:

- bricked, damaged or unrecoverable radios, routers, switches and other equipment;
- failed, interrupted or corrupted firmware updates, including from a lost connection, a power failure, or a wrong firmware file or version;
- a config upload, restore or edit, or a login change, that cuts off a remote site or locks the User out of a device, which may need a site visit, a tower climb or replacement equipment to recover, together with the hazards of that work;
- outages, degraded service or lost connectivity for a network's users, including a wireless internet service provider's (WISP's) subscribers and clients, and the loss of emergency calling (such as 911, 112 or 999) over that service;
- wrong, unlawful or non-compliant radio settings in a config, including country code, transmit power, frequencies, channel width and DFS, which can cause harmful interference, breach radio regulations or license conditions, and lead to fines or enforcement action;
- a reboot, update or change at a bad time;
- port scans, subnet sweeps, discovery probes and packet capture tripping intrusion detection or prevention systems, firewalls or abuse monitoring, getting the computer or its address blocked, drawing complaints, or making fragile devices crash or restart;
- temporary addresses and VLAN interfaces causing address conflicts or otherwise disturbing a network, including when an interruption leaves them in place;
- lost or corrupted data, configs, backups, settings, notes and logs;
- voided manufacturer warranties, support entitlements or service agreements, or a breach of a manufacturer's or network operator's terms;
- exposure of credentials and sensitive data held in config backups (which contain password hashes, keys and shared secrets), in logins remembered in the operating system's credential store, and in exports, notes and logs;
- connections to older firmware that use outdated encryption, which OpenDisco allows for compatibility;
- wrong or incomplete results leading to wrong decisions, such as a missed device, vulnerability or firmware release;
- faults in beta versions, including the iPhone and iPad app.

The User confirms having the technical knowledge and experience to use network tools of this kind safely, and understanding the equipment and networks the User manages.

## 6. The User's responsibilities

The User alone is responsible for every scan, change and command made with OpenDisco, including every command typed in its SSH sessions, and for the results. OpenDisco being able to do something is not permission to do it. Before and while using OpenDisco, the User will:

- keep current, tested backups of every config and of any other data that matters, including copies kept outside OpenDisco;
- make changes, firmware updates and reboots only in planned maintenance windows, with notice to affected subscribers and clients where their agreements or the law require it;
- check every config, firmware file and setting before applying it, including the radio settings listed in section 5, and confirm it suits that device, model, firmware and location;
- keep out-of-band or local access to remote equipment, such as a console connection, a second management path or someone on site, before changing it;
- follow the manufacturer's documented procedures and recommendations, including for firmware updates and recovery;
- protect config backups, exports, remembered logins and the computer that holds them as carefully as the equipment's own logins, and delete them when no longer needed;
- check OpenDisco's results independently before relying on them for any important decision;
- hold every license and authorization that the equipment, its radio settings and the User's work require;
- handle any personal data in scan results, exports, notes and logs, such as subscribers' IP and MAC addresses, as privacy law requires;
- answer for the acts of anyone the User allows to use OpenDisco.

## 7. Authorized, lawful and non-malicious use only

The User represents, warrants and agrees that the User:

- will use OpenDisco only on networks and equipment the User owns, or is expressly authorized by their owner or operator to scan, monitor and administer, and only within that authorization, which the User will hold before starting, in writing where practical;
- will not use OpenDisco maliciously, or to gain unauthorized access to, disrupt, damage, disable or degrade any network, equipment, service or data;
- will not use OpenDisco to intercept, capture or monitor communications the User is not authorized to monitor, to obtain, crack or misuse credentials, or to bypass or defeat any authentication, security measure or access control;
- will not use OpenDisco to commit, help or encourage any crime, fraud, harassment or surveillance of others, or any infringement of anyone's rights;
- will comply with every law and regulation that applies to the User's use of OpenDisco, including computer-misuse laws (such as the United States Computer Fraud and Abuse Act and the United Kingdom Computer Misuse Act 1990), telecommunications and interception laws, radio-spectrum rules, privacy and data-protection laws, and export-control and sanctions laws;
- will comply with the acceptable-use policies and other terms of any network operator, service provider, employer or client that apply to the User's activity.

The Protected Parties do not monitor or control how OpenDisco is used and are not responsible for any use of it.

## 8. Limitation of liability

TO THE MAXIMUM EXTENT PERMITTED BY LAW, NO PROTECTED PARTY WILL BE LIABLE TO THE USER OR TO ANYONE ELSE FOR ANY DAMAGES OR LOSSES OF ANY KIND ARISING OUT OF OR RELATING TO OPENDISCO, ITS USE OR MISUSE, THE INABILITY TO USE IT, OR THESE TERMS, WHETHER DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY OR PUNITIVE. THIS INCLUDES DAMAGED, BRICKED OR DESTROYED EQUIPMENT; LOST REVENUE, PROFITS, BUSINESS, CUSTOMERS OR GOODWILL; SUBSCRIBER CREDITS, REFUNDS OR PENALTIES; LABOUR, TRUCK ROLLS, SITE VISITS AND TOWER CLIMBS; REPLACEMENT EQUIPMENT; LOST OR CORRUPTED DATA; DOWNTIME AND OUTAGES; FINES; AND THIRD-PARTY CLAIMS. IT APPLIES UNDER ANY THEORY OF LIABILITY, WHETHER CONTRACT, TORT (INCLUDING NEGLIGENCE), STRICT LIABILITY, STATUTE, WARRANTY OR OTHERWISE, EVEN IF A PROTECTED PARTY WAS ADVISED OF THE POSSIBILITY OF THOSE DAMAGES OR THEY WERE FORESEEABLE, AND EVEN IF A REMEDY FAILS OF ITS ESSENTIAL PURPOSE.

WHERE THE LAW DOES NOT ALLOW A LIABILITY TO BE EXCLUDED, THE TOTAL LIABILITY OF ALL THE PROTECTED PARTIES TOGETHER, FOR ALL CLAIMS COMBINED, IS LIMITED TO THE GREATER OF (A) THE AMOUNT THE USER PAID FOR OPENDISCO IN THE TWELVE MONTHS BEFORE THE EVENT GIVING RISE TO THE FIRST CLAIM, AND (B) TEN UNITED STATES DOLLARS (USD 10).

Any claim arising out of or relating to OpenDisco or these Terms must be brought within one year after it arose, or it is permanently barred, to the maximum extent permitted by law.

The User accepts that the disclaimer in section 4, the assumption of risk in section 5 and the limits in this section are a fair allocation of risk and an essential basis of this agreement, without which OpenDisco would not be offered.

## 9. Indemnification

The User will defend, indemnify and hold harmless the Protected Parties from and against every claim, demand, action and proceeding, and every resulting loss, liability, damage, judgment, settlement, fine, penalty, cost and expense (including reasonable lawyers' fees), arising out of or relating to:

- the User's use or misuse of OpenDisco, or its use by anyone the User allows to use it;
- any scan, change, command, config, firmware or setting made or applied with OpenDisco by or for the User;
- the User's breach of these Terms, including the promises in section 7;
- the User's breach of any law or of anyone's rights.

This includes claims by the User's subscribers, clients and employers, by network, equipment, site and tower owners, by other operators, and by regulators. The Protected Parties may take part in, or take control of, the defence of any such claim at the User's expense, and the User will cooperate. The User will not settle any such claim in a way that admits fault for, or places any obligation on, a Protected Party without that Protected Party's written consent.

## 10. Release

To the maximum extent permitted by law, the User releases and forever discharges the Protected Parties from every claim, demand and liability of any kind, known or unknown, suspected or unsuspected, arising out of or relating to OpenDisco or its use, including any claim for damaged equipment, outages or any other loss described in sections 5 and 8, and agrees never to bring any such claim against them.

A User who is a California resident waives California Civil Code section 1542, which says: "A GENERAL RELEASE DOES NOT EXTEND TO CLAIMS THAT THE CREDITOR OR RELEASING PARTY DOES NOT KNOW OR SUSPECT TO EXIST IN HIS OR HER FAVOR AT THE TIME OF EXECUTING THE RELEASE AND THAT, IF KNOWN BY HIM OR HER, WOULD HAVE MATERIALLY AFFECTED HIS OR HER SETTLEMENT WITH THE DEBTOR OR RELEASED PARTY." The User also waives any similar law elsewhere.

## 11. No support or updates

The Protected Parties have no obligation to provide support, maintenance, fixes, security patches, updates or new versions, to answer questions or reports, or to keep any feature, download, update check or data source available. They may change, suspend or stop distributing OpenDisco, or any part of it, at any time without notice. Any help they do give is voluntary, can stop at any time, and is covered by these Terms.

## 12. Third-party services and software

OpenDisco contacts these third-party services:

- Ubiquiti's firmware server, to look up and download firmware releases, and Ubiquiti's security advisories, for vulnerability data;
- the National Vulnerability Database (NVD) at NIST, for CVE data;
- GitHub, to check for and download OpenDisco updates;
- on Windows, npcap.com, to download Npcap, the Nmap Project's packet-capture driver, which has its own license; its free license covers only a limited number of computers.

None of these services or their operators is affiliated with OpenDisco, and none endorses it. The Protected Parties do not control them, do not guarantee their availability, accuracy or security, and are not responsible for them, for their content (including firmware files and vulnerability data), or for what they do with the information they receive. Each request gives the service what it needs, including the computer's IP address and, for firmware lookups, device platform names, and each service handles that under its own terms and privacy policy. OpenDisco has no analytics or tracking of its own. The automatic update, CVE and firmware checks can be turned off in Settings. This product uses the NVD API but is not endorsed or certified by the NVD.

Other software that OpenDisco uses or includes, such as the operating system's SSH client and credential store, and the components named in OpenDisco's NOTICE file, is provided by others under its own terms. Where OpenDisco is obtained through an app store, that store's terms also apply to the download; the store's operator is not a party to these Terms and is not responsible for OpenDisco.

## 13. No affiliation with Ubiquiti

OpenDisco is an independent project. It is not made, endorsed, sponsored or supported by Ubiquiti Inc. or any other equipment maker. Ubiquiti, UniFi, airMAX, EdgeMAX, UISP, AmpliFi and WiFiman are trademarks of Ubiquiti Inc., and other product names belong to their owners; OpenDisco uses them only to say what it works with.

## 14. Changes to these Terms

A new version of OpenDisco may come with changed Terms. The Terms are shown again after every upgrade, and must be accepted again to keep using OpenDisco. Each acceptance applies from then on, and does not reduce the protection that Terms accepted earlier give the Protected Parties for anything that happened while those Terms were in force.

## 15. Where the law limits these Terms

Some jurisdictions do not allow certain warranties to be excluded, certain liability to be limited or excluded (for example, liability for death or personal injury caused by negligence, for fraud, or for gross negligence or wilful misconduct), or certain consumer rights to be waived. Where such a law applies, the affected parts of these Terms apply to the fullest extent that law permits. So some of these limits may not apply to a particular User, but every other part of these Terms still applies in full. Nothing in these Terms excludes or limits any liability or right that cannot lawfully be excluded or limited.

## 16. General

- Severability: if any part of these Terms is found invalid or unenforceable, it is enforced to the maximum extent permitted and changed only as much as needed to make it enforceable, and the rest of these Terms remains in full effect.
- Survival: sections 4 to 10, 15 and 16 continue to apply after the User stops using or removes OpenDisco, and after any later version of these Terms is accepted.
- No waiver: a failure or delay in enforcing any part of these Terms is not a waiver of it.
- Entire agreement: these Terms, together with the Apache License for the rights it grants, are the entire agreement about the User's use of OpenDisco, and replace any earlier understanding about it.
- Third-party beneficiaries: every Protected Party may rely on and enforce these Terms directly, including those who are not a party to them.
- Assignment: the User may not transfer these Terms or any right under them. Michael Froehlke may transfer them, for example together with the project.
- Interpretation: headings are for convenience only. If these Terms are translated, the English version controls.
