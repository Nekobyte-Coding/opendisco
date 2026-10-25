# OpenDisco Terms of Use

Version {version}. Effective when accepted.

## Summary

This summary is a plain-English overview only. It does not replace the full Terms below, which control.

- OpenDisco's source code is free and open source. OpenDisco is provided "as is", with no warranty of any kind, to the extent the law allows.
- OpenDisco scans networks, logs into devices and changes them: it updates firmware, edits, uploads and restores configs, changes logins and reboots devices. Any of that can brick a radio, cut off a remote site or take subscribers offline. The User accepts all of that risk.
- Its device tools have been tested only on simulated devices, not yet on real equipment.
- Nekobyte-Coding, Michael Froehlke and the project's contributors are not responsible for any bricked or damaged equipment, outage, lost revenue, tower climb or other loss, to the fullest extent the law allows, and the User agrees not to hold them liable for it.
- The User will use OpenDisco lawfully, never maliciously, and only on networks and devices the User owns or is expressly authorized to scan and administer.
- If anyone makes a claim against those people because of the User's use of OpenDisco, the User covers it.
- Anyone who does not agree must not use OpenDisco.

## 1. Definitions

In these Terms:

- "OpenDisco" means OpenDisco: Open Discovery Tool for Ubiquiti Devices, the software published at github.com/Nekobyte-Coding/opendisco, in every version and form distributed by Nekobyte-Coding, including its installers, packages and apps, the command-line tool included in them, its updates, its documentation and the CVE list published with it, and also any other copy of it on which the User accepts these Terms.
- "Third-Party Content" means firmware, security advisories, vulnerability data and other content that OpenDisco fetches from third parties. It is not part of OpenDisco.
- "The User" means the person using OpenDisco and any organization on whose behalf they use it.
- "The Protected Parties" means Nekobyte-Coding (the GitHub account that publishes OpenDisco), Michael Froehlke (its author and copyright holder), and the project's contributors. The protection these Terms give them extends to their heirs, successors and assigns.
- "The Component Authors" means the authors and contributors of the third-party software components included in OpenDisco, as listed in its third-party notices (shown in the app as "Open-source licenses").
- "Equipment" includes any radio, antenna, router, switch, access point, console, computer, phone or other device, and its firmware, configuration and data.
- "Including" means including without limitation.

These Terms are an agreement between the User and Michael Froehlke, who publishes OpenDisco through the Nekobyte-Coding account.

## 2. Acceptance

By selecting "I agree" (on the command line, by typing it or by using the --accept-terms option), or by installing, opening or otherwise using OpenDisco, the User accepts these Terms and agrees to be bound by them. Anyone who does not agree must not use OpenDisco, and must close it and remove it.

The person accepting confirms that they have read these Terms, that they are at least 18 years old and the age of majority where they live, and that they are able to enter into a binding agreement. A person accepting on behalf of an employer, client or other organization confirms that they have the authority to bind it, and that organization is bound too. A person without that authority is personally bound.

Accepting in any of these ways has the same effect as signing a written agreement.

## 3. OpenDisco's licenses and these Terms

OpenDisco's source code is open source under the Apache License, Version 2.0, set out in its LICENSE file. OpenDisco also includes third-party components under their own open-source licenses, listed in its third-party notices, which also say where each component's source code can be obtained.

These Terms are the terms for using OpenDisco as built and distributed by Nekobyte-Coding: the installers, packages and apps on the repository's Releases page, the app's built-in updates, and any app store listing. They also apply to any other copy of OpenDisco on which the User accepts them.

Nothing in these Terms restricts, amends or takes away any right that the Apache License or a component's license grants, including any right to obtain the source code, to copy, modify or distribute it, or to modify a component and reverse engineer OpenDisco to debug that modification. Where these Terms conflict with one of those licenses about a right that license grants, that license controls for that right only, and the rest of these Terms still applies. Anyone who redistributes a component must follow that component's license.

The User's agreements in these Terms, including those in sections 5 to 10, are contractual promises made to the Protected Parties in return for their making OpenDisco available. They are not conditions of the Apache License or of any component's license, and do not limit the copyright and patent licenses those licenses grant. A breach of them is a breach of these Terms.

Sections 7 (Disclaimer of Warranty) and 8 (Limitation of Liability) of the Apache License already provide OpenDisco on an "AS IS" basis and exclude the contributors' liability. These Terms are consistent with those sections, and add the User's own agreements about risk, lawful use, indemnity and release.

If a copy of OpenDisco was not built and distributed by Nekobyte-Coding, for example a copy built from source or obtained from someone else, the Protected Parties did not make or distribute that copy and are not responsible for it or for any change made to it, and these Terms still protect them.

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

OpenDisco's results, statuses, issue lists, CVE matches and firmware information are automated general information, not advice. The User must not rely on them without checking them, and makes every decision based on them, such as whether a device is secure or whether to update it, on the User's own judgment. No advice or information from any Protected Party, in OpenDisco, its documentation or anywhere else, creates any warranty.

Third-Party Content is provided by its owner under the owner's terms, which the User must follow. OpenDisco fetches it only when the User asks or allows it to, and the Protected Parties give no warranty about it and are not its distributor.

The disclaimers in this section, and the exclusions of liability in section 8, are also made for the Component Authors.

## 5. Assumption of all risk

OpenDisco is intended for administrators of networks and equipment that they own or are authorized to manage. It is a powerful network tool. It sends discovery probes, sweeps subnets, can scan all 65,535 TCP ports of a device, listens to network traffic, adds temporary addresses and tagged VLAN interfaces to the computer with administrator rights, and logs into equipment over SSH and HTTPS. It changes equipment: it updates firmware, edits, uploads and restores configs, changes logins, reboots devices and blinks their LEDs. Its safeguards, such as backups before changes, checksum and model checks and confirmation prompts, reduce some risks but do not remove them, and can fail. Its device steps follow manufacturer documentation and firmware scripts, which can be wrong, can change without notice, and can behave differently on a particular model, hardware revision or firmware.

OpenDisco's device tools (firmware updates, config editing, uploads and restores, login changes, reboots and Locate) have been tested only against simulated devices, not yet on real equipment. Known issues and limitations are listed in the README and the release notes. The User must treat every use of a device tool on the User's equipment as untested until the User has tested it there.

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

OpenDisco is not a safety or emergency system, and is not designed or tested to keep any network available. Where a network carries emergency calling or other services that people's safety depends on, the User alone is responsible for keeping them available, including by planning changes so that a failed change does not leave anyone without them.

The Protected Parties give no safety advice. Any site visit, tower climb or other field work, including work to recover equipment, is the User's own operation, carried out under the User's own safety rules and legal duties.

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
- follow the license and terms of all firmware and other Third-Party Content that the User fetches or installs with OpenDisco;
- handle any personal data in scan results, config backups, exports, notes and logs, such as subscribers' names and their IP and MAC addresses, as privacy law requires. The User decides what OpenDisco is used to collect and is responsible for it under data-protection law. OpenDisco keeps it on the User's own devices and sends none of it to the Protected Parties;
- answer for the acts of anyone the User allows to use OpenDisco.

## 7. Authorized, lawful and non-malicious use only

The User represents, warrants and agrees that the User:

- will use OpenDisco only on networks and equipment the User owns, or is expressly authorized by their owner or operator to scan, monitor and administer, and only within that authorization, which the User will hold before starting, in writing where practical;
- will not use OpenDisco maliciously, or to gain unauthorized access to, disrupt, damage, disable or degrade any network, equipment, service or data;
- will not use OpenDisco to intercept, capture or monitor communications the User is not authorized to monitor, to obtain, crack or misuse credentials, or to bypass or defeat any authentication, security measure or access control;
- will not use OpenDisco to commit, help or encourage any crime, fraud, harassment or surveillance of others, or any infringement of anyone's rights;
- will comply with every law and regulation that applies to the User's use of OpenDisco, including computer-misuse laws (such as the United States Computer Fraud and Abuse Act, California Penal Code section 502 and the United Kingdom Computer Misuse Act 1990), telecommunications and interception laws, radio-spectrum rules, and privacy and data-protection laws;
- is not located in, ordinarily resident in or a national of a country or region subject to comprehensive United States, European Union or United Kingdom sanctions, is not named on any government list of prohibited or restricted parties, and will not use, export or provide OpenDisco in breach of export-control or sanctions laws;
- will comply with the acceptable-use policies and other terms of any network operator, service provider, employer or client that apply to the User's activity.

Each of these promises is made to every Protected Party. The Protected Parties do not monitor or control how OpenDisco is used and are not responsible for any use of it.

## 8. Limitation of liability

NOTHING IN THESE TERMS EXCLUDES OR LIMITS ANY LIABILITY FOR DEATH OR PERSONAL INJURY CAUSED BY NEGLIGENCE; FOR FRAUD OR FRAUDULENT MISREPRESENTATION; FOR GROSS NEGLIGENCE, WILFUL MISCONDUCT, WILFUL INJURY TO A PERSON OR PROPERTY, OR VIOLATION OF LAW, WHERE THE APPLICABLE LAW (INCLUDING CALIFORNIA CIVIL CODE SECTION 1668) DOES NOT ALLOW IT TO BE EXCLUDED; OR ANY OTHER LIABILITY OR CONSUMER RIGHT THAT CANNOT LAWFULLY BE EXCLUDED OR LIMITED. SUBJECT TO THAT:

TO THE MAXIMUM EXTENT PERMITTED BY LAW, NO PROTECTED PARTY AND NO COMPONENT AUTHOR WILL BE LIABLE TO THE USER OR TO ANYONE ELSE FOR ANY DAMAGES OR LOSSES OF ANY KIND ARISING OUT OF OR RELATING TO OPENDISCO, ITS USE OR MISUSE, THE INABILITY TO USE IT, OR THESE TERMS, WHETHER DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY OR PUNITIVE. THIS INCLUDES DAMAGED, BRICKED OR DESTROYED EQUIPMENT; LOST REVENUE, PROFITS, BUSINESS, CUSTOMERS OR GOODWILL; SUBSCRIBER CREDITS, REFUNDS OR PENALTIES; LABOUR, TRUCK ROLLS, SITE VISITS AND TOWER CLIMBS; REPLACEMENT EQUIPMENT; LOST OR CORRUPTED DATA; DOWNTIME AND OUTAGES; FINES; AND THIRD-PARTY CLAIMS. IT APPLIES UNDER ANY THEORY OF LIABILITY, WHETHER CONTRACT, TORT (INCLUDING NEGLIGENCE, AND INCLUDING A PROTECTED PARTY'S OR COMPONENT AUTHOR'S OWN NEGLIGENCE), STRICT LIABILITY, STATUTE, WARRANTY OR OTHERWISE, EVEN IF A PROTECTED PARTY OR COMPONENT AUTHOR WAS ADVISED OF THE POSSIBILITY OF THOSE DAMAGES OR THEY WERE FORESEEABLE, AND EVEN IF A REMEDY FAILS OF ITS ESSENTIAL PURPOSE.

WHERE THE LAW DOES NOT ALLOW A LIABILITY TO BE EXCLUDED, THE TOTAL LIABILITY OF ALL THE PROTECTED PARTIES AND COMPONENT AUTHORS TOGETHER, FOR ALL CLAIMS COMBINED, IS LIMITED TO THE GREATER OF (A) THE AMOUNT THE USER PAID FOR OPENDISCO IN THE TWELVE MONTHS BEFORE THE EVENT GIVING RISE TO THE FIRST CLAIM, AND (B) TEN UNITED STATES DOLLARS (USD 10).

Any claim arising out of or relating to OpenDisco or these Terms must be brought within one year after it arose, or it is permanently barred, to the maximum extent permitted by law.

The User accepts that the disclaimer in section 4, the assumption of risk in section 5 and the limits in this section are a fair allocation of risk and an essential basis of this agreement, without which OpenDisco would not be offered.

## 9. Indemnification

THE USER WILL DEFEND, INDEMNIFY AND HOLD HARMLESS THE PROTECTED PARTIES FROM AND AGAINST EVERY CLAIM, DEMAND, ACTION AND PROCEEDING BROUGHT BY ANYONE OTHER THAN THE USER, AND EVERY RESULTING LOSS, LIABILITY, DAMAGE, JUDGMENT, SETTLEMENT, FINE, PENALTY, COST AND EXPENSE (INCLUDING REASONABLE LAWYERS' FEES), ARISING OUT OF OR RELATING TO:

- THE USER'S USE OR MISUSE OF OPENDISCO, OR ITS USE BY ANYONE THE USER ALLOWS TO USE IT;
- ANY SCAN, CHANGE, COMMAND, CONFIG, FIRMWARE OR SETTING MADE OR APPLIED WITH OPENDISCO BY OR FOR THE USER;
- THE USER'S BREACH OF THESE TERMS, INCLUDING THE PROMISES IN SECTION 7;
- THE USER'S BREACH OF ANY LAW OR OF ANYONE'S RIGHTS.

THIS APPLIES EVEN IF THE CLAIM ALLEGES, OR A COURT FINDS, THAT A PROTECTED PARTY WAS NEGLIGENT OR THAT OPENDISCO WAS DEFECTIVE, EXCEPT TO THE EXTENT A COURT FINALLY DECIDES THAT THE LOSS WAS CAUSED BY THAT PROTECTED PARTY'S FRAUD, GROSS NEGLIGENCE, WILFUL MISCONDUCT OR VIOLATION OF LAW. IT COVERS CLAIMS AND PROCEEDINGS BY THE USER'S SUBSCRIBERS, CLIENTS AND EMPLOYERS; BY WORKERS, CONTRACTORS AND ANYONE ELSE INJURED, INCLUDING IN A SITE VISIT OR TOWER CLIMB; BY NETWORK, EQUIPMENT, SITE AND TOWER OWNERS; BY ANYONE WHOSE NETWORK OR EQUIPMENT WAS SCANNED, ACCESSED OR CHANGED; BY OTHER OPERATORS; AND BY REGULATORS, PROSECUTORS AND OTHER AUTHORITIES.

The Protected Parties may use counsel of their choice, and may take part in, or take control of, the defence of any such claim at the User's expense, and the User will cooperate. The User will not settle any such claim in a way that admits fault for, or places any obligation on, a Protected Party without that Protected Party's written consent.

If the User is a consumer, this section applies only to claims caused by the User's own breach of these Terms or of the law.

## 10. Release

TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE USER RELEASES AND FOREVER DISCHARGES THE PROTECTED PARTIES FROM EVERY CLAIM, DEMAND AND LIABILITY OF ANY KIND, KNOWN OR UNKNOWN, SUSPECTED OR UNSUSPECTED, ARISING OUT OF OR RELATING TO THE USER'S USE OF OPENDISCO AFTER THE USER ACCEPTS THESE TERMS. THIS INCLUDES ANY CLAIM FOR DAMAGED EQUIPMENT, OUTAGES OR ANY OTHER LOSS DESCRIBED IN SECTIONS 5 AND 8, AND ANY CLAIM THAT A PROTECTED PARTY WAS NEGLIGENT OR THAT OPENDISCO WAS DEFECTIVE, BUT NOT CLAIMS FOR FRAUD, GROSS NEGLIGENCE, WILFUL MISCONDUCT, WILFUL INJURY TO A PERSON OR PROPERTY, OR VIOLATION OF LAW, WHERE THE APPLICABLE LAW (INCLUDING CALIFORNIA CIVIL CODE SECTION 1668) DOES NOT ALLOW THEM TO BE RELEASED. THE USER AGREES NEVER TO BRING ANY CLAIM RELEASED BY THIS SECTION AGAINST THEM.

Claims about the User's earlier use of OpenDisco remain governed by the Terms the User accepted then or, where there were none, by the Apache License. This section does not apply to rights of a consumer that the law of the place where the consumer lives does not allow to be released in advance, or to any right to seek public injunctive relief that the law does not allow to be waived.

The User waives California Civil Code section 1542, which says: "A GENERAL RELEASE DOES NOT EXTEND TO CLAIMS THAT THE CREDITOR OR RELEASING PARTY DOES NOT KNOW OR SUSPECT TO EXIST IN HIS OR HER FAVOR AT THE TIME OF EXECUTING THE RELEASE AND THAT, IF KNOWN BY HIM OR HER, WOULD HAVE MATERIALLY AFFECTED HIS OR HER SETTLEMENT WITH THE DEBTOR OR RELEASED PARTY." The User also waives any similar law elsewhere.

## 11. No support or updates

The Protected Parties have no obligation to provide support, maintenance, fixes, security patches, updates or new versions, to answer questions or reports, or to keep any feature, download, update check or data source available. They may change, suspend or stop distributing OpenDisco, or any part of it, at any time without notice. Any help they do give is voluntary, can stop at any time, and is covered by these Terms. For a copy obtained through an app store, this section is subject to section 17.

## 12. Third-party services and software

OpenDisco contacts these third-party services:

- Ubiquiti's firmware server, to look up firmware releases and, when the User asks, to download them;
- Ubiquiti's security advisories, for vulnerability data;
- the National Vulnerability Database (NVD) at NIST, for CVE data;
- GitHub, to check for and download OpenDisco updates;
- on Windows, npcap.com, to download Npcap, the Nmap Project's packet-capture driver, which has its own license; its free license covers only a limited number of computers.

None of these services or their operators is affiliated with OpenDisco, and none endorses it. The Protected Parties do not control them, do not guarantee their availability, accuracy or security, and are not responsible for them, for their content (including firmware files and vulnerability data), or for what they do with the information they receive. Each request gives the service what it needs, including the computer's IP address and, for firmware lookups, device platform names, and each service handles that under its own terms and privacy policy. OpenDisco sends the Protected Parties no information about the User or the User's networks or devices; it has no analytics or tracking. The automatic update, CVE and firmware checks can be turned off in Settings, and firmware is downloaded only when the User asks. This product uses the NVD API but is not endorsed or certified by the NVD.

Other software that OpenDisco uses or includes, such as the operating system's SSH client and credential store, and the components named in OpenDisco's third-party notices, is provided by others under its own terms.

The Windows version of OpenDisco includes Microsoft's Visual C++ runtime as part of Python. The User will not remove or alter its copyright, trademark or patent notices, use Microsoft's trademarks to suggest that Microsoft made or endorses OpenDisco, run it on any platform other than Microsoft Windows, or include it in a malicious, deceptive or unlawful program.

## 13. No affiliation with Ubiquiti

OpenDisco is an independent project. It is not made, endorsed, sponsored or supported by Ubiquiti Inc. or any other equipment maker. Ubiquiti has not reviewed, tested or approved OpenDisco or the device steps it uses. Ubiquiti, UniFi, UniFi OS, airMAX, airFiber, LTU, GigaBeam, EdgeMAX, EdgeOS, EdgeRouter, EdgeSwitch, UISP, AmpliFi and WiFiman are trademarks of Ubiquiti Inc., and other product names belong to their owners; OpenDisco uses them only to say what it works with.

## 14. Changes to these Terms

A new version of OpenDisco may come with changed Terms. When an update changes these Terms, OpenDisco says so before the update is installed where it can, and shows the new Terms before the new version is used. They must be accepted again to keep using OpenDisco. Each acceptance applies from then on, and does not reduce the protection that Terms accepted earlier give the Protected Parties for anything that happened while those Terms were in force.

## 15. Where the law limits these Terms

Some jurisdictions do not allow certain warranties to be excluded, certain liability to be limited or excluded, or certain consumer rights to be waived. Where such a law applies, the affected parts of these Terms apply to the fullest extent that law permits. So some of these limits may not apply to a particular User, but every other part of these Terms still applies in full.

## 16. General

- Governing law and courts: these Terms, and any dispute or claim arising out of or relating to them or to OpenDisco, are governed by the laws of the State of California, United States of America, without regard to its conflict-of-laws rules. The United Nations Convention on Contracts for the International Sale of Goods does not apply. The state and federal courts located in California have exclusive jurisdiction, and the User consents to their personal jurisdiction and to venue there. A User who is a consumer keeps the protection of the mandatory laws of the place where the User lives, and may bring proceedings in its courts, where those laws give the User that right.
- Legal notices: legal notices to the Protected Parties must be sent privately, through the repository's private reporting form at github.com/Nekobyte-Coding/opendisco/security/advisories/new. If that form is not available, the sender may open an issue at github.com/Nekobyte-Coding/opendisco/issues asking for a private contact, without including the content of the notice.
- Relationship: nothing in these Terms makes the User and any Protected Party partners, joint venturers, agents, or employer and employee, and no Protected Party takes part in, directs or approves any use of OpenDisco.
- Severability: if any part of these Terms is found invalid or unenforceable, it is enforced to the maximum extent permitted. Where a court may change it to make it enforceable, it is changed only as much as needed; where a court may not, only that part is set aside. Either way, the rest of these Terms remains in full effect.
- Survival: sections 3 to 10, 12, 13, 15, 16 and 17 continue to apply after the User stops using or removes OpenDisco, and after any later version of these Terms is accepted.
- No waiver: a failure or delay in enforcing any part of these Terms is not a waiver of it.
- Entire agreement: these Terms, together with the Apache License and the components' licenses for the rights they grant, are the entire agreement about the User's use of OpenDisco, and replace any earlier understanding about it.
- Third-party beneficiaries: every Protected Party, and every Component Author for sections 4 and 8, may rely on and enforce these Terms directly, including those who are not a party to them.
- Assignment: the User may not transfer these Terms or any right under them. Michael Froehlke may transfer them, for example together with the project.
- Interpretation: headings are for convenience only. If these Terms are translated, the English version controls.

## 17. Copies from an app store

This section applies only to a copy of OpenDisco obtained through an app store. For that copy it applies in addition to the rest of these Terms and, where they conflict, instead of them. The store's own terms also apply to the download. The store's operator is not a party to these Terms and is not responsible for OpenDisco, except as this section says for Apple. Google is not a party to these Terms.

For a copy obtained through Apple's App Store:

- These Terms are between the User and Michael Froehlke only, not Apple Inc. ("Apple"). Michael Froehlke, not Apple, is solely responsible for OpenDisco and its content.
- The User may use that copy on Apple-branded products that the User owns or controls, as the Usage Rules in Apple's Media Services Terms and Conditions allow, including through Family Sharing where it applies. This permission is not transferable, and, as section 3 says, it does not limit any right under the Apache License or a component's license.
- Apple has no obligation to provide any maintenance or support for OpenDisco. Any maintenance or support that the law requires is Michael Froehlke's responsibility alone.
- If OpenDisco fails to conform to any warranty that applies and has not been effectively disclaimed, the User may notify Apple, and Apple will refund the purchase price, if any. To the maximum extent permitted by law, Apple has no other warranty obligation for OpenDisco. As between Apple and Michael Froehlke, any other claims, losses, liabilities, damages, costs or expenses caused by a failure to conform to a warranty are Michael Froehlke's responsibility, within the limits of these Terms.
- Michael Froehlke, not Apple, is responsible for addressing any claims by the User or any third party relating to OpenDisco or its possession or use, including product liability claims, claims that it fails to conform to any legal or regulatory requirement, and claims under consumer protection, privacy or similar laws. These Terms do not limit Michael Froehlke's liability to the User beyond what the law allows.
- As between Apple and Michael Froehlke, if a third party claims that OpenDisco, or the User's possession and use of it, infringes that third party's intellectual property rights, Michael Froehlke, not Apple, is responsible for the investigation, defence, settlement and discharge of that claim.
- The User represents that the User is not located in a country that is subject to a United States Government embargo or that the United States Government has designated as a "terrorist supporting" country, and is not listed on any United States Government list of prohibited or restricted parties.
- Questions, complaints and claims about OpenDisco go to Michael Froehlke in the way section 16 sets out for legal notices.
- The User must comply with any third-party terms that apply when using OpenDisco, such as those of the User's network or service provider.
- Apple and its subsidiaries are third-party beneficiaries of these Terms, and once the User accepts them, Apple has the right to enforce them against the User as a third-party beneficiary.

Where OpenDisco is bought, a User who is a consumer keeps the rights the consumer's law gives, such as rights to digital content that conforms to the contract and to the updates needed to keep it conforming, and nothing in these Terms limits those rights. In Australia, OpenDisco bought by a consumer comes with guarantees under the Australian Consumer Law that cannot be excluded, and nothing in these Terms excludes, restricts or modifies them.
