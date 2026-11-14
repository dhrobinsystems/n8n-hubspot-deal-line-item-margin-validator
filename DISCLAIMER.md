# ⚠️ Disclaimer & Liability Limitation

**Use at your own risk.** I built `n8n-hubspot-deal-line-item-margin-validator` as an open-source reference implementation of deal-desk margin governance. It reads deal, line-item, and product data from HubSpot, writes validation results back to deal properties, and creates approval tasks for sales leadership. Every one of those actions affects how your team prices and closes revenue. You alone are responsible for how you configure, deploy, and operate it.

- **No Liability.** In no event shall the author, DH Robin, or dhRobin Systems be liable for any direct, indirect, incidental, special, exemplary, or consequential damages arising from the use of this software. That includes, without limitation, mispriced or unprofitable deals, missed or duplicated approval tasks, incorrect margin or discount calculations, overwritten deal properties, lost revenue, lost data, commission disputes, or business interruption, however caused and on any theory of liability.

- **No Warranty.** The software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. I make no guarantee that the margin math matches your accounting treatment, that the example thresholds suit your business, or that HubSpot's APIs will keep behaving as they do today.

- **Production Testing Required.** Run it with `SANDBOX_MODE=true` and `DRY_RUN=true` (the defaults) in a HubSpot sandbox or developer test portal first. Compare the verdicts against deals your finance team has already reviewed by hand before you enable writes. Treat every validation write and every approval task as visible to your sales team the moment it lands: a wrong "approval required" flag stalls a live deal, and a wrong "passed" flag lets a below-margin deal through. Only set `SANDBOX_MODE=false` together with `ALLOW_PRODUCTION_MODE=true` after you have signed off on your own rules.

- **Third-Party APIs & Compliance.** HubSpot, n8n, and any chat or logging webhooks you connect are third-party services under their own terms, rate limits, and data-processing agreements. Costs of goods sold, floor prices, and discount policies are commercially sensitive; you are responsible for who can see the deal properties, tasks, notifications, and audit logs this workflow produces, and for compliance with your internal pricing, revenue-recognition, and approval policies. This software is not accounting, financial, or legal advice.

By using, copying, modifying, or distributing this software, you acknowledge that you have read this disclaimer and accept these terms.

## License

Released under the MIT License. Copyright (c) 2026 DH Robin (dhRobin Systems). See [LICENSE](https://github.com/dhrobinsystems/n8n-hubspot-deal-line-item-margin-validator/blob/main/LICENSE).

---

DISCLAIMER.md · Licensed under the MIT License. License: MIT © 2026 dhRobin Systems · Provided as-is, see the disclaimer.
