# Haze Fuji Compliance Portal Auditor Workstation Design Addendum

## Summary

This design addendum specifies the interaction design, layouts, states, wireframes, data contracts, and accessibility acceptance criteria for the `/audit` institutional compliance workstation on Avalanche Fuji (`chainId = 43113`).

The goal is an industrial, utilitarian, and trustworthy audit interface built strictly on Haze's alpine-volcanic design system. It enables institutional auditors to authenticate via SIWE, review assigned compliance cases, independently verify on-chain evidence with at least 12 confirmations, decrypt granted fields in-memory, review and download canonically signed exports, and inspect tamper-evident personal access logs.

---

## 1. Visual Foundation & Palette

The `/audit` workstation adheres strictly to the existing Haze design tokens and shell:
- **CSS Variables & Palette**:
  - Background: `var(--haze-bg)` (`#16130f`)
  - Surfaces / Cards: `var(--haze-surface)` (`#221e18`)
  - Text: `var(--haze-text)` (`#f3ece2`)
  - Muted Text / Labels: `var(--haze-muted)` (`#d4c4ae`)
  - Primary Accent & Focus: `var(--haze-accent)` (`#1f6b62`) (Text: `#f3ece2`)
  - Public / Warning: `var(--haze-public)` (`#c47a3a`)
  - Private / Detail: `var(--haze-private)` (`#8ea3c7`)
  - Borders & Dividers: `var(--haze-line)` (`color-mix(in srgb, var(--haze-muted) 22%, transparent)`)
- **Typography**:
  - Primary UI & Prose: `IBM Plex Sans`, `ui-sans-serif`, `system-ui`, `sans-serif`
  - Code, Hashes, Amounts, Timestamps: `IBM Plex Mono`, `ui-monospace`, `monospace`
  - Tabular numerals enabled (`font-variant-numeric: tabular-nums`) for currency and identifiers
- **Rules**:
  - No neon teal `#00E5C9`, emoji status icons, gradients, glassmorphism, or new external CSS libraries.
  - Full-width workspace container within the existing `.haze-shell` and `.haze-stage` (bypassing the 440px pool card constraint).
  - Single header integration using existing Haze top bar (no duplicated portal header).
  - Minimum color contrast ratio >= 4.5:1 for normal text and >= 3:1 for large text / UI controls.
  - Status is never communicated by color alone: all status badges and integrity checklist items use explicit text labels and semantic accessible elements.

---

## 2. Authentication State Machine & Flow

### Unauthenticated Surface
When navigating to `/audit` without an active session, the user is presented with a single focused card: **"Fuji Auditor Access"**.

```
+-------------------------------------------------------------+
|                      HAZE COMPLIANCE                        |
|                                                             |
|  [ Fuji · 43113 ]  [ Application: 0x00...0a11 ]             |
|                                                             |
|  Institutional Auditor Sign-In                              |
|  Connect an authorized auditor wallet to inspect assigned   |
|  compliance cases and chain evidence.                       |
|                                                             |
|  [ 1. Connect Wallet ]                                      |
|                                                             |
|  -- After Connection --                                     |
|  Connected: 0xAuditor...1234                                |
|  Auditor Session Duration: 1 hour                           |
|                                                             |
|  [ 2. Review Identity & Sign with Ethereum ]                |
|                                                             |
|  [Status Banner: Polite ARIA message]                       |
+-------------------------------------------------------------+
```

### Authentication Lifecycle:
1. **Wallet Connection**:
   - Checks chain ID `43113` (Avalanche Fuji). If wrong network, prompts network switch.
   - Reads connected address.
2. **SIWE Challenge**:
   - Calls `POST /api/compliance/auth/challenge` to obtain a single-use nonce, domain, issued-at, and expiry.
3. **EIP-191 Signature**:
   - Formats standard SIWE message:
     ```
     ${domain} wants you to sign in with your Ethereum account:
     ${address}

     Sign in to Haze Compliance Portal (Fuji)

     URI: ${uri}
     Version: 1
     Chain ID: 43113
     Nonce: ${nonce}
     Issued At: ${issuedAt}
     Expiration Time: ${expirationTime}
     Resources:
     - urn:haze:app:${applicationId}
     ```
   - User signs message with `personal_sign`.
4. **Verification & Session Creation**:
   - Calls `POST /api/compliance/auth/verify` with message and signature.
   - Backend validates nonce, domain, signature, grant status, and creates an opaque hashed session stored in Postgres.
   - Sets `Set-Cookie: haze_audit_session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/`.
   - Returns UI-safe `AuditSession`.
5. **Error & Recovery States**:
   - *Wrong Wallet*: Clear message "Connected wallet has no active auditor grant for application 0x...0a11" with "Connect Different Wallet" button.
   - *Signature Rejected*: "Signature was rejected in wallet. Please try again."
   - *Session Expired*: "Your auditor session has expired. Sign in again to resume."
   - *Service Unavailable*: "Compliance service is temporarily unavailable. Please retry shortly."

---

## 3. Authenticated Master-Detail Workstation

### Layout Hierarchy

#### Desktop (>= 1080px)
Three-column fixed-fluid grid:
- **Left Column (260px)**: Case Queue (assigned cases list with status and grant expiry).
- **Middle Column (Flexible / 1fr)**: Case Disclosure Record (case details, "Verify & disclose" action, decrypted fields).
- **Right Column (280px)**: Integrity & Access History Panel (12-confirmation chain verification checklist, export action, personal access log).

```
+-----------------------------------------------------------------------------------------------------------------+
| HAZE COMPLIANCE  [Fuji · 43113] [App 0x...0a11] [Auditor 0x...1234] [Sign Out]                                 |
+-------------------+---------------------------------------------------------+-----------------------------------+
| ASSIGNED CASES    | CASE: fuji-withdrawal-8218e5a4                          | INTEGRITY & FINALITY              |
| [Search Cases...] | Fuji USDC Withdrawal Investigation                      |                                   |
|                   | Status: [Verified]  Grant Expiry: 2026-09-01 00:00 UTC  | [x] 12+ Confirmations (58 blocks) |
| > Case 8218e5a4   | Tx: 0x8218...8a03 [Copy] [Snowtrace]                    | [x] Canonical Receipt & Block 0x1 |
|   Withdrawal 1M   |                                                         | [x] PrivateTransaction Event      |
|   [Active]        | Granted Fields:                                         | [x] App & Action Bound (Withdraw) |
|                   | [tx_hash] [amount] [asset] [timestamp] [policy_version] | [x] Envelope Hash Verified        |
|   Case 9b12c4d1   |                                                         | [x] Audit Commitment Matched      |
|   Deposit 500k    | [ Verify & Disclose Evidence ]                          |                                   |
|   [Closed]        | ------------------------------------------------------- | EXPORT                            |
|                   | DISCLOSED RECORD                                        | [ Download Signed Export ]        |
|                   | Transaction Hash: 0x8218e5a4...232c8a03                 |                                   |
|                   | Amount:           1.000000 USDC                         | PERSONAL ACCESS HISTORY           |
|                   | Asset:            0x54258902...11a31Bc65                | 09:15:20 query (allowed)          |
|                   | Timestamp:        2026-08-21 23:05:12 Local (UTC)       | 09:14:02 login (allowed)          |
|                   | Policy Version:   1                                     | 08:30:11 export (allowed)         |
+-------------------+---------------------------------------------------------+-----------------------------------+
```

#### Tablet (720px - 1079px)
Two-column layout:
- Left: Case Queue (240px).
- Right: Main Case Record; Integrity Panel and Personal Access History flow underneath the disclosure record.

#### Mobile (< 720px)
Single-column view transition:
- Default view: Assigned Cases list.
- Tapping a case switches to the full-width Case Record view with a prominent `[<- Back to Cases]` button in the top navigation bar.
- Export review opens in a sliding bottom sheet with full touch/keyboard focus trap.

---

## 4. Workstation Components & Behavior

### 4.1 Case Queue
- Renders all cases assigned to the authenticated auditor for the active application.
- Displays case ID, short title, status pill (`Active`, `Disclosed`, `Expired`, `Revoked`), and grant expiration.
- Keyboard accessible: Arrow up/down to navigate, Enter/Space to select, Tab into details.

### 4.2 Case & Disclosure Record
- **Header**:
  - Case Title & Identifier (`fuji-withdrawal-8218e5a4`)
  - Application ID (`0x0000000000000000000000000000000000000000000000000000000000000a11`)
  - Target Transaction Hash with 1-click clipboard copy and Snowtrace link (`https://testnet.snowtrace.io/tx/...`)
  - Tags for granted fields: `tx_hash`, `amount`, `asset`, `timestamp`, `policy_version`. Forbidden fields (`user`, `counterparty`) are explicitly omitted.
- **Primary Action: "Verify & Disclose"**:
  - Triggers revalidation of chain finality and authorization, followed by in-memory decryption.
  - States:
    - `Idle`: Ready to verify.
    - `Verifying`: Spinner with polite announcement "Verifying chain evidence and confirmations...".
    - `Disclosed`: Displays tabular disclosed values.
    - `Insufficient Confirmations`: Displays warning "Transaction has only N confirmations (< 12 required). Disclose locked until finality is reached."
    - `Integrity Failure`: Shows error banner "Integrity verification failed: envelope hash or commitment mismatch."
    - `Expired / Revoked`: "Case grant has expired or was revoked."
- **Disclosed Record Table**:
  - Formatted strictly according to institutional compliance standards:
    - `tx_hash`: Full hash with copy button and external link.
    - `amount`: Formatted from 6-decimal base units (`1000000` -> `1.000000 USDC`).
    - `asset`: Circle USDC Fuji address (`0x5425890298aed601595a70AB815c96711a31Bc65`).
    - `timestamp`: Formatted in local browser time with exact UTC ISO string available on toggle/hover.
    - `policy_version`: Numeric version string.

### 4.3 Integrity & Finality Panel
Presents 6 distinct integrity verification checks:
1. **12+ Confirmations**: Current block minus receipt block >= 12.
2. **Canonical Receipt**: Status `0x1` and valid block hash.
3. **Event Verification**: `PrivateTransaction` emitted on configured `HazePool`.
4. **Action Binding**: Action equals `WITHDRAW` (3) and application ID matches.
5. **Envelope Hash**: `keccak256(envelope)` equals stored `auditCiphertextHash`.
6. **Audit Commitment**: Recomputed Poseidon commitment from decrypted facts matches on-chain `auditDataCommitment`.

Each check displays:
- Icon: `[x]` checkmark (green) or `[!]` alert (red/amber).
- Label and technical evidence detail (e.g. `58 confirmations`, `Block #57897923`).

### 4.4 Export Review Modal / Bottom Sheet
- The "Export" button is disabled until disclosure succeeds.
- Clicking "Export" opens a modal (desktop/tablet) or bottom sheet (mobile) containing:
  - Export Metadata: Case ID, Subject (Auditor address), Signing Key ID, Expiry Timestamp (10 minutes).
  - Scope: Exact list of granted fields.
  - Verification Hash: SHA-256 / Keccak-256 of the canonical export payload.
  - Detached Signature: Hex encoded signature.
  - Primary Action: `[ Download Signed JSON ]`.
- Closing the modal restores focus to the Export trigger button.

### 4.5 Personal Access History
- Displays the auditor's recent access logs.
- Refreshes automatically whenever a disclosure query or export is performed.
- Columns: Timestamp (HH:MM:SS), Operation (`query`, `export`, `auth`), Result (`ALLOWED` / `DENIED`).
- Disclosed plaintext values are never included in the access log.

---

## 5. Accessibility Acceptance Criteria

1. **Keyboard Navigation**:
   - All interactive controls reachable via standard Tab sequence.
   - Arrow navigation within case queue.
   - Escape closes modals and bottom sheets.
   - Focus trapped within active dialogs; returned to trigger on close.
2. **Screen Reader Announcements**:
   - `aria-live="polite"` region for status updates (verifying, disclosed, exported, errors).
   - Semantic landmarks: `<header role="banner">`, `<nav aria-label="Assigned cases">`, `<main id="content">`, `<aside aria-label="Integrity and activity">`.
3. **Contrast & Motion**:
   - Minimum 4.5:1 text contrast across all surfaces.
   - Respects `prefers-reduced-motion: reduce` (disables transitions and spinners).
4. **Mobile Usability**:
   - All interactive targets meet minimum 44px x 44px hit area.
   - No horizontal scrolling at 390px viewport width.
