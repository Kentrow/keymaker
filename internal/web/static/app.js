// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

// Preferences live in the browser, never on the server: they say nothing about the account
// and the tool writes nothing to disk. A browser that refuses storage still works, it just
// forgets the choice.
const preferences = {
  read (key, fallback) {
    try {
      return localStorage.getItem(key) || fallback
    } catch (refused) {
      return fallback
    }
  },
  write (key, value) {
    try {
      localStorage.setItem(key, value)
    } catch (refused) {
      // Nothing to do: the choice applies to this page and is forgotten on the next one.
    }
  }
}

const languages = [
  { code: 'en', name: 'English', short: 'EN', flag: 'flag flag-gb' },
  { code: 'fr', name: 'Français', short: 'FR', flag: 'flag flag-fr' }
]

// Applied here rather than from Alpine, so the page is painted in the chosen theme instead
// of switching to it once the component wakes up.
const storedTheme = preferences.read('keymaker.theme', 'system')
if (storedTheme === 'light' || storedTheme === 'dark') {
  document.documentElement.dataset.theme = storedTheme
}

// One cell of the CSV report. A value a spreadsheet would read as a formula gets a leading
// quote, since application names and descriptions come from the account and end up opened in
// one; a value holding a separator, a quote or a line break is quoted.
function csvCell (value) {
  let text = value === null || value === undefined ? '' : String(value)
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
}

function preferredLanguage () {
  const stored = preferences.read('keymaker.language', '')
  if (languages.some(language => language.code === stored)) return stored
  return navigator.language && navigator.language.startsWith('fr') ? 'fr' : 'en'
}

const findingOrder = ['broad-access', 'account-control', 'billing-access', 'wider-than-needed', 'pending-validation', 'support-issued', 'same-as-another', 'no-ip-restriction', 'no-expiry', 'expires-soon', 'never-used', 'dormant', 'no-description']

const severityRank = { risk: 3, caution: 2, note: 1 }

// Four API statuses, three ways to read them: one is usable, one may still become usable,
// and the rest are over. The label keeps the API's own word; only the tone is grouped.
const statusTone = status => {
  if (status === 'validated') return 'active'
  if (status === 'pendingValidation') return 'pending'
  return 'inactive'
}

// How many routes each branch holds among those kept, which is what choosing that branch then
// lists. A route belongs to every branch its path starts with.
const countBranches = (branches, routes, kept) => {
  const known = new Set(branches)
  const counts = {}
  for (const route of routes) {
    if (!kept(route)) continue
    const segments = route.path.split('/')
    for (let end = 2; end <= segments.length; end++) {
      const prefix = segments.slice(0, end).join('/')
      if (known.has(prefix)) counts[prefix] = (counts[prefix] || 0) + 1
    }
  }
  return counts
}

// The counts of the branch grid, kept for one combination of catalogue and filters: the grid
// reads them on every redraw, and they only change when one of those does.
let branchTallies = { key: '', counts: {} }

const dictionaries = {
  en: {
    quickFilters: 'Quick filters',
    refresh: 'Refresh',
    refreshing: 'Refreshing',
    language: 'Language',
    theme: 'Appearance',
    themeSystem: 'Match the system',
    themeLight: 'Light',
    themeDark: 'Dark',
    view: 'View',
    viewGrid: 'Cards',
    viewList: 'List',
    revoke: 'Revoke',
    revokeTitle: 'Revoke this key?',
    revokeWarning: 'This cannot be undone. Anything still using this key stops working the moment it is revoked, and the key cannot be brought back: a replacement is a new key with a new value to deploy.',
    revokePrompt: reference => `Type ${reference} to confirm`,
    leaveAction: 'Revoke and leave',
    leaveTitle: 'Revoke the key this tool uses, and leave?',
    leaveWarning: 'Keymaker ends the key it authenticates with, and can do nothing afterwards: every screen stops working, and using it again takes a new management key. No other key is touched.',
    leaveWhatStays: 'A key holding the rule to delete keys is deleted, and only its application stays behind, which the next run lists among the applications without a key. Any other key is expired, and stays listed until the inactive keys are swept.',
    leftTitle: 'The key this tool used is revoked.',
    leftDeleted: reference => `Key ${reference} is deleted. Its application stays behind with no key: the next run with another management key lists it among the applications without a key.`,
    leftExpired: reference => `Key ${reference} is expired. It stays listed until the inactive keys are swept, from another management key or the OVHcloud console.`,
    leftStop: 'Nothing more can be done here. You can close this page and stop the process.',
    revokeMismatch: reference => `That is not ${reference}. Type the identifier of this key, with or without the #.`,
    revoking: 'Revoking...',
    cancel: 'Cancel',
    revoked: reference => `Key ${reference} revoked.`,
    addressesEdit: 'Addresses',
    addressesUnavailableRule: 'Changing the addresses of a key takes the rule PUT /me/api/credential/*, which the management key does not hold. The default management key leaves it out on purpose: the audit flags it as able to change access to the account, since it can widen the reach of any key.',
    addressesRuleLink: 'Issue a management key that holds it',
    addressesUnavailableLookup: 'This instance cannot look up the address it is seen from, so it does not restrict the key it runs with: a list leaving that address out would lock the tool out for good.',
    addressesTitle: 'Allowed addresses',
    addressesHint: 'One address or block per line, such as 203.0.113.4 or 192.0.2.0/24. Leave it empty for the key to accept any address.',
    addressesField: 'Addresses the key accepts',
    addressesAddMine: 'Add the address of this instance',
    addressesContinue: 'Continue',
    addressesChecking: 'Checking...',
    addressesStored: 'The key will accept these addresses, as OVHcloud stores them:',
    addressesAny: 'The key will accept any address, and the audit will flag it.',
    addressesSeenFrom: address => `This instance is seen from ${address}, which the list covers.`,
    addressesWarning: 'The change takes effect within seconds. Anything using this key from an address the list leaves out stops working.',
    addressesBack: 'Back',
    addressesSave: 'Save',
    addressesSaving: 'Saving...',
    addressesSaved: reference => `Addresses of key ${reference} changed.`,
    sweepHeadline: n => n === 1 ? '1 inactive key' : `${n} inactive keys`,
    sweepWhy: 'Expired or refused, they open nothing. Revoking them clears the inventory and cuts no access.',
    sweepUnavailable: 'Revoking them takes the rule to delete keys, which the management key does not hold.',
    sweepAction: 'Revoke them',
    sweepTitle: 'Revoke the inactive keys?',
    sweepWarning: 'This cannot be undone. These keys grant nothing today, so nothing stops working; what goes is the record of them.',
    sweepConfirm: n => n === 1 ? 'Revoke 1 key' : `Revoke ${n} keys`,
    sweeping: 'Revoking...',
    sweepDone: n => n === 1 ? '1 key revoked.' : `${n} keys revoked.`,
    sweepPartly: (done, refused) => `${done} revoked, ${refused} refused. The ones refused are still listed, each with its reason.`,
    sweepNone: 'No key was revoked.',
    keylessTitle: n => n === 1 ? '1 application without a key' : `${n} applications without a key`,
    keylessWhy: 'Revoking a key leaves its application behind. An application is a key and a secret a new credential can be requested under, and that request only needs your validation to become a working key. Delete the ones nothing uses.',
    keylessShow: 'Show them',
    keylessHide: 'Hide them',
    keylessHowTo: 'Deleting an application here removes its key and its secret for good. It is only offered for the ones holding no key: OVHcloud revokes every key of an application along with it.',
    keylessUnreadable: n => n === 1 ? '1 application could not be read.' : `${n} applications could not be read.`,
    keylessMissingRule: 'The management key cannot list applications: it holds no GET /me/api/application rule. Issue a key with that rule to see the applications left without one.',
    appDelete: 'Delete',
    appDeleteUnavailable: 'deletion unavailable',
    appDeleteUnavailableRule: 'The management key has no DELETE rule for this application.',
    appDeleteUnavailableInUse: 'This application still holds a key. Deleting it would revoke that key.',
    appDeleteTitle: 'Delete this application?',
    appDeleteWarning: 'This cannot be undone. The application key and secret disappear with it, so nothing can request a new key under this application again. No existing key is affected: this is only offered for applications holding none.',
    appDeleted: reference => `Application ${reference} deleted.`,
    appDeleting: 'Deleting...',
    appSweepAction: 'Delete them all',
    appSweepTitle: 'Delete every application without a key?',
    appSweepWarning: 'This cannot be undone. Each application key and secret disappears, so nothing can request a new key under them again. No existing key is touched: applications still holding one are left alone.',
    appSweepConfirm: n => n === 1 ? 'Delete 1 application' : `Delete ${n} applications`,
    appSweepDone: n => n === 1 ? '1 application deleted.' : `${n} applications deleted.`,
    appSweepPartly: (done, refused) => `${done} deleted, ${refused} refused. The ones refused are still listed, each with its reason.`,
    appSweepNone: 'No application was deleted.',
    replace: 'Replace',
    replaceTitle: reference => `Replacing key ${reference}`,
    replaceWarning: 'A key is not edited. What this does is issue a second one, with values of its own application key, secret and consumer key to deploy everywhere the first is used. The key being replaced keeps working until you revoke it, which is the last step below and yours to take once the new one is in place.',
    replaceRules: 'Its access rules are loaded below and in the explorer, where they can be changed before the key is issued.',
    replaceDrop: 'Issue this as a new key instead',
    replaceAddressesTitle: 'Allowed addresses of the replaced key',
    replaceAddressesHint: 'They do not travel with the link. Enter them again under "Restricted IPs" on the OVHcloud page, or the new key will work from any address.',
    replaceUnrestricted: 'The replaced key accepted any address. If the new one runs from a fixed host, restrict it under "Restricted IPs" on the OVHcloud page.',
    replaceRevoke: reference => `Revoke the replaced key ${reference}`,
    replaceRevokeHint: 'Do this once the new key is deployed. Nothing that uses the old one keeps working after it.',
    replaceRevokeLocked: 'Open the OVHcloud page and issue the new key first. This step unlocks once that page has been opened.',
    revokeUnavailableRule: 'The management key has no DELETE rule for this credential.',
    loading: 'Reading the inventory from the OVHcloud API.',
    errorHint: 'Nothing was changed on your account.',
    metricTotal: 'Keys',
    metricAtRisk: 'At risk',
    search: 'Search',
    searchPlaceholder: 'identifier, application, path, address',
    status: 'Status',
    application: 'Application',
    sort: 'Sort',
    anyStatus: 'Any',
    anyApplication: 'Any',
    sortAttention: 'Alerts first',
    sortLastUse: 'Last use',
    noMatch: 'No key matches these filters.',
    clearFilters: 'Clear the filters',
    reportLabel: 'Download the report',
    reportHint: 'The whole inventory, whatever the filters show, with its findings and the applications left without a key. It holds no key value.',
    columnAllowedIps: 'Allowed addresses',
    columnCreated: 'Created',
    columnExpires: 'Expires',
    columnLastUse: 'Last use',
    selfLabel: 'this tool',
    externalLabel: 'external application',
    externalHint: 'This application is not one of this account\'s own. Keys issued through the OVHcloud API console or a third-party tool look like this, and they are often old and broad.',
    unrestricted: 'any address',
    never: 'never',
    noExpiry: 'never',
    unnamedApplication: 'Unnamed application',
    deletedApplication: 'Deleted application',
    orphanedStatus: 'inoperative',
    orphanedNote: 'The application of this key was deleted. OVHcloud still lists the key with its old status, but refuses every call made with it. Revoking it clears the inventory and cuts no access.',
    noDescriptionText: 'No description.',
    rulesCount: n => n === 1 ? '1 access rule' : `${n} access rules`,
    showAll: 'show all',
    showFewer: 'show fewer',
    rulesUnfoldAll: 'Show every rule',
    rulesFoldAll: 'Fold the rules',
    shown: (shown, total) => shown === total ? `${total} shown` : `${shown} of ${total} shown`,
    statuses: {
      validated: 'active',
      pendingValidation: 'pending validation',
      expired: 'expired',
      refused: 'refused'
    },
    nothingToReport: 'Nothing to report. Every usable key is scoped, restricted and dated.',
    identityUnknown: 'Keymaker could not tell which key it runs with, so that key is not marked, and actions are offered on it that the tool will refuse when asked. Refresh to try again; the process log carries the detail.',
    unreadableKeys: n => n === 1 ? 'One key could not be read and is missing from this list. The process log carries the detail.' : `${n} keys could not be read and are missing from this list. The process log carries the detail.`,
    noKeys: 'This account has no API key.',
    findings: {
      'broad-access': {
        label: 'broad access',
        explanation: 'A key like this reaches the whole account, billing and contact details included. Issue one scoped to the routes it actually calls.',
        clause: n => n === 1 ? 'One key can reach the whole account.' : `${n} keys can reach the whole account.`
      },
      'no-ip-restriction': {
        label: 'any address',
        explanation: 'The key works from anywhere. If it runs from a fixed host, restrict it to that address.',
        clause: n => n === 1 ? 'One key accepts any source address.' : `${n} keys accept any source address.`
      },
      'no-expiry': {
        label: 'no expiry',
        explanation: 'The key never expires, so a leak stays useful forever. An end date bounds the damage.',
        clause: n => n === 1 ? 'One key never expires.' : `${n} keys never expire.`
      },
      'expires-soon': {
        label: 'expires soon',
        explanation: 'This key expires within a week. Whatever uses it stops working that day, without a warning of its own. If it is still needed, issue its replacement and deploy it before then.',
        clause: n => n === 1 ? 'One key expires within a week.' : `${n} keys expire within a week.`
      },
      'never-used': {
        label: 'never used',
        explanation: 'Issued more than a month ago and never used once. If nothing needs it, revoke it.',
        clause: n => n === 1 ? 'One key has never been used.' : `${n} keys have never been used.`
      },
      dormant: {
        label: 'dormant',
        explanation: 'Not used for more than six months. Check whether anything still depends on it.',
        clause: n => n === 1 ? 'One key has been idle for six months.' : `${n} keys have been idle for six months.`
      },
      'no-description': {
        label: 'no description',
        explanation: 'Nothing records what this key is for, which makes it hard to decide whether it can go.',
        clause: n => n === 1 ? 'One key has no description.' : `${n} keys have no description.`
      },
      'support-issued': {
        label: 'issued by support',
        explanation: 'OVHcloud support created this key, not you, usually while working on a ticket. Once the ticket is closed it has no reason to stay.',
        clause: n => n === 1 ? 'One key was created by OVHcloud support.' : `${n} keys were created by OVHcloud support.`
      },
      'account-control': {
        label: 'changes account access',
        explanation: 'A rule of this key can create, change or remove what gives access to the account: users, tokens, OAuth2 clients, the addresses other keys accept, two-factor authentication. Leaked, it can let someone in or lock you out, beyond its own rules.',
        clause: n => n === 1 ? 'One key can change access to the account.' : `${n} keys can change access to the account.`
      },
      'billing-access': {
        label: 'billing and payments',
        explanation: 'A rule of this key reaches invoices, orders, payment means or balances. Read, that is financial data; written, it can pay an order with a registered payment mean.',
        clause: n => n === 1 ? 'One key reaches billing or payments.' : `${n} keys reach billing or payments.`
      },
      'wider-than-needed': {
        label: 'wider than needed',
        explanation: 'This is the key Keymaker authenticates with, and it holds rules Keymaker never uses. Whoever got hold of it would get those too. The rules in question are listed on the card.',
        clause: () => 'The key this tool uses holds more than it needs.'
      },
      'same-as-another': {
        label: 'same as another',
        explanation: 'Another key of the same application carries the same rules and the same addresses, so nothing tells the two apart. One of them is usually a first attempt nobody revoked. Compare the last use dates and keep one.',
        clause: n => n === 1 ? 'One key is indistinguishable from another.' : `${n} keys are indistinguishable from another.`
      },
      'pending-validation': {
        label: 'never validated',
        explanation: 'Nobody ever validated this key on the OVHcloud page, so it opens nothing. It is one click away from working, with the rules listed here: validate it if it is still wanted, revoke it otherwise.',
        clause: n => n === 1 ? 'One key is still waiting to be validated.' : `${n} keys are still waiting to be validated.`
      }
    },
    renewKey: 'Issue a new management key',
    renewHint: 'Opens the OVHcloud page for your region with exactly the permissions this tool needs, already filled in. Validate it, then put the three values in your ovh.conf and restart. Drop the DELETE line on that page if you would rather run without revocation.',
    metricWatch: 'To watch',
    metricClean: 'Nothing flagged',
    bandRiskHint: 'Keys reaching the whole account. One of these leaking costs you everything you can do.',
    bandWatchHint: 'Keys with something worth knowing about, none of it reaching the whole account.',
    bandCleanHint: 'Usable keys this audit has no reservation about. It does not mean they are needed. Expired and refused keys are not audited and are not counted here.',
    bandAllHint: 'Every key on the account.',
    screenGroup: 'Screen',
    screenCreate: 'New key',
    createTitle: 'Create a key',
    createIntro: 'A key belongs to an application and carries the access rules you choose. Neither can be changed afterwards: the API has no endpoint to edit either, so a key that needs different rules is a new key.',
    stepRules: 'Access rules',
    handoffTitle: 'Create on OVHcloud',
    handoffBody: 'The page that issues a key is the one place an application and a key are created together, so this is where the key is issued. Your access rules travel with the link; the rest of the form is filled in there.',
    handoffFields: 'On that page you choose a name, a description and a validity, and you can restrict the key to an address under "Restricted IPs". OVHcloud then shows the three values once: the application key, the application secret and the consumer key. None of them pass through Keymaker.',
    handoffValidity: 'Validity offered there: Unlimited, 5 minutes, 1 hour, 1 day, 30 days. It cannot be chosen from here.',
    handoffAddress: 'This instance is seen from',
    handoffShowAddress: 'Show my public address',
    stepHandover: 'Retire the key it replaces',
    handoffOpen: 'Open the OVHcloud page',
    rulesNone: 'No rule chosen yet. Open the explorer and pick the routes this key needs.',
    rulesEdit: 'Change them in the explorer',
    keylessExplain: 'Why an application outlives its keys',
    replaceExplain: 'Why the rules of a key cannot be changed',
    screenGuide: 'Understand',
    guideTitle: 'What an OVHcloud API key is made of',
    guideIntro: 'What everyone calls a key is three things, created in one move and living apart afterwards: an application, a key issued under it, and the access rules that key carries. What this tool offers, refuses or flags follows from how the three fit together. The example below is invented.',
    guideFigureTitle: 'One application, two keys',
    guideFigureHint: 'Invented identifiers, in the shape the inventory shows when two keys were issued under one application.',
    guideKindApplication: 'Application',
    guideKindKey: 'Key',
    guideAppKey: 'Application key',
    guideAppSecret: 'The application secret goes with it, and OVHcloud displayed it once.',
    guideFrom: 'Allowed address',
    guideKeyRenewal: 'the machine that renews the certificate',
    guideKeyReader: 'a second machine, which only reads',
    guideApplicationTitle: 'The application is the program, not the permission',
    guideApplicationBody: 'An application is what a program presents as its identity: an application key that names it, and an application secret that proves it. It is created once, it outlives every key issued under it, and on its own it opens nothing at all. Two unrelated programs have no reason to share one.',
    guideApplicationNote: 'In the inventory, the application is the name above a key. Several keys can carry the same one.',
    guideKeyTitle: 'The key is the permission, and the only thing a revocation removes',
    guideKeyBody: 'A key, the consumer key, is an account holder saying yes to one application: for these rules, from these addresses, until this date. It proves nothing by itself, since the application key, the application secret and the consumer key sign every call together. Revoking it withdraws that yes and leaves the application where it was.',
    guideKeyNote: 'A key is pending validation until the account holder validates it on the OVHcloud page. Until then it opens nothing either.',
    guideRulesTitle: 'The rules are settled when the key is issued',
    guideRulesBody: 'A rule is a method and a path, such as GET /domain/zone/*, where * stands for any identifier. A key carries the rules chosen at its creation, and the API has no endpoint to change them afterwards. A key that needs other rules is another key, which is what Replace prepares: the old rules as a starting point, a new key, and the old one revoked last.',
    guideRulesNote: 'A rule such as GET /* reaches the whole account. That is what this audit calls a key at risk.',
    guideExternalTitle: 'Applications the account does not own',
    guideExternalBody: 'Some keys were issued under an application belonging to someone else, the OVHcloud API console and its mobile application among them. The account holder validated those keys like any other and can revoke them from here, but the application behind them cannot be read or deleted from this account. The inventory marks them as external.',
    guideStoryTitle: 'The life of one application',
    guideStoryOne: 'A script has to edit one DNS zone. The OVHcloud page creates the application and its first key in the same move, and displays the three values once.',
    guideStoryTwo: 'A second machine needs the same access. It asks OVHcloud for a key of its own under that application, the account holder validates it, and the application now holds two keys, each with its own rules and addresses.',
    guideStoryThree: 'The first machine is decommissioned, so its key is revoked. The application stays behind, key and secret intact, and a new key can still be requested under it. No inventory of keys can show that, which is why this tool lists the applications holding none.',
    guideStoryFour: 'The day the script is gone for good, the application is deleted too. OVHcloud revokes every key still under it in the same move, which is why deleting one that still holds a key is refused here.',
    screenInventory: 'Inventory',
    screenExplorer: 'Explorer',
    explorerTitle: 'Build a set of access rules',
    explorerIntro: 'Pick the routes a key needs. Access rules cannot be changed once a key exists, so what is chosen here is what that key can do for its whole life.',
    routeSearch: 'Search a route, or what it does',
    branch: 'Branch',
    branchAll: 'Every',
    method: 'Method',
    methodAll: 'Every',
    deprecatedShow: 'Include deprecated routes',
    deprecatedTag: 'deprecated',
    operationAdd: 'Add this access rule',
    operationDrop: 'Remove this access rule',
    wildcardHint: 'covers every identifier',
    catalogueLoading: 'Reading the API catalogue',
    catalogueLive: n => `${n} routes, read from the API at startup.`,
    catalogueSnapshot: (n, date) => `${n} routes, from the copy shipped with this build on ${date}. Anything added to the API since is missing here.`,
    routesShown: (shown, total) => {
      if (shown < total) return `${shown} of ${total} routes, the rest load as you reach them`
      return total === 1 ? '1 route' : `${total} routes`
    },
    routesEmpty: 'No route matches.',
    branchesShown: n => `${n} branches of the API. Start from one, or search all of them.`,
    branchRoutes: n => n === 1 ? '1 route' : `${n} routes`,
    branchesBack: 'All branches',
    selectionTitle: 'Selected rules',
    selectionEmpty: 'Nothing selected. Choose an operation on a route to add it.',
    selectionCount: n => n === 1 ? '1 rule' : `${n} rules`,
    ruleRemove: 'Remove',
    rulesClear: 'Clear',
    rulesCopy: 'Copy',
    rulesCopied: 'Copied.',
    rulesCopyFailed: 'The browser refused to write to the clipboard.',
    broadRule: 'reaches the whole account',
    unneededTitle: 'Rules this tool never uses',
    unneededRenew: 'Issue a key with only the rules this tool needs',
    controlWarning: 'One of these rules can change access to the account: users, tokens, OAuth2 clients, the addresses other keys accept, or two-factor authentication. Leaked, a key holding it can let someone in or lock you out.',
    billingWarning: 'One of these rules reaches billing or payments. Read, that is financial data; written, it can pay an order with a registered payment mean.',
    broadWarning: 'A rule that reaches the whole account gives the key everything you can do. Narrow it unless that is the intent.',
    unauthorized: 'Session not recognised. Reopen the address the process printed at startup.',
    unreachable: 'The interface could not reach its own backend.',
    problems: {
      'credential-unusable': 'The OVHcloud API refused the configured credential itself, not one of its permissions. It is expired, revoked, or paired with the wrong application secret. Issuing a new one and putting it in your ovh.conf is the fix.',
      'permission-denied': 'The OVHcloud API refused the call. The usual cause is an access rule the management key does not hold; the process log carries what the API actually said.',
      'api-failure': 'The OVHcloud API call failed. The process log carries the detail.',
      'self-revocation': 'This is the key the tool authenticates with. Revoking it would lock you out of this screen.',
      'identity-unknown': 'The tool could not establish which credential it authenticates with, so it stopped rather than revoking without that guard. The process log carries what the API said.',
      'no-rules': 'A key with no access rule can do nothing. Choose at least one route.',
      'malformed-rule': 'One of the access rules names a method or a path the API would refuse.',
      'lookup-disabled': 'This instance was started with the address lookup switched off.',
      'lookup-failed': 'The address could not be looked up. The process log carries the detail.',
      'bad-identifier': 'That credential identifier is not a number.',
      'already-revoked': 'This key no longer exists: it was already revoked.',
      'application-in-use': 'This application still holds a key. Deleting it would revoke that key, so it is refused. Revoke the key first if that is what you want.',
      'application-gone': 'This application no longer exists: it was already deleted.',
      'missing-token': 'This request did not carry the token handed to the page. Reload and try again.',
      'bad-address': entry => entry ? `${entry} is not an address or an address block.` : 'The list could not be read.',
      'any-address-block': entry => `${entry} lets every address in, so it restricts nothing. To accept any address, leave the list empty.`,
      'too-many-addresses': 'A key accepts at most 64 address blocks here.',
      'credential-inactive': 'Only a usable key can have its addresses changed. This one is expired, refused or awaiting validation.',
      'self-lookup-off': 'This instance cannot look up the address it is seen from, so it does not restrict the key it runs with.',
      'self-lockout': entry => `This list leaves out ${entry}, the address this instance is seen from. Saved, it would lock the tool out of the account for good: the key could not even undo it.`
    },
    disclaimer: 'Unofficial project. Not affiliated with OVHcloud, and neither operated, maintained nor supported by OVHcloud.',
    changelogLink: 'Changelog',
    repositoryLink: 'Source code',
    licenceLink: 'Apache-2.0',
    copyright: '2026 Kentrow'
  },

  fr: {
    quickFilters: 'Filtres rapides',
    refresh: 'Actualiser',
    refreshing: 'Actualisation',
    language: 'Langue',
    theme: 'Apparence',
    themeSystem: 'Suivre le système',
    themeLight: 'Clair',
    themeDark: 'Sombre',
    view: 'Affichage',
    viewGrid: 'Cartes',
    viewList: 'Liste',
    revoke: 'Révoquer',
    revokeTitle: 'Révoquer cette clé ?',
    revokeWarning: 'L’opération est irréversible. Tout ce qui utilise encore cette clé cesse de fonctionner dès la révocation, et la clé ne revient pas : la remplacer, c’est en créer une autre, avec une nouvelle valeur à redéployer.',
    revokePrompt: reference => `Saisissez ${reference} pour confirmer`,
    leaveAction: 'Révoquer et partir',
    leaveTitle: 'Révoquer la clé de cet outil et partir ?',
    leaveWarning: 'Keymaker met fin à la clé avec laquelle il s’authentifie, et ne peut plus rien faire ensuite : plus aucun écran ne fonctionne, et s’en servir à nouveau demande une nouvelle clé de gestion. Aucune autre clé n’est touchée.',
    leaveWhatStays: 'Une clé qui porte le droit de supprimer des clés est supprimée, et seule son application reste, que la prochaine utilisation liste parmi les applications sans clé. Toute autre clé est expirée, et reste listée jusqu’à la révocation des clés inactives.',
    leftTitle: 'La clé de cet outil est révoquée.',
    leftDeleted: reference => `La clé ${reference} est supprimée. Son application reste, sans clé : la prochaine utilisation avec une autre clé de gestion la liste parmi les applications sans clé.`,
    leftExpired: reference => `La clé ${reference} est expirée. Elle reste listée jusqu’à la révocation des clés inactives, depuis une autre clé de gestion ou la console OVHcloud.`,
    leftStop: 'Plus rien ne peut être fait ici. Vous pouvez fermer cette page et arrêter le processus.',
    revokeMismatch: reference => `Ce n’est pas ${reference}. Saisissez l’identifiant de cette clé, avec ou sans le #.`,
    revoking: 'Révocation...',
    cancel: 'Annuler',
    revoked: reference => `Clé ${reference} révoquée.`,
    addressesEdit: 'Adresses',
    addressesUnavailableRule: 'Modifier les adresses d’une clé demande le droit PUT /me/api/credential/*, que la clé de gestion ne porte pas. La clé de gestion par défaut l’omet exprès : l’audit le signale comme capable de modifier les accès au compte, puisqu’il peut élargir la portée de n’importe quelle clé.',
    addressesRuleLink: 'Émettre une clé de gestion qui le porte',
    addressesUnavailableLookup: 'Cette instance ne peut pas rechercher l’adresse depuis laquelle elle est vue, elle ne restreint donc pas la clé qu’elle utilise : une liste qui oublierait cette adresse enfermerait l’outil dehors pour de bon.',
    addressesTitle: 'Adresses autorisées',
    addressesHint: 'Une adresse ou un bloc par ligne, comme 203.0.113.4 ou 192.0.2.0/24. Laissez vide pour que la clé accepte toute adresse.',
    addressesField: 'Adresses acceptées par la clé',
    addressesAddMine: 'Ajouter l’adresse de cette instance',
    addressesContinue: 'Continuer',
    addressesChecking: 'Vérification...',
    addressesStored: 'La clé acceptera ces adresses, telles qu’OVHcloud les enregistre :',
    addressesAny: 'La clé acceptera n’importe quelle adresse, et l’audit le signalera.',
    addressesSeenFrom: address => `Cette instance est vue depuis ${address}, que la liste couvre.`,
    addressesWarning: 'Le changement prend effet en quelques secondes. Tout ce qui utilise cette clé depuis une adresse absente de la liste cesse de fonctionner.',
    addressesBack: 'Retour',
    addressesSave: 'Enregistrer',
    addressesSaving: 'Enregistrement...',
    addressesSaved: reference => `Adresses de la clé ${reference} modifiées.`,
    sweepHeadline: n => n === 1 ? '1 clé inactive' : `${n} clés inactives`,
    sweepWhy: 'Expirées ou refusées, elles n’ouvrent plus rien. Les révoquer nettoie l’inventaire et ne coupe aucun accès.',
    sweepUnavailable: 'Les révoquer demande le droit de supprimer des clés, que la clé de gestion ne porte pas.',
    sweepAction: 'Les révoquer',
    sweepTitle: 'Révoquer les clés inactives ?',
    sweepWarning: 'L’opération est irréversible. Ces clés n’accordent plus rien aujourd’hui : rien ne cesse de fonctionner, c’est leur trace qui disparaît.',
    sweepConfirm: n => n === 1 ? 'Révoquer 1 clé' : `Révoquer ${n} clés`,
    sweeping: 'Révocation...',
    sweepDone: n => n === 1 ? '1 clé révoquée.' : `${n} clés révoquées.`,
    sweepPartly: (done, refused) => `${done} révoquée${done > 1 ? 's' : ''}, ${refused} refusée${refused > 1 ? 's' : ''}. Celles refusées restent listées, chacune avec sa raison.`,
    sweepNone: 'Aucune clé n’a été révoquée.',
    keylessTitle: n => n <= 1 ? `${n} application sans clé` : `${n} applications sans clé`,
    keylessWhy: 'Révoquer une clé laisse son application derrière elle. Une application, c’est une clé et un secret sous lesquels une nouvelle clé peut être demandée, et cette demande n’attend que votre validation pour devenir une clé utilisable. Supprimez celles qui ne servent plus.',
    keylessShow: 'Les afficher',
    keylessHide: 'Les masquer',
    keylessHowTo: 'Supprimer une application ici efface définitivement sa clé et son secret. Ce n’est proposé que pour celles qui ne portent aucune clé : OVHcloud révoque toutes les clés d’une application en même temps qu’elle.',
    keylessUnreadable: n => n <= 1 ? `${n} application n’a pas pu être lue.` : `${n} applications n’ont pas pu être lues.`,
    keylessMissingRule: 'La clé de gestion ne peut pas lister les applications : elle n’a pas le droit GET /me/api/application. Émettez une clé avec ce droit pour voir les applications restées sans clé.',
    appDelete: 'Supprimer',
    appDeleteUnavailable: 'suppression indisponible',
    appDeleteUnavailableRule: 'La clé de gestion n’a pas le droit DELETE sur cette application.',
    appDeleteUnavailableInUse: 'Cette application porte encore une clé. La supprimer révoquerait cette clé.',
    appDeleteTitle: 'Supprimer cette application ?',
    appDeleteWarning: 'L’opération est irréversible. La clé d’application et son secret disparaissent avec elle : plus aucune clé ne pourra être demandée sous cette application. Aucune clé existante n’est touchée : la suppression n’est proposée que pour les applications qui n’en portent aucune.',
    appDeleted: reference => `Application ${reference} supprimée.`,
    appDeleting: 'Suppression...',
    appSweepAction: 'Toutes les supprimer',
    appSweepTitle: 'Supprimer toutes les applications sans clé ?',
    appSweepWarning: 'L’opération est irréversible. Chaque clé d’application et son secret disparaissent : plus aucune clé ne pourra être demandée sous elles. Aucune clé existante n’est touchée : les applications qui en portent une sont laissées de côté.',
    appSweepConfirm: n => n <= 1 ? `Supprimer ${n} application` : `Supprimer ${n} applications`,
    appSweepDone: n => n <= 1 ? `${n} application supprimée.` : `${n} applications supprimées.`,
    appSweepPartly: (done, refused) => `${done} supprimée${done > 1 ? 's' : ''}, ${refused} refusée${refused > 1 ? 's' : ''}. Celles refusées restent listées, chacune avec sa raison.`,
    appSweepNone: 'Aucune application n’a été supprimée.',
    replace: 'Remplacer',
    replaceTitle: reference => `Remplacement de la clé ${reference}`,
    replaceWarning: 'Une clé ne se modifie pas. Ce que vous faites ici, c’est en émettre une seconde, avec ses propres valeurs à déployer partout où la première est utilisée. La clé remplacée continue de fonctionner jusqu’à ce que vous la révoquiez, ce qui est la dernière étape ci-dessous et vous revient une fois la nouvelle en place.',
    replaceRules: 'Ses droits d’accès sont chargés ci-dessous et dans l’explorateur, où vous pouvez les modifier avant d’émettre la clé.',
    replaceDrop: 'En faire une nouvelle clé sans remplacement',
    replaceAddressesTitle: 'Adresses autorisées de la clé remplacée',
    replaceAddressesHint: 'Elles ne passent pas par le lien. Ressaisissez-les sous « Restricted IPs » sur la page OVHcloud, sinon la nouvelle clé fonctionnera depuis n’importe quelle adresse.',
    replaceUnrestricted: 'La clé remplacée acceptait n’importe quelle adresse. Si la nouvelle tourne sur une machine fixe, restreignez-la sous « Restricted IPs » sur la page OVHcloud.',
    replaceRevoke: reference => `Révoquer la clé remplacée ${reference}`,
    replaceRevokeHint: 'À faire une fois la nouvelle clé déployée. Plus rien de ce qui utilise l’ancienne ne fonctionnera ensuite.',
    replaceRevokeLocked: 'Ouvrez d’abord la page OVHcloud et émettez la nouvelle clé. Cette étape se déverrouille une fois cette page ouverte.',
    revokeUnavailableRule: 'La clé de gestion n’a pas le droit DELETE sur ce credential.',
    loading: 'Lecture de l’inventaire depuis l’API OVHcloud.',
    errorHint: 'Rien n’a été modifié sur le compte.',
    metricTotal: 'Clés',
    metricAtRisk: 'À risque',
    search: 'Recherche',
    searchPlaceholder: 'identifiant, application, chemin, adresse',
    status: 'Statut',
    application: 'Application',
    sort: 'Tri',
    anyStatus: 'Tous',
    anyApplication: 'Toutes',
    sortAttention: 'Alertes d’abord',
    sortLastUse: 'Dernier usage',
    noMatch: 'Aucune clé ne correspond à ces filtres.',
    clearFilters: 'Réinitialiser les filtres',
    reportLabel: 'Télécharger le rapport',
    reportHint: 'Tout l’inventaire, quels que soient les filtres, avec ses constats et les applications sans clé. Il ne contient aucune valeur de clé.',
    columnAllowedIps: 'Adresses autorisées',
    columnCreated: 'Création',
    columnExpires: 'Expiration',
    columnLastUse: 'Dernier usage',
    selfLabel: 'cet outil',
    externalLabel: 'application externe',
    externalHint: 'Cette application n’appartient pas à ce compte. Les clés émises depuis la console API OVHcloud ou un outil tiers apparaissent ainsi, et elles sont souvent anciennes et étendues.',
    unrestricted: 'toute adresse',
    never: 'jamais',
    noExpiry: 'jamais',
    unnamedApplication: 'Application sans nom',
    deletedApplication: 'Application supprimée',
    orphanedStatus: 'inopérante',
    orphanedNote: 'L’application de cette clé a été supprimée. OVHcloud liste encore la clé avec son ancien statut, mais refuse tout appel fait avec elle. La révoquer nettoie l’inventaire et ne coupe aucun accès.',
    noDescriptionText: 'Aucune description.',
    rulesCount: n => n <= 1 ? `${n} droit d’accès` : `${n} droits d’accès`,
    showAll: 'tout afficher',
    showFewer: 'réduire',
    rulesUnfoldAll: 'Afficher tous les droits',
    rulesFoldAll: 'Replier les droits',
    shown: (shown, total) => shown === total ? `${total} affichée${total > 1 ? 's' : ''}` : `${shown} sur ${total} affichée${total > 1 ? 's' : ''}`,
    statuses: {
      validated: 'active',
      pendingValidation: 'en attente de validation',
      expired: 'expirée',
      refused: 'refusée'
    },
    nothingToReport: 'Rien à signaler. Chaque clé utilisable est restreinte, datée et limitée à ce qu’elle appelle.',
    identityUnknown: 'Keymaker n’a pas pu établir quelle clé il utilise : elle n’est donc pas signalée, et des actions y sont proposées que l’outil refusera si on les demande. Actualisez pour réessayer ; le détail est dans le journal du processus.',
    unreadableKeys: n => n === 1 ? 'Une clé n’a pas pu être lue et manque dans cette liste. Le détail est dans le journal du processus.' : `${n} clés n’ont pas pu être lues et manquent dans cette liste. Le détail est dans le journal du processus.`,
    noKeys: 'Ce compte n’a aucune clé API.',
    findings: {
      'broad-access': {
        label: 'accès étendu',
        explanation: 'Une clé de ce genre atteint l’ensemble du compte, facturation et coordonnées comprises. Émettez-en une limitée aux routes qu’elle appelle réellement.',
        clause: n => n === 1 ? 'Une clé atteint l’ensemble du compte.' : `${n} clés atteignent l’ensemble du compte.`
      },
      'no-ip-restriction': {
        label: 'toute adresse',
        explanation: 'La clé fonctionne depuis n’importe où. Si elle tourne sur une machine fixe, restreignez-la à cette adresse.',
        clause: n => n === 1 ? 'Une clé accepte n’importe quelle adresse source.' : `${n} clés acceptent n’importe quelle adresse source.`
      },
      'no-expiry': {
        label: 'sans expiration',
        explanation: 'La clé n’expire jamais : une fuite reste exploitable indéfiniment. Une date de fin borne les dégâts.',
        clause: n => n === 1 ? 'Une clé n’expire jamais.' : `${n} clés n’expirent jamais.`
      },
      'expires-soon': {
        label: 'expire bientôt',
        explanation: 'Cette clé expire dans moins d’une semaine. Ce qui l’utilise cesse de fonctionner ce jour-là, sans prévenir. Si elle sert encore, émettez sa remplaçante et déployez-la avant.',
        clause: n => n === 1 ? 'Une clé expire dans moins d’une semaine.' : `${n} clés expirent dans moins d’une semaine.`
      },
      'never-used': {
        label: 'jamais utilisée',
        explanation: 'Émise il y a plus d’un mois et jamais utilisée. Si rien n’en dépend, révoquez-la.',
        clause: n => n === 1 ? 'Une clé n’a jamais servi.' : `${n} clés n’ont jamais servi.`
      },
      dormant: {
        label: 'dormante',
        explanation: 'Inutilisée depuis plus de six mois. Vérifiez que rien n’en dépend encore.',
        clause: n => n === 1 ? 'Une clé dort depuis six mois.' : `${n} clés dorment depuis six mois.`
      },
      'no-description': {
        label: 'sans description',
        explanation: 'Rien n’indique à quoi sert cette clé, ce qui rend difficile de décider si elle peut disparaître.',
        clause: n => n === 1 ? 'Une clé n’a pas de description.' : `${n} clés n’ont pas de description.`
      },
      'support-issued': {
        label: 'créée par le support',
        explanation: 'C’est le support OVHcloud qui a créé cette clé, pas vous, en général pendant le traitement d’un ticket. Une fois le ticket clos, elle n’a plus de raison de rester.',
        clause: n => n === 1 ? 'Une clé a été créée par le support OVHcloud.' : `${n} clés ont été créées par le support OVHcloud.`
      },
      'account-control': {
        label: 'touche aux accès du compte',
        explanation: 'Un droit de cette clé permet de créer, modifier ou supprimer ce qui donne accès au compte : utilisateurs, jetons, clients OAuth2, adresses acceptées par d’autres clés, double authentification. Si elle fuit, elle peut faire entrer quelqu’un ou vous mettre dehors, au-delà de ses propres droits.',
        clause: n => n === 1 ? 'Une clé peut modifier les accès au compte.' : `${n} clés peuvent modifier les accès au compte.`
      },
      'billing-access': {
        label: 'facturation et paiements',
        explanation: 'Un droit de cette clé atteint les factures, les commandes, les moyens de paiement ou les soldes. En lecture, ce sont des données financières ; en écriture, elle peut régler une commande avec un moyen de paiement enregistré.',
        clause: n => n === 1 ? 'Une clé atteint la facturation ou les paiements.' : `${n} clés atteignent la facturation ou les paiements.`
      },
      'wider-than-needed': {
        label: 'plus large que nécessaire',
        explanation: 'C’est la clé avec laquelle Keymaker s’authentifie, et elle porte des droits dont Keymaker ne se sert jamais. Qui la récupérerait aurait ceux-là aussi. Les droits en question sont listés sur la carte.',
        clause: () => 'La clé de cet outil porte plus que ce dont il a besoin.'
      },
      'same-as-another': {
        label: 'identique à une autre',
        explanation: 'Une autre clé de la même application porte les mêmes droits et les mêmes adresses : rien ne distingue les deux. L’une est en général un premier essai que personne n’a révoqué. Comparez les dates de dernier usage et n’en gardez qu’une.',
        clause: n => n === 1 ? 'Une clé est indiscernable d’une autre.' : `${n} clés sont indiscernables d’une autre.`
      },
      'pending-validation': {
        label: 'jamais validée',
        explanation: 'Personne n’a jamais validé cette clé sur la page OVHcloud, elle n’ouvre donc rien. Elle est à un clic de fonctionner, avec les droits listés ici : validez-la si elle sert encore, révoquez-la sinon.',
        clause: n => n === 1 ? 'Une clé attend toujours d’être validée.' : `${n} clés attendent toujours d’être validées.`
      }
    },
    renewKey: 'Émettre une nouvelle clé de gestion',
    renewHint: 'Ouvre la page OVHcloud de votre région avec exactement les droits dont cet outil a besoin, déjà remplis. Validez-la, puis placez les trois valeurs dans votre ovh.conf et redémarrez. Retirez la ligne DELETE sur cette page si vous préférez fonctionner sans révocation.',
    metricWatch: 'À surveiller',
    metricClean: 'Sans réserve',
    bandRiskHint: 'Clés qui atteignent l’ensemble du compte. Si l’une fuite, elle coûte tout ce que vous pouvez faire.',
    bandWatchHint: 'Clés qui méritent un coup d’œil, sans atteindre l’ensemble du compte.',
    bandCleanHint: 'Clés utilisables sur lesquelles cet audit n’a pas de réserve. Cela ne veut pas dire qu’elles sont utiles. Les clés expirées et refusées ne sont pas auditées et ne sont pas comptées ici.',
    bandAllHint: 'Toutes les clés du compte.',
    screenGroup: 'Écran',
    screenCreate: 'Nouvelle clé',
    createTitle: 'Créer une clé',
    createIntro: 'Une clé appartient à une application et porte les droits d’accès que vous choisissez. Ni l’un ni l’autre ne se modifient ensuite : l’API n’a aucun endpoint pour les changer, donc une clé qui a besoin d’autres droits est une nouvelle clé.',
    stepRules: 'Droits d’accès',
    handoffTitle: 'Créer sur OVHcloud',
    handoffBody: 'La page qui émet une clé est le seul endroit où une application et une clé sont créées ensemble : c’est donc là que la clé est émise. Vos droits d’accès partent avec le lien ; le reste du formulaire se remplit là-bas.',
    handoffFields: 'Sur cette page vous choisissez un nom, une description et une validité, et vous pouvez restreindre la clé à une adresse sous « Restricted IPs ». OVHcloud affiche ensuite les trois valeurs, une seule fois : la clé d’application, le secret d’application et la consumer key. Aucune ne passe par Keymaker.',
    handoffValidity: 'Validités proposées là-bas : Unlimited, 5 minutes, 1 hour, 1 day, 30 days. Elle ne se choisit pas depuis ici.',
    handoffAddress: 'Cette instance est vue depuis',
    handoffShowAddress: 'Afficher mon adresse publique',
    stepHandover: 'Retirer la clé remplacée',
    handoffOpen: 'Ouvrir la page OVHcloud',
    rulesNone: 'Aucun droit retenu. Ouvrez l’explorateur et choisissez les routes dont cette clé a besoin.',
    rulesEdit: 'Les modifier dans l’explorateur',
    keylessExplain: 'Pourquoi une application survit à ses clés',
    replaceExplain: 'Pourquoi les droits d’une clé ne se modifient pas',
    screenGuide: 'Comprendre',
    guideTitle: 'De quoi se compose une clé d’API OVHcloud',
    guideIntro: 'Ce que tout le monde appelle une clé, ce sont trois choses créées d’un seul geste puis vivant séparément : une application, une clé émise sous elle, et les droits d’accès que porte cette clé. Ce que cet outil propose, refuse ou signale découle de la façon dont ces trois-là s’emboîtent. L’exemple ci-dessous est inventé.',
    guideFigureTitle: 'Une application, deux clés',
    guideFigureHint: 'Identifiants inventés, dans la forme que montre l’inventaire quand deux clés ont été émises sous une même application.',
    guideKindApplication: 'Application',
    guideKindKey: 'Clé',
    guideAppKey: 'Clé d’application',
    guideAppSecret: 'Le secret d’application va avec, et OVHcloud ne l’a affiché qu’une fois.',
    guideFrom: 'Adresse autorisée',
    guideKeyRenewal: 'la machine qui renouvelle le certificat',
    guideKeyReader: 'une deuxième machine, qui ne fait que lire',
    guideApplicationTitle: 'L’application, c’est le programme, pas la permission',
    guideApplicationBody: 'Une application est ce qu’un programme présente comme identité : une clé d’application qui le nomme, et un secret d’application qui le prouve. Elle est créée une fois, elle survit à toutes les clés émises sous elle, et seule elle n’ouvre rien du tout. Deux programmes sans rapport n’ont aucune raison d’en partager une.',
    guideApplicationNote: 'Dans l’inventaire, l’application est le nom au-dessus d’une clé. Plusieurs clés peuvent porter la même.',
    guideKeyTitle: 'La clé, c’est la permission, et la seule chose qu’une révocation enlève',
    guideKeyBody: 'Une clé, la consumer key, c’est le titulaire du compte qui dit oui à une application : pour ces droits, depuis ces adresses, jusqu’à cette date. Elle ne prouve rien seule, puisque la clé d’application, le secret d’application et la consumer key signent ensemble chaque appel. La révoquer retire ce oui et laisse l’application où elle était.',
    guideKeyNote: 'Une clé reste en attente de validation tant que le titulaire du compte ne l’a pas validée sur la page OVHcloud. D’ici là, elle n’ouvre rien non plus.',
    guideRulesTitle: 'Les droits sont figés au moment où la clé est émise',
    guideRulesBody: 'Un droit d’accès, c’est une méthode et un chemin, par exemple GET /domain/zone/*, où * tient lieu de n’importe quel identifiant. Une clé porte les droits choisis à sa création, et l’API n’a aucune route pour les modifier ensuite. Une clé qui a besoin d’autres droits est une autre clé : c’est ce que prépare Remplacer, les anciens droits comme point de départ, une nouvelle clé, et l’ancienne révoquée en dernier.',
    guideRulesNote: 'Un droit comme GET /* atteint l’ensemble du compte. C’est ce que cet audit appelle une clé à risque.',
    guideExternalTitle: 'Les applications que le compte ne possède pas',
    guideExternalBody: 'Certaines clés ont été émises sous une application appartenant à quelqu’un d’autre, dont la console API d’OVHcloud et son application mobile. Le titulaire du compte les a validées comme les autres et peut les révoquer d’ici, mais l’application derrière elles ne peut être ni lue ni supprimée depuis ce compte. L’inventaire les signale comme externes.',
    guideStoryTitle: 'La vie d’une application',
    guideStoryOne: 'Un script doit modifier une zone DNS. La page OVHcloud crée l’application et sa première clé d’un seul geste, et affiche les trois valeurs une fois.',
    guideStoryTwo: 'Une deuxième machine a besoin du même accès. Elle demande à OVHcloud une clé à elle sous cette application, le titulaire du compte la valide, et l’application porte maintenant deux clés, chacune avec ses droits et ses adresses.',
    guideStoryThree: 'La première machine est mise hors service, sa clé est donc révoquée. L’application reste derrière, clé et secret intacts, et une nouvelle clé peut encore être demandée sous elle. Aucun inventaire de clés ne peut le montrer, et c’est pourquoi cet outil liste les applications qui n’en portent aucune.',
    guideStoryFour: 'Le jour où le script disparaît pour de bon, l’application est supprimée elle aussi. OVHcloud révoque du même geste toutes les clés encore sous elle, et c’est pourquoi supprimer une application qui en porte encore une est refusé ici.',
    screenInventory: 'Inventaire',
    screenExplorer: 'Explorateur',
    explorerTitle: 'Composer un jeu de droits d’accès',
    explorerIntro: 'Choisissez les routes dont une clé a besoin. Les droits d’accès ne se modifient pas une fois la clé créée : ce qui est retenu ici vaut pour toute sa durée de vie.',
    routeSearch: 'Chercher une route, ou ce qu’elle fait',
    branch: 'Branche',
    branchAll: 'Toutes',
    method: 'Méthode',
    methodAll: 'Toutes',
    deprecatedShow: 'Inclure les routes dépréciées',
    deprecatedTag: 'dépréciée',
    operationAdd: 'Ajouter ce droit d’accès',
    operationDrop: 'Retirer ce droit d’accès',
    wildcardHint: 'couvre tous les identifiants',
    catalogueLoading: 'Lecture du catalogue de l’API',
    catalogueLive: n => `${n} routes, lues sur l’API au démarrage.`,
    catalogueSnapshot: (n, date) => `${n} routes, issues de la copie livrée avec cette version le ${date}. Ce que l’API a ajouté depuis ne figure pas ici.`,
    routesShown: (shown, total) => {
      if (shown < total) return `${shown} routes sur ${total}, la suite se charge au fil du défilement`
      return total === 1 ? '1 route' : `${total} routes`
    },
    routesEmpty: 'Aucune route ne correspond.',
    branchesShown: n => `${n} branches de l’API. Partez de l’une d’elles, ou cherchez dans toutes.`,
    branchRoutes: n => n === 1 ? '1 route' : `${n} routes`,
    branchesBack: 'Toutes les branches',
    selectionTitle: 'Droits retenus',
    selectionEmpty: 'Rien de retenu. Choisissez une opération sur une route pour l’ajouter.',
    selectionCount: n => n <= 1 ? `${n} droit` : `${n} droits`,
    ruleRemove: 'Retirer',
    rulesClear: 'Vider',
    rulesCopy: 'Copier',
    rulesCopied: 'Copié.',
    rulesCopyFailed: 'Le navigateur a refusé l’écriture dans le presse-papiers.',
    broadRule: 'porte sur tout le compte',
    unneededTitle: 'Droits dont cet outil ne se sert jamais',
    unneededRenew: 'Émettre une clé avec uniquement les droits dont cet outil a besoin',
    controlWarning: 'L’un de ces droits peut modifier les accès au compte : utilisateurs, jetons, clients OAuth2, adresses acceptées par d’autres clés, ou double authentification. Si elle fuit, une clé qui le porte peut faire entrer quelqu’un ou vous mettre dehors.',
    billingWarning: 'L’un de ces droits atteint la facturation ou les paiements. En lecture, ce sont des données financières ; en écriture, il permet de régler une commande avec un moyen de paiement enregistré.',
    broadWarning: 'Un droit qui porte sur tout le compte donne à la clé tout ce que vous pouvez faire. Restreignez-le, sauf si c’est l’intention.',
    unauthorized: 'Session non reconnue. Rouvrez l’adresse affichée au démarrage du processus.',
    unreachable: 'L’interface n’a pas pu joindre son propre backend.',
    problems: {
      'credential-unusable': 'L’API OVHcloud a refusé la clé configurée elle-même, et non l’un de ses droits. Elle est expirée, révoquée, ou associée au mauvais secret d’application. La solution est d’en émettre une nouvelle et de la placer dans votre ovh.conf.',
      'permission-denied': 'L’API OVHcloud a refusé l’appel. La cause habituelle est un droit d’accès que la clé de gestion ne possède pas ; le journal du processus contient ce que l’API a réellement répondu.',
      'api-failure': 'L’appel à l’API OVHcloud a échoué. Le détail est dans le journal du processus.',
      'self-revocation': 'C’est la clé avec laquelle l’outil s’authentifie. La révoquer vous couperait l’accès à cet écran.',
      'identity-unknown': 'L’outil n’a pas pu établir avec quelle clé il s’authentifie ; il s’est arrêté plutôt que de révoquer sans ce garde-fou. Le journal du processus contient la réponse de l’API.',
      'no-rules': 'Une clé sans aucun droit d’accès ne peut rien faire. Choisissez au moins une route.',
      'malformed-rule': 'L’un des droits d’accès nomme une méthode ou un chemin que l’API refuserait.',
      'lookup-disabled': 'Cette instance a été démarrée avec la résolution d’adresse désactivée.',
      'lookup-failed': 'L’adresse n’a pas pu être obtenue. Le détail est dans le journal du processus.',
      'bad-identifier': 'Cet identifiant de credential n’est pas un nombre.',
      'already-revoked': 'Cette clé n’existe plus : elle a déjà été révoquée.',
      'application-in-use': 'Cette application porte encore une clé. La supprimer révoquerait cette clé : l’opération est donc refusée. Révoquez d’abord la clé si c’est bien ce que vous voulez.',
      'application-gone': 'Cette application n’existe plus : elle a déjà été supprimée.',
      'missing-token': 'Cette requête ne portait pas le jeton remis à la page. Rechargez, puis réessayez.',
      'bad-address': entry => entry ? `${entry} n’est ni une adresse ni un bloc d’adresses.` : 'La liste n’a pas pu être lue.',
      'any-address-block': entry => `${entry} laisse entrer toutes les adresses, il ne restreint donc rien. Pour accepter toute adresse, laissez la liste vide.`,
      'too-many-addresses': 'Une clé accepte ici au plus 64 blocs d’adresses.',
      'credential-inactive': 'Seule une clé utilisable peut voir ses adresses modifiées. Celle-ci est expirée, refusée ou en attente de validation.',
      'self-lookup-off': 'Cette instance ne peut pas rechercher l’adresse depuis laquelle elle est vue, elle ne restreint donc pas la clé qu’elle utilise.',
      'self-lockout': entry => `Cette liste oublie ${entry}, l’adresse depuis laquelle cette instance est vue. Enregistrée, elle enfermerait l’outil hors du compte pour de bon : la clé ne pourrait même pas revenir en arrière.`
    },
    disclaimer: 'Projet non officiel. Sans affiliation avec OVHcloud, et ni exploité, ni maintenu, ni supporté par OVHcloud.',
    changelogLink: 'Journal des modifications',
    repositoryLink: 'Code source',
    licenceLink: 'Apache-2.0',
    copyright: '2026 Kentrow'
  }
}

const collapsedRules = 3

// How many routes are added to the page at a time. The catalogue arrives whole and stays in
// memory; what costs is putting four thousand rows in the DOM, so the list grows as the
// reader reaches the end of it rather than all at once.
const routeBatch = 80

// The same for the keys of the inventory. A card weighs far more than a route row: with five
// hundred keys, drawing them all took most of a second at every change of filter.
const keyBatch = 40

// How far below the fold the end of the list is treated as reached, so the next rows are
// there before the reader arrives at the gap.
const lookahead = 600

// The pending session request, which every mutation waits on before reading the page token.
// It is kept outside the component: Alpine wraps component data in a proxy, and a promise read
// back through one can no longer be awaited.
let sessionRequest = Promise.resolve()

document.addEventListener('alpine:init', () => {
  Alpine.data('inventory', () => ({
    lang: preferredLanguage(),
    theme: storedTheme,
    view: preferences.read('keymaker.view', 'list'),
    languagesOpen: false,
    loading: true,
    refreshing: false,
    error: '',
    endpoint: '',
    version: '',
    current: null,
    credentials: [],
    summary: { total: 0, examined: 0, unreadable: 0, flagged: 0, atRisk: 0, counts: {} },
    search: '',
    status: '',
    application: '',
    finding: '',
    band: '',
    sort: 'attention',
    csrf: '',
    addressLookup: false,
    managementKeyUrl: '',
    addressKeyUrl: '',
    sensitive: [],
    notice: '',
    confirming: null,
    confirmText: '',
    confirmError: '',
    revoking: false,
    leaving: false,
    leaveText: '',
    leaveError: '',
    leaveBusy: false,
    retired: null,
    addressing: null,
    addressText: '',
    addressPlan: null,
    addressBusy: false,
    addressEditError: '',
    addressReasons: {},
    sweepAsked: false,
    replacing: null,
    sweeping: false,
    sweepError: '',
    applications: { listed: false, reason: '', applications: [], unreadable: 0 },
    keylessOpen: false,
    deletingApplication: null,
    applicationError: '',
    applicationBusy: false,
    appSweepAsked: false,
    appSweepError: '',
    appSweeping: false,
    expanded: {},
    allRules: false,
    reasons: {},
    explained: {},
    screen: 'inventory',
    catalogue: { live: false, taken: '', branches: [], routes: [] },
    catalogueLoading: false,
    catalogueError: '',
    routeSearch: '',
    routeBranch: '',
    routeMethod: '',
    routeDeprecated: false,
    routeBudget: routeBatch,
    keyBudget: keyBatch,
    selection: [],
    copyNotice: '',
    handoffUrl: '',
    publicAddress: '',
    addressError: '',
    addressCopied: false,
    copiedReplacedAddress: '',
    handoffOpened: false,
    handoffError: '',

    init () {
      document.documentElement.lang = this.lang
      this.requestSession()
      this.load()
      this.observeRoutes()
      this.observeKeys()
      for (const choice of ['search', 'status', 'application', 'finding', 'band', 'sort', 'view']) {
        this.$watch(choice, () => this.resetKeys())
      }
      for (const filter of ['routeSearch', 'routeBranch', 'routeMethod', 'routeDeprecated']) {
        this.$watch(filter, () => this.resetRoutes())
      }
      this.$watch('confirming', target => this.toggleDialog(this.$refs.revokeDialog, target !== null))
      this.$watch('leaving', open => this.toggleDialog(this.$refs.leaveDialog, open))
      this.$watch('addressing', target => this.toggleDialog(this.$refs.addressDialog, target !== null))
      this.$watch('sweepAsked', asked => this.toggleDialog(this.$refs.sweepDialog, asked))
      this.$watch('deletingApplication', target => this.toggleDialog(this.$refs.applicationDialog, target !== null))
      this.$watch('appSweepAsked', asked => this.toggleDialog(this.$refs.applicationSweepDialog, asked))
    },

    // The confirmations are native modal dialogs: the browser moves the focus into them, keeps
    // it there, makes the page behind them inert, and hands the focus back to the control that
    // opened them. The state still lives in the component; this only mirrors it, so that every
    // way of closing, a button, Escape or a click beside the dialog, goes through one path.
    toggleDialog (dialog, open) {
      if (!dialog) return
      if (open && !dialog.open) dialog.showModal()
      if (!open && dialog.open) dialog.close()
    },

    // The page and the inventory load side by side, so a mutation can be asked for before the
    // session has answered; it would then go out without the token and come back refused.
    requestSession () {
      sessionRequest = this.openSession()
      return sessionRequest
    },

    // The page token arrives apart from the inventory: creating a key needs no permission
    // on the management credential, so an account whose listing is refused must still be
    // able to send a mutation.
    async openSession () {
      try {
        const response = await fetch('/api/session', { credentials: 'same-origin' })
        if (!response.ok) return
        const payload = await response.json()
        // Read defensively: a field this version does not get back must leave the page
        // working rather than break every binding that reads it.
        this.csrf = payload.csrf || ''
        this.endpoint = payload.endpoint || ''
        this.version = payload.version || ''
        this.addressLookup = Boolean(payload.addressLookup)
        this.managementKeyUrl = payload.managementKeyUrl || ''
        this.addressKeyUrl = payload.addressKeyUrl || ''
        this.sensitive = Array.isArray(payload.sensitive) ? payload.sensitive : []
      } catch (failure) {
        // The inventory reports the same unreachable backend; saying it twice adds nothing.
      }
    },

    async load () {
      // The full-page loading state belongs to the first read, when there is nothing to
      // keep on screen. A refresh leaves the inventory where it is: emptying it collapses
      // the page, which moves everything the reader was looking at and takes the scrollbar
      // with it.
      this.loading = this.credentials.length === 0
      this.refreshing = true
      this.error = ''
      try {
        const response = await fetch('/api/inventory', { credentials: 'same-origin' })
        if (response.status === 401) {
          this.error = this.labels.unauthorized
          return
        }
        const payload = await response.json()
        if (!response.ok) {
          this.error = this.wordProblem(payload)
          return
        }
        this.endpoint = payload.endpoint
        this.current = payload.current
        this.credentials = payload.credentials
        this.summary = payload.summary
        this.loadApplications()
      } catch (failure) {
        this.error = this.labels.unreachable
      } finally {
        this.loading = false
        this.refreshing = false
      }
    },

    toggleLanguages () {
      this.languagesOpen = !this.languagesOpen
    },

    closeLanguages () {
      this.languagesOpen = false
    },

    pickLanguage () {
      this.lang = this.language.code
      this.languagesOpen = false
      document.documentElement.lang = this.lang
      preferences.write('keymaker.language', this.lang)
    },

    useSystemTheme () {
      this.applyTheme('system')
    },

    useLightTheme () {
      this.applyTheme('light')
    },

    useDarkTheme () {
      this.applyTheme('dark')
    },

    applyTheme (theme) {
      this.theme = theme
      if (theme === 'system') {
        delete document.documentElement.dataset.theme
      } else {
        document.documentElement.dataset.theme = theme
      }
      preferences.write('keymaker.theme', theme)
    },

    useListView () {
      this.applyView('list')
    },

    useGridView () {
      this.applyView('grid')
    },

    applyView (view) {
      this.view = view
      preferences.write('keymaker.view', view)
    },

    // A key's own control wins over the one for the whole list, both ways.
    rulesOpen (id) {
      return id in this.expanded ? this.expanded[id] : this.allRules
    },

    toggleRules () {
      this.expanded[this.row.id] = !this.rulesOpen(this.row.id)
    },

    // An audit pass reads every rule of every key, which used to take a click per key. Folded
    // stays the default, and is not remembered: most visits want the list short.
    toggleAllRules () {
      this.allRules = !this.allRules
      this.expanded = {}
    },

    get rulesFoldable () {
      const folded = this.view === 'list' ? 0 : collapsedRules
      return this.matched.some(item => item.rules.length > folded)
    },

    get allRulesLabel () {
      return this.allRules ? this.labels.rulesFoldAll : this.labels.rulesUnfoldAll
    },

    get allRulesExpanded () {
      return this.allRules ? 'true' : 'false'
    },

    // Why revocation is not offered, and what a finding means, used to live in a title
    // attribute: a pointer hovering long enough could read it, a keyboard, a touch screen or a
    // screen reader could not. Both are now a control that unfolds the sentence under the card.
    toggleReason () {
      this.reasons[this.row.id] = !this.reasons[this.row.id]
    },

    explainFinding () {
      const code = this.flag.code
      this.explained[this.row.id] = this.explained[this.row.id] === code ? '' : code
    },

    askRevoke () {
      this.confirming = this.row.id
      this.confirmText = ''
      this.confirmError = ''
      this.notice = ''
    },

    cancelRevoke () {
      this.confirming = null
      this.confirmText = ''
      this.confirmError = ''
    },

    async confirmRevoke () {
      if (this.confirmBlocked) return

      const target = this.confirming
      this.revoking = true
      this.confirmError = ''
      await sessionRequest
      try {
        const response = await fetch(`/api/credentials/${target}`, {
          method: 'DELETE',
          credentials: 'same-origin',
          headers: { 'X-Keymaker-Csrf': this.csrf }
        })
        const payload = response.ok ? {} : await response.json().catch(() => ({}))
        // Revoked elsewhere since the inventory was read: the key is gone, which is what was
        // asked for, so the dialog closes on the reason rather than staying open on an error.
        const gone = payload.code === 'already-revoked'
        if (!response.ok && !gone) {
          this.confirmError = this.wordProblem(payload)
          return
        }
        this.confirming = null
        this.confirmText = ''
        this.notice = gone ? this.wordProblem(payload) : this.labels.revoked('#' + target)
        if (this.replacing && this.replacing.id === target) this.dropReplacement()
        await this.load()
        this.settleFocus()
      } catch (failure) {
        this.confirmError = this.labels.unreachable
      } finally {
        this.revoking = false
      }
    },

    askLeave () {
      this.leaving = true
      this.leaveText = ''
      this.leaveError = ''
      this.notice = ''
    },

    cancelLeave () {
      this.leaving = false
      this.leaveText = ''
      this.leaveError = ''
    },

    // The request names no key: the server ends the one it authenticates with. Once it has
    // answered, nothing asked of it afterwards can succeed, so the page stops asking and says
    // what is left of the key instead.
    async confirmLeave () {
      if (this.leaveBlocked) return

      this.leaveBusy = true
      this.leaveError = ''
      await sessionRequest
      try {
        const response = await fetch('/api/credentials/current/retirement', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'X-Keymaker-Csrf': this.csrf }
        })
        const payload = await response.json().catch(() => ({}))
        if (!response.ok) {
          this.leaveError = this.wordProblem(payload)
          return
        }
        this.leaving = false
        this.retired = { id: payload.id, deleted: Boolean(payload.deleted) }
        window.scrollTo(0, 0)
      } catch (failure) {
        this.leaveError = this.labels.unreachable
      } finally {
        this.leaveBusy = false
      }
    },

    get leaveReference () {
      return this.current === null ? '' : '#' + this.current
    },

    get leavePrompt () {
      return this.labels.revokePrompt(this.leaveReference)
    },

    // Typed out like any revocation, and against the same identifier the card shows.
    get leaveBlocked () {
      const typed = this.leaveText.trim().replace(/^#/, '')
      return this.current === null || typed !== String(this.current) || this.leaveBusy
    },

    get leaveFailed () {
      return this.leaveError !== ''
    },

    get leaveLabel () {
      return this.leaveBusy ? this.labels.revoking : this.labels.leaveAction
    },

    get retiredShown () {
      return this.retired !== null
    },

    get retiredText () {
      if (this.retired === null) return ''
      const reference = '#' + this.retired.id
      return this.retired.deleted ? this.labels.leftDeleted(reference) : this.labels.leftExpired(reference)
    },

    toggleAddressReason () {
      this.addressReasons[this.row.id] = !this.addressReasons[this.row.id]
    },

    askAddresses () {
      this.addressing = { id: this.row.id, title: this.row.title, reference: this.row.reference }
      this.addressText = this.row.addressList
      this.addressPlan = null
      this.addressEditError = ''
      this.notice = ''
    },

    cancelAddresses () {
      this.addressing = null
      this.addressText = ''
      this.addressPlan = null
      this.addressEditError = ''
    },

    // The button that moves between the two steps disappears with its step, so the focus is
    // placed on what the next step is about rather than left to fall out of the dialog.
    editAddressesAgain () {
      this.addressPlan = null
      this.addressEditError = ''
      this.whenShown(() => this.$refs.addressField, field => field.focus())
    },

    // The address is the one the process is seen from, which is the one that matters when the
    // key being edited runs on the same host as this tool.
    async addMyAddress () {
      this.addressEditError = ''
      try {
        const response = await fetch('/api/address', { credentials: 'same-origin' })
        const payload = await response.json()
        if (!response.ok) {
          this.addressEditError = this.wordProblem(payload)
          return
        }
        const lines = this.addressText.split('\n').map(line => line.trim()).filter(line => line !== '')
        if (!lines.includes(payload.address)) lines.push(payload.address)
        this.addressText = lines.join('\n')
      } catch (failure) {
        this.addressEditError = this.labels.unreachable
      }
    },

    // The server puts the list in the form OVHcloud stores it in and runs every check, the one
    // that keeps the tool from locking itself out included, before anything is written. The
    // reader confirms that result, and saving runs the same checks again.
    async previewAddresses () {
      const plan = await this.sendAddresses('POST', `/api/credentials/${this.addressing.id}/addresses/preview`)
      if (!plan) return
      this.addressPlan = plan
      this.whenShown(() => this.$refs.addressSave, save => save.focus())
    },

    async saveAddresses () {
      const reference = this.addressing.reference
      const saved = await this.sendAddresses('PUT', `/api/credentials/${this.addressing.id}/addresses`)
      if (!saved) return
      this.cancelAddresses()
      this.notice = this.labels.addressesSaved(reference)
      await this.load()
    },

    async sendAddresses (method, target) {
      if (this.addressBusy) return null
      this.addressBusy = true
      this.addressEditError = ''
      await sessionRequest
      try {
        const response = await fetch(target, {
          method,
          credentials: 'same-origin',
          headers: { 'X-Keymaker-Csrf': this.csrf, 'Content-Type': 'application/json' },
          body: JSON.stringify({ addresses: this.addressText.split('\n') })
        })
        const payload = await response.json().catch(() => ({}))
        if (!response.ok) {
          // A refusal found at saving time is about a list the reader has to change, so the
          // dialog goes back to it.
          this.addressPlan = null
          this.addressEditError = this.wordProblem(payload)
          this.whenShown(() => this.$refs.addressField, field => field.focus())
          return null
        }
        return { addresses: payload.addresses || [], seenFrom: payload.seenFrom || '' }
      } catch (failure) {
        this.addressEditError = this.labels.unreachable
        return null
      } finally {
        this.addressBusy = false
      }
    },

    get addressingTitle () {
      return this.addressing === null ? '' : this.addressing.title
    },

    get addressingReference () {
      return this.addressing === null ? '' : this.addressing.reference
    },

    get addressEditing () {
      return this.addressPlan === null
    },

    get addressReviewing () {
      return this.addressPlan !== null
    },

    get addressPlanned () {
      return this.addressPlan === null ? [] : this.addressPlan.addresses.map(address => ({ key: address, address }))
    },

    get addressPlanAny () {
      return this.addressPlan !== null && this.addressPlan.addresses.length === 0
    },

    get addressPlanSome () {
      return this.addressPlan !== null && this.addressPlan.addresses.length > 0
    },

    get addressSeenFromText () {
      return this.addressPlan === null || this.addressPlan.seenFrom === '' ? '' : this.labels.addressesSeenFrom(this.addressPlan.seenFrom)
    },

    get addressFailed () {
      return this.addressEditError !== ''
    },

    get addressContinueLabel () {
      return this.addressBusy ? this.labels.addressesChecking : this.labels.addressesContinue
    },

    get addressSaveLabel () {
      return this.addressBusy ? this.labels.addressesSaving : this.labels.addressesSave
    },

    // The applications of the account, which the inventory cannot show: it lists keys, and
    // these have none. Loaded after the inventory rather than with it, since the screen is
    // worth showing before this answer arrives.
    async loadApplications () {
      try {
        const response = await fetch('/api/applications', { credentials: 'same-origin' })
        if (!response.ok) return
        const payload = await response.json()
        this.applications = {
          listed: Boolean(payload.listed),
          reason: payload.reason || '',
          applications: payload.applications || [],
          unreadable: payload.unreadable || 0
        }
      } catch (failure) {
        // The inventory reports an unreachable backend; saying it twice adds nothing.
      }
    },

    get keylessApplications () {
      return this.applications.applications
        .filter(item => item.credentials === 0)
        .map(item => ({
          key: item.id,
          id: item.id,
          reference: '#' + item.id,
          title: item.name || this.labels.unnamedApplication,
          description: item.description || '',
          deleteOffered: item.delete.allowed,
          deleteRefused: !item.delete.allowed,
          deleteReason: item.delete.reason === 'in-use' ? this.labels.appDeleteUnavailableInUse : this.labels.appDeleteUnavailableRule
        }))
    },

    get hasKeylessApplications () {
      return this.applications.listed && this.keylessApplications.length > 0
    },

    // Unfolded is not enough: deleting the last application empties the list while the
    // panel is open, and the banner that closes it goes away with that application. The
    // panel follows the list rather than the last click.
    get keylessDetailShown () {
      return this.keylessOpen && this.hasKeylessApplications
    },

    get keylessHeadline () {
      return this.labels.keylessTitle(this.keylessApplications.length)
    },

    get keylessToggleLabel () {
      return this.keylessOpen ? this.labels.keylessHide : this.labels.keylessShow
    },

    get keylessExpanded () {
      return this.keylessOpen ? 'true' : 'false'
    },

    get keylessUnreadableNotice () {
      const count = this.applications.unreadable || 0
      return count > 0 ? this.labels.keylessUnreadable(count) : ''
    },

    get applicationsRefused () {
      return this.applications.reason === 'missing-rule'
    },

    toggleKeyless () {
      this.keylessOpen = !this.keylessOpen
    },

    get deletableApplications () {
      return this.keylessApplications.filter(item => item.deleteOffered)
    },

    get canSweepApplications () {
      return this.deletableApplications.length > 0
    },

    get appSweepLabel () {
      return this.appSweeping ? this.labels.appDeleting : this.labels.appSweepConfirm(this.deletableApplications.length)
    },

    get appSweepFailed () {
      return this.appSweepError !== ''
    },

    askSweepApplications () {
      this.appSweepAsked = true
      this.appSweepError = ''
      this.notice = ''
    },

    cancelSweepApplications () {
      this.appSweepAsked = false
      this.appSweepError = ''
    },

    // The request carries no list: the server selects what holds no key from what the API
    // answers. What was confirmed here is a set, and the report says what became of it.
    async confirmSweepApplications () {
      if (this.appSweeping) return

      this.appSweeping = true
      this.appSweepError = ''
      await sessionRequest
      try {
        const response = await fetch('/api/applications/keyless/deletions', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'X-Keymaker-Csrf': this.csrf }
        })
        const payload = await response.json()
        if (!response.ok) {
          this.appSweepError = this.wordProblem(payload)
          return
        }
        this.appSweepAsked = false
        this.notice = this.appSweepOutcome(payload)
        await this.loadApplications()
        this.settleFocus()
      } catch (failure) {
        this.appSweepError = this.labels.unreachable
      } finally {
        this.appSweeping = false
      }
    },

    appSweepOutcome (payload) {
      const done = (payload.deleted || []).length
      const refused = (payload.failed || []).length
      if (refused > 0) return this.labels.appSweepPartly(done, refused)
      return done > 0 ? this.labels.appSweepDone(done) : this.labels.appSweepNone
    },

    askDeleteApplication () {
      this.deletingApplication = this.item
      this.applicationError = ''
      this.notice = ''
    },

    cancelDeleteApplication () {
      this.deletingApplication = null
      this.applicationError = ''
    },

    get deletingApplicationTitle () {
      return this.deletingApplication ? this.deletingApplication.title : ''
    },

    get deletingApplicationReference () {
      return this.deletingApplication ? this.deletingApplication.reference : ''
    },

    get applicationFailed () {
      return this.applicationError !== ''
    },

    get applicationDeleteLabel () {
      return this.applicationBusy ? this.labels.appDeleting : this.labels.appDelete
    },

    // Deleting an application is refused by the server for anything still holding a key, which
    // it counts against the API rather than against this list.
    async confirmDeleteApplication () {
      if (this.applicationBusy || !this.deletingApplication) return

      const target = this.deletingApplication
      this.applicationBusy = true
      this.applicationError = ''
      await sessionRequest
      try {
        const response = await fetch(`/api/applications/${target.id}`, {
          method: 'DELETE',
          credentials: 'same-origin',
          headers: { 'X-Keymaker-Csrf': this.csrf }
        })
        const payload = response.ok ? {} : await response.json().catch(() => ({}))
        const gone = payload.code === 'application-gone'
        if (!response.ok && !gone) {
          this.applicationError = this.wordProblem(payload)
          return
        }
        this.deletingApplication = null
        this.notice = gone ? this.wordProblem(payload) : this.labels.appDeleted(target.reference)
        await this.loadApplications()
        this.settleFocus()
      } catch (failure) {
        this.applicationError = this.labels.unreachable
      } finally {
        this.applicationBusy = false
      }
    },

    // Expired and refused keys, which is the whole set the sweep touches. Counted from the
    // inventory rather than from a filter, so the offer does not change with what the
    // reader is looking at.
    get inactiveKeys () {
      return this.credentials.filter(item => item.status === 'expired' || item.status === 'refused')
    },

    get hasInactive () {
      return this.inactiveKeys.length > 0
    },

    // The banner says how many keys are inactive whatever the rules, but offers to revoke them
    // only when the management key may: a button the server would refuse for every key is the
    // kind of control the cards stopped showing.
    get sweepOffered () {
      return this.inactiveKeys.some(item => item.revoke.allowed)
    },

    get sweepRefused () {
      return this.hasInactive && !this.sweepOffered
    },

    get inactiveHeadline () {
      return this.labels.sweepHeadline(this.inactiveKeys.length)
    },

    get sweepRows () {
      return this.inactiveKeys.map(item => ({
        key: item.id,
        reference: '#' + item.id,
        title: this.applicationName(item),
        status: this.labels.statuses[item.status] || item.status,
        statusClass: `pill status ${statusTone(item.status)}`
      }))
    },

    get sweepLabel () {
      return this.sweeping ? this.labels.sweeping : this.labels.sweepConfirm(this.inactiveKeys.length)
    },

    get sweepFailed () {
      return this.sweepError !== ''
    },

    askSweep () {
      this.sweepAsked = true
      this.sweepError = ''
      this.notice = ''
    },

    cancelSweep () {
      this.sweepAsked = false
      this.sweepError = ''
    },

    // The request carries no list: the server selects what is inactive from what the API
    // answers. What was confirmed here is a set, and the report says what became of it.
    async confirmSweep () {
      if (this.sweeping) return

      this.sweeping = true
      this.sweepError = ''
      await sessionRequest
      try {
        const response = await fetch('/api/credentials/inactive/revocations', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'X-Keymaker-Csrf': this.csrf }
        })
        const payload = await response.json()
        if (!response.ok) {
          this.sweepError = this.wordProblem(payload)
          return
        }
        this.sweepAsked = false
        this.notice = this.sweepOutcome(payload)
        await this.load()
        this.settleFocus()
      } catch (failure) {
        this.sweepError = this.labels.unreachable
      } finally {
        this.sweeping = false
      }
    },

    sweepOutcome (payload) {
      const done = (payload.revoked || []).length
      const refused = (payload.failed || []).length
      if (refused > 0) return this.labels.sweepPartly(done, refused)
      return done > 0 ? this.labels.sweepDone(done) : this.labels.sweepNone
    },

    // Clone-and-replace. The API has no way to change the rules of an
    // issued key, so the only honest shape for "edit" is a second key that takes over. The
    // old one is left alone here: it keeps working until its owner revokes it, which is
    // offered once the new value is in hand and not before.
    cloneCredential () {
      const item = this.credentials.find(entry => entry.id === this.row.id)
      if (!item) return

      this.selection = item.rules.map(rule => ({ method: rule.method, path: rule.path }))
      this.replacing = { id: item.id, reference: '#' + item.id, allowedIps: item.allowedIps.slice() }
      this.copiedReplacedAddress = ''
      this.handoffOpened = false
      this.refreshHandoff()
      this.copyNotice = ''
      this.switchScreen('create')
    },

    get replacingKey () {
      return this.replacing !== null
    },

    get addressUnknown () {
      return this.publicAddress === ''
    },

    // The OVHcloud page takes no address from the link, so the restriction of the key being
    // replaced is the one thing a replacement silently loses. It is put in front of the reader
    // on the step where it has to be typed again, one address at a time with its own copy.
    get replacedAddresses () {
      if (!this.replacing) return []
      return this.replacing.allowedIps.map(address => ({
        key: address,
        address,
        copyLabel: this.copiedReplacedAddress === address ? this.labels.rulesCopied : this.labels.rulesCopy
      }))
    },

    get replacedRestricted () {
      return this.replacedAddresses.length > 0
    },

    get replacedUnrestricted () {
      return this.replacing !== null && this.replacing.allowedIps.length === 0
    },

    async copyReplacedAddress () {
      const address = this.entry.address
      try {
        await navigator.clipboard.writeText(address)
        this.copiedReplacedAddress = address
        this.addressError = ''
      } catch (refused) {
        this.copiedReplacedAddress = ''
        this.addressError = this.labels.rulesCopyFailed
      }
    },

    get replacingTitle () {
      return this.replacing ? this.labels.replaceTitle(this.replacing.reference) : ''
    },

    // Revoking the replaced key before the new one exists leaves whatever used it with
    // nothing. The step waits until the page that issues the new key has at least been
    // opened; whether it was deployed is the reader's to know, and the hint says so.
    noteHandoffOpened () {
      this.handoffOpened = true
    },

    get replacedRevokeLocked () {
      return !this.handoffOpened
    },

    get replacingRevokeLabel () {
      return this.replacing ? this.labels.replaceRevoke(this.replacing.reference) : ''
    },

    // Dropping the link leaves the rules where they are: what the reader gives up is the
    // offer to revoke the old key, not the work of assembling the new one.
    dropReplacement () {
      this.replacing = null
    },

    askRevokeReplaced () {
      this.confirming = this.replacing.id
      this.confirmText = ''
      this.confirmError = ''
      this.notice = ''
      this.switchScreen('inventory')
    },

    // The report is built from what the page already holds and handed to the browser as a file:
    // nothing is written on the server, which persists nothing. It covers the whole inventory,
    // not the filtered view, since it records what the account held at a moment. The
    // application key, the one value of a key the inventory carries, stays out of it.
    reportData () {
      return {
        tool: 'keymaker',
        version: this.version,
        endpoint: this.endpoint,
        generatedAt: new Date().toISOString(),
        summary: {
          total: this.summary.total,
          examined: this.summary.examined,
          flagged: this.summary.flagged,
          atRisk: this.summary.atRisk,
          findings: this.summary.counts
        },
        credentials: this.credentials.map(item => ({
          id: item.id,
          status: item.status,
          inUse: Boolean(item.self),
          application: {
            id: item.application.id,
            name: item.application.name,
            description: item.application.description,
            external: Boolean(item.application.external),
            deleted: Boolean(item.application.deleted)
          },
          createdAt: item.createdAt,
          expiresAt: item.expiresAt,
          lastUsedAt: item.lastUsedAt,
          allowedIps: item.allowedIps,
          rules: item.rules.map(rule => ({ method: rule.method, path: rule.path })),
          findings: item.findings.map(finding => finding.code)
        })),
        applicationsWithoutKey: this.applications.listed
          ? this.applications.applications
            .filter(item => item.credentials === 0)
            .map(item => ({ id: item.id, name: item.name, description: item.description }))
          : null
      }
    },

    reportCsv () {
      const header = ['id', 'status', 'in_use', 'application_id', 'application', 'external', 'application_deleted', 'created', 'expires', 'last_used', 'allowed_ips', 'rules', 'findings']
      const rows = this.reportData().credentials.map(item => [
        item.id,
        item.status,
        item.inUse,
        item.application.id,
        item.application.name,
        item.application.external,
        item.application.deleted,
        item.createdAt || '',
        item.expiresAt || '',
        item.lastUsedAt || '',
        item.allowedIps.join(' '),
        item.rules.map(rule => `${rule.method} ${rule.path}`).join(' '),
        item.findings.join(' ')
      ])
      return [header, ...rows].map(row => row.map(csvCell).join(',')).join('\r\n') + '\r\n'
    },

    downloadReportJson () {
      this.saveReport('json', 'application/json', JSON.stringify(this.reportData(), null, 2) + '\n')
    },

    downloadReportCsv () {
      this.saveReport('csv', 'text/csv', this.reportCsv())
    },

    // Named after the endpoint and the day, so that reports taken over time sort themselves.
    saveReport (extension, type, content) {
      const day = new Date().toISOString().slice(0, 10)
      const url = URL.createObjectURL(new Blob([content], { type: `${type};charset=utf-8` }))
      const link = document.createElement('a')
      link.href = url
      link.download = `keymaker-${this.endpoint || 'report'}-${day}.${extension}`
      document.body.appendChild(link)
      link.click()
      link.remove()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    },

    clearFilters () {
      this.search = ''
      this.status = ''
      this.application = ''
      this.finding = ''
      this.band = ''
    },

    // Two shortcuts, and only on the inventory: / to search and Escape to clear the filters,
    // which is most of what anyone does on a screen they reopen every few weeks. A key typed
    // into a field stays that field's, and Escape belongs to an open dialog or menu first.
    shortcut (event) {
      if (this.screen !== 'inventory' || this.retired !== null || this.languagesOpen) return
      if (event.ctrlKey || event.metaKey || event.altKey || document.querySelector('dialog[open]')) return

      const field = event.target.closest && event.target.closest('input, textarea, select, [contenteditable]')
      if (event.key === '/' && !field) {
        event.preventDefault()
        this.$refs.search.focus()
        return
      }
      if (event.key === 'Escape' && this.filtering && (!field || field === this.$refs.search)) {
        this.clearFilters()
      }
    },

    get searchHinted () {
      return this.search === ''
    },

    // A screen change is a new page to the reader. It starts at the top, where the warning of a
    // replacement sits, rather than at the height the previous screen was scrolled to, and the
    // title of the new screen takes the focus so that a keyboard or a screen reader lands where
    // the new content begins. The inventory has no title and leaves the focus where it was.
    switchScreen (screen) {
      if (this.screen === screen) return
      this.screen = screen
      this.$nextTick(() => {
        window.scrollTo(0, 0)
        this.whenShown(() => document.querySelector(`[data-screen-title="${screen}"]`), title => title.focus({ preventScroll: true }))
      })
    },

    // Alpine's next tick can come before a screen shown by x-show is laid out, and a focus or
    // a scroll aimed at an element still hidden is dropped without a word: the focus falls
    // back to the page and the reader lands nowhere. This waits a few frames for the element
    // to be shown before acting on it, and gives up quietly on one that never is.
    whenShown (find, act, frames = 10) {
      const element = find()
      if (element && element.offsetParent !== null) {
        act(element)
        return
      }
      if (frames > 0) requestAnimationFrame(() => this.whenShown(find, act, frames - 1))
    },

    // An action that removes the control which opened it, a revoked key or a deleted application,
    // leaves the focus on nothing once its dialog has closed and the list been redrawn: a
    // keyboard starts over from the top of the page, and a screen reader says nothing. The
    // notice reporting the outcome takes the focus then, and is read out with it. Checked two
    // frames later, once the removed control is really gone; a focus that found a home of its
    // own is left there.
    settleFocus () {
      requestAnimationFrame(() => requestAnimationFrame(() => {
        const active = document.activeElement
        if (active && active !== document.body && active.isConnected) return
        this.whenShown(() => this.$refs.notice, notice => notice.focus())
      }))
    },

    showInventory () {
      this.switchScreen('inventory')
    },

    showGuide () {
      this.switchScreen('guide')
    },

    // A link from a screen that leans on this vocabulary lands on the paragraph that answers
    // the question, not at the top of the guide. The screen change scrolls to the top first;
    // this runs after it and takes the reader further down, focus included, so that a
    // keyboard or a screen reader lands where the eye does.
    showGuideAt (anchor) {
      this.switchScreen('guide')
      this.$nextTick(() => this.whenShown(() => document.getElementById(anchor), section => {
        section.scrollIntoView({ block: 'start' })
        const title = section.querySelector('h2')
        if (title) title.focus({ preventScroll: true })
      }))
    },

    explainKeyless () {
      this.showGuideAt('guide-story')
    },

    explainReplacement () {
      this.showGuideAt('guide-rules')
    },

    // The guide is the one screen with nothing behind it. Its example is invented and lives
    // here rather than in the markup, so that both languages tell the same story and the
    // identifiers stay recognisably made up.
    get guideApplication () {
      // The application key is shortened the way the interface shortens anything that looks
      // like a credential value: the example is about the shape of the thing, and a full one
      // written here would be a secret-shaped string in a public repository.
      return { name: 'dns-renewal', reference: '#5210987', key: '4f3c…45ec' }
    },

    get guideKeys () {
      return [
        {
          key: 'renewal',
          reference: '#118820304',
          note: this.labels.guideKeyRenewal,
          address: '203.0.113.4',
          rules: [
            { key: 'zone', method: 'GET', path: '/domain/zone/*', methodClass: 'method method-get' },
            { key: 'record', method: 'POST', path: '/domain/zone/*/record', methodClass: 'method method-post' }
          ]
        },
        {
          key: 'reader',
          reference: '#118820517',
          note: this.labels.guideKeyReader,
          address: '203.0.113.9',
          rules: [
            { key: 'zone', method: 'GET', path: '/domain/zone/*', methodClass: 'method method-get' }
          ]
        }
      ]
    },

    get guideCards () {
      return [
        {
          key: 'application',
          anchor: 'guide-application',
          title: this.labels.guideApplicationTitle,
          body: this.labels.guideApplicationBody,
          note: this.labels.guideApplicationNote
        },
        {
          key: 'credential',
          anchor: 'guide-key',
          title: this.labels.guideKeyTitle,
          body: this.labels.guideKeyBody,
          note: this.labels.guideKeyNote
        },
        {
          key: 'rules',
          anchor: 'guide-rules',
          title: this.labels.guideRulesTitle,
          body: this.labels.guideRulesBody,
          note: this.labels.guideRulesNote
        },
        {
          key: 'external',
          anchor: 'guide-external',
          title: this.labels.guideExternalTitle,
          body: this.labels.guideExternalBody,
          note: ''
        }
      ]
    },

    get guideStory () {
      return [
        { key: 'one', step: '1', body: this.labels.guideStoryOne },
        { key: 'two', step: '2', body: this.labels.guideStoryTwo },
        { key: 'three', step: '3', body: this.labels.guideStoryThree },
        { key: 'four', step: '4', body: this.labels.guideStoryFour }
      ]
    },

    // One reload for every screen. A button that appears and disappears moves the rest of
    // the header under the pointer, so it stays, and each screen reloads what it reads. The
    // guide reads nothing, and refreshes the inventory the reader will come back to.
    refresh () {
      if (this.retired !== null) return
      if (this.screen === 'explorer') {
        this.loadCatalogue()
        return
      }
      if (this.screen === 'create') {
        this.requestSession()
        return
      }
      this.load()
    },

    // The catalogue is fetched the first time the explorer is opened rather than with the
    // inventory: it is close to a megabyte and the first screen has no use for it.
    showExplorer () {
      this.switchScreen('explorer')
      if (!this.catalogue.routes.length && !this.catalogueLoading) this.loadCatalogue()
    },

    async loadCatalogue () {
      this.catalogueLoading = true
      this.catalogueError = ''
      try {
        const response = await fetch('/api/catalogue', { credentials: 'same-origin' })
        if (response.status === 401) {
          this.catalogueError = this.labels.unauthorized
          return
        }
        const payload = await response.json()
        if (!response.ok) {
          this.catalogueError = this.wordProblem(payload)
          return
        }
        // Read field by field, like the session: an answer missing one of them must leave
        // the screen empty rather than break every binding that walks it.
        this.catalogue = {
          live: Boolean(payload.live),
          taken: payload.taken || '',
          branches: payload.branches || [],
          routes: payload.routes || []
        }
      } catch (failure) {
        this.catalogueError = this.labels.unreachable
      } finally {
        this.catalogueLoading = false
      }
    },

    toggleOperation () {
      const method = this.operation.method
      const path = this.route.rule
      const at = this.selection.findIndex(rule => rule.method === method && rule.path === path)
      if (at >= 0) {
        this.selection.splice(at, 1)
        return
      }
      this.selection.push({ method, path })
      this.copyNotice = ''
    },

    dropRule () {
      const method = this.rule.method
      const path = this.rule.path
      this.selection = this.selection.filter(rule => !(rule.method === method && rule.path === path))
      this.copyNotice = ''
    },

    clearRules () {
      this.selection = []
      this.copyNotice = ''
    },

    async copyRules () {
      const text = this.selection.map(rule => `${rule.method} ${rule.path}`).join('\n')
      try {
        await navigator.clipboard.writeText(text)
        this.copyNotice = this.labels.rulesCopied
      } catch (refused) {
        this.copyNotice = this.labels.rulesCopyFailed
      }
    },

    get refreshLabel () {
      return this.refreshing || this.catalogueLoading ? this.labels.refreshing : this.labels.refresh
    },

    get refreshClass () {
      return this.refreshing || this.catalogueLoading ? 'primary working' : 'primary'
    },

    get screenButtons () {
      return {
        inventory: this.screen === 'inventory' ? 'segment chosen' : 'segment',
        explorer: this.screen === 'explorer' ? 'segment chosen' : 'segment',
        create: this.screen === 'create' ? 'segment chosen' : 'segment',
        guide: this.screen === 'guide' ? 'segment chosen' : 'segment'
      }
    },

    // Once the key in use is ended, no screen has anything left to show: each would only
    // fail against an API that no longer answers this process.
    get onInventory () {
      return this.screen === 'inventory' && this.retired === null
    },

    get onExplorer () {
      return this.screen === 'explorer' && this.retired === null
    },

    get onGuide () {
      return this.screen === 'guide' && this.retired === null
    },

    get catalogueReady () {
      return !this.catalogueError && this.catalogue.routes.length > 0
    },

    // Same rule as the inventory: the waiting line is for the first read only.
    get catalogueFirstLoad () {
      return this.catalogueLoading && this.catalogue.routes.length === 0
    },

    get catalogueOrigin () {
      const count = this.catalogue.routes.length
      if (this.catalogue.live) return this.labels.catalogueLive(count)
      return this.labels.catalogueSnapshot(count, this.day(this.catalogue.taken) || this.catalogue.taken)
    },

    // The branches come from the API index rather than from the shape of the paths: where
    // one branch ends and the next begins is not something a path reveals, "/dedicated/server"
    // and "/dedicated/cluster" being two of them while "/me/api" is part of one.
    get branchOptions () {
      return this.catalogue.branches
    },

    // The explorer opens on the branches rather than on four thousand routes in alphabetical
    // order, which begin with /allDom: people think of their account as /me, /domain or
    // /cloud. A search reaches every branch at once, so typing skips this step.
    get branchLanding () {
      return this.routeBranch === '' && this.routeSearch.trim() === ''
    },

    get routeListing () {
      return !this.branchLanding
    },

    get routesNone () {
      return this.routeListing && this.found.empty
    },

    get routesGrowing () {
      return this.routeListing && this.found.more
    },

    // A route is counted when the list a branch opens would show it: with an operation of the
    // chosen method, and not only deprecated ones unless those are asked for. The grid and the
    // list it leads to then agree.
    get branchCounts () {
      const key = [this.catalogue.taken, this.catalogue.routes.length, this.routeMethod, this.routeDeprecated].join('|')
      if (branchTallies.key !== key) {
        const kept = route => route.operations.some(operation =>
          (this.routeDeprecated || !operation.deprecated) && (!this.routeMethod || operation.method === this.routeMethod))
        branchTallies = { key, counts: countBranches(this.catalogue.branches, this.catalogue.routes, kept) }
      }
      return branchTallies.counts
    },

    // A branch no route the filters keep sits under leads nowhere, so it is left out.
    get branchEntries () {
      const counts = this.branchCounts
      return this.catalogue.branches.filter(branch => counts[branch]).map(branch => ({
        branch,
        count: this.labels.branchRoutes(counts[branch])
      }))
    },

    get branchesLabel () {
      return this.labels.branchesShown(this.branchEntries.length)
    },

    pickBranch () {
      this.routeBranch = this.entry.branch
    },

    clearBranch () {
      this.routeBranch = ''
    },

    get methodOptions () {
      const seen = new Set()
      for (const route of this.catalogue.routes) {
        for (const operation of route.operations) seen.add(operation.method)
      }
      return [...seen].sort()
    },

    // found carries the shown routes and the counts together, so the template reads both
    // without the filtering running twice.
    get found () {
      const needle = this.routeSearch.trim().toLowerCase()
      const routes = []
      let total = 0

      for (const route of this.catalogue.routes) {
        if (this.routeBranch && !this.inBranch(route.path, this.routeBranch)) continue

        const operations = route.operations.filter(operation => {
          if (!this.routeDeprecated && operation.deprecated) return false
          return !this.routeMethod || operation.method === this.routeMethod
        })
        if (!operations.length) continue
        if (needle && !this.routeMatches(route, operations, needle)) continue

        total += 1
        if (routes.length < this.routeBudget) routes.push(this.presentRoute(route, operations))
      }

      return {
        routes,
        empty: total === 0,
        more: routes.length < total,
        label: this.labels.routesShown(routes.length, total)
      }
    },

    // A filter narrows the list to something the reader means to read, so the page starts
    // from the top of it rather than keeping the height scrolled to before.
    resetRoutes () {
      this.routeBudget = routeBatch
    },

    growRoutes () {
      if (!this.found.more) return
      this.routeBudget += routeBatch

      // The observer reports a change of state, not a state. If the rows just added are not
      // enough to push the end of the list back out of view, nothing further would fire, so
      // the question is asked again once they are on the page.
      requestAnimationFrame(() => {
        const end = document.getElementById('route-end')
        if (!end) return
        if (end.getBoundingClientRect().top < window.innerHeight + lookahead) this.growRoutes()
      })
    },

    // A new filter, sort or view is a new list, read from its top. A refresh is not: the reader
    // keeps the keys already drawn and the place they were reading.
    resetKeys () {
      this.keyBudget = keyBatch
    },

    growKeys () {
      if (!this.keysGrowing) return
      this.keyBudget += keyBatch
      requestAnimationFrame(() => {
        const end = document.getElementById('key-end')
        if (!end) return
        if (end.getBoundingClientRect().top < window.innerHeight + lookahead) this.growKeys()
      })
    },

    observeKeys () {
      const end = document.getElementById('key-end')
      if (!end || !window.IntersectionObserver) return

      const observer = new IntersectionObserver(entries => {
        if (entries.some(entry => entry.isIntersecting)) this.growKeys()
      }, { rootMargin: `${lookahead}px` })
      observer.observe(end)
    },

    // Growing on reaching the end of the list rather than on a button: the reader is
    // scrolling, and a button would be one more thing to notice before carrying on.
    observeRoutes () {
      const end = document.getElementById('route-end')
      if (!end || !window.IntersectionObserver) return

      const observer = new IntersectionObserver(entries => {
        if (entries.some(entry => entry.isIntersecting)) this.growRoutes()
      }, { rootMargin: `${lookahead}px` })
      observer.observe(end)
    },

    inBranch (path, branch) {
      return path === branch || path.startsWith(`${branch}/`)
    },

    routeMatches (route, operations, needle) {
      if (route.path.toLowerCase().includes(needle)) return true
      return operations.some(operation => operation.description.toLowerCase().includes(needle))
    },

    presentRoute (route, operations) {
      const broad = this.broadRule(route.rule)
      return {
        key: route.path,
        rule: route.rule,
        wildcard: route.wildcard,
        broad,
        className: broad ? 'route broad' : 'route',
        operations: operations.map(operation => this.presentOperation(route, operation))
      }
    },

    presentOperation (route, operation) {
      const chosen = this.chosen(operation.method, route.rule)
      const sensitive = this.sensitiveFinding(operation.method, route.rule)
      const classes = ['method', `method-${operation.method.toLowerCase()}`]
      if (chosen) classes.push('chosen')
      if (operation.deprecated) classes.push('deprecated')
      return {
        method: operation.method,
        description: operation.description,
        deprecated: operation.deprecated,
        sensitive: sensitive ? this.labels.findings[sensitive].label : '',
        sensitiveClass: sensitive === 'account-control' ? 'tag risk' : 'tag',
        chosen,
        className: classes.join(' '),

        // The whole row is the control, verb and purpose alike: the verb alone was a small
        // target, and a reader who has just read what an operation does should be able to
        // press what they read.
        rowClass: chosen ? 'operation chosen' : 'operation',
        hint: chosen ? this.labels.operationDrop : this.labels.operationAdd
      }
    },

    chosen (method, path) {
      return this.selection.some(rule => rule.method === method && rule.path === path)
    },

    // The same reading the audit applies to an existing key: a wildcard
    // whose fixed part stops at the account root covers everything under it.
    broadRule (path) {
      const star = path.indexOf('*')
      if (star < 0) return false
      const fixed = path.slice(0, star).replace(/\/+$/, '')
      return fixed === '' || fixed === '/me'
    },

    // The reading the audit applies to an existing key, over the list the audit itself
    // serves with the session: a rule reaches a branch when it names a route in it, or when
    // its wildcard starts before the branch does. A broad rule is reported as such and not
    // branch by branch, as on a card.
    sensitiveFinding (method, path) {
      if (this.broadRule(path)) return ''
      const verb = method.toUpperCase()
      const star = path.indexOf('*')
      const fixed = star < 0 ? '' : path.slice(0, star)
      const found = this.sensitive.find(branch => {
        if (branch.methods.length > 0 && !branch.methods.includes(verb)) return false
        if (star < 0) return this.inBranch(path, branch.path)
        return this.inBranch(fixed.replace(/\/+$/, ''), branch.path) || branch.path.startsWith(fixed)
      })
      return found ? found.finding : ''
    },

    get selectionControl () {
      return this.selection.some(rule => this.sensitiveFinding(rule.method, rule.path) === 'account-control')
    },

    get selectionBilling () {
      return this.selection.some(rule => this.sensitiveFinding(rule.method, rule.path) === 'billing-access')
    },

    get selectedRules () {
      return this.selection.map(rule => ({
        key: `${rule.method} ${rule.path}`,
        method: rule.method,
        methodClass: `method method-${rule.method.toLowerCase()}`,
        path: rule.path,
        broad: this.broadRule(rule.path),
        className: this.broadRule(rule.path) ? 'rule broad' : 'rule'
      }))
    },

    get hasSelection () {
      return this.selection.length > 0
    },

    get noSelection () {
      return this.selection.length === 0
    },

    get selectionLabel () {
      return this.labels.selectionCount(this.selection.length)
    },

    get selectionBroad () {
      return this.selection.some(rule => this.broadRule(rule.path))
    },

    showCreate () {
      this.switchScreen('create')
      this.refreshHandoff()
    },

    // The address is forged by the backend and rendered as a real link rather than opened
    // from script: a window opened after an await is no longer part of the click that asked
    // for it, and a browser is right to refuse it. The rules only change in the explorer, so
    // the link is rebuilt on arriving here rather than on every toggle.
    async refreshHandoff () {
      this.handoffError = ''
      if (this.selection.length === 0) {
        this.handoffUrl = ''
        return
      }
      await sessionRequest
      try {
        const response = await fetch('/api/handoff', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'X-Keymaker-Csrf': this.csrf, 'Content-Type': 'application/json' },
          body: JSON.stringify({ rules: this.selection })
        })
        const payload = await response.json()
        if (!response.ok) {
          this.handoffUrl = ''
          this.handoffError = this.wordProblem(payload)
          return
        }
        this.handoffUrl = payload.url || ''
      } catch (failure) {
        this.handoffUrl = ''
        this.handoffError = this.labels.unreachable
      }
    },

    get handoffReady () {
      return this.handoffUrl !== ''
    },

    // Red is kept for what went wrong. An empty selection is not an error: step one already
    // says, in plain text right above, that the rules come first.
    get handoffProblem () {
      return this.handoffError
    },

    get publicAddressKnown () {
      return this.publicAddress !== ''
    },

    get addressCopyLabel () {
      return this.addressCopied ? this.labels.rulesCopied : this.labels.rulesCopy
    },

    // The address is going to be typed into a field on another site, which is the one case
    // where a copy button earns its place: the value is long, exact, and unforgiving of a
    // digit dropped in transit.
    async copyAddress () {
      try {
        await navigator.clipboard.writeText(this.publicAddress)
        this.addressCopied = true
        this.addressError = ''
      } catch (refused) {
        this.addressCopied = false
        this.addressError = this.labels.rulesCopyFailed
      }
    },

    // Shown rather than filled in: the page this link leads to has its own address field and
    // does not accept one from the link, so the most this can do is put the value in front
    // of the reader while they are there.
    async showAddress () {
      this.addressError = ''
      try {
        const response = await fetch('/api/address', { credentials: 'same-origin' })
        const payload = await response.json()
        if (!response.ok) {
          this.addressError = this.wordProblem(payload)
          return
        }
        this.publicAddress = payload.address || ''
        this.addressCopied = false
      } catch (failure) {
        this.addressError = this.labels.unreachable
      }
    },

    // The explorer is where rules are chosen; this only moves the reader to the screen that
    // turns them into a key, so the two never hold separate lists.
    useSelection () {
      this.switchScreen('create')
      this.refreshHandoff()
    },

    backToExplorer () {
      this.switchScreen('explorer')
    },

    get onCreate () {
      return this.screen === 'create' && this.retired === null
    },

    get labels () {
      return dictionaries[this.lang]
    },

    // The API answers with a code and an English sentence. The code is what gets worded
    // here; the sentence is only the fallback for a code this version does not know, which
    // is better than showing nothing at all.
    // A problem about one entry of what was sent names it, so the reader knows which line to fix.
    wordProblem (payload) {
      const known = this.labels.problems[payload && payload.code]
      if (typeof known === 'function') return known(payload.entry || '')
      return known || (payload && payload.error) || this.labels.unreachable
    },

    get languages () {
      return languages.map(language => ({
        code: language.code,
        name: language.name,
        short: language.short,
        flagClass: language.flag,
        className: language.code === this.lang ? 'chosen' : ''
      }))
    },

    get currentLanguage () {
      return this.languages.find(language => language.code === this.lang) || this.languages[0]
    },

    get languagesExpanded () {
      return this.languagesOpen ? 'true' : 'false'
    },

    get themeButtons () {
      return {
        system: this.theme === 'system' ? 'chosen' : '',
        light: this.theme === 'light' ? 'chosen' : '',
        dark: this.theme === 'dark' ? 'chosen' : ''
      }
    },

    get viewButtons () {
      return {
        list: this.view === 'list' ? 'chosen' : '',
        grid: this.view === 'grid' ? 'chosen' : ''
      }
    },

    get cardsClass () {
      return `cards ${this.view}`
    },

    get noticed () {
      return this.notice !== ''
    },

    get confirmingCredential () {
      return this.credentials.find(item => item.id === this.confirming) || null
    },

    get confirmingTitle () {
      const found = this.confirmingCredential
      return found ? (this.applicationName(found)) : ''
    },

    get confirmingReference () {
      return this.confirming === null ? '' : '#' + this.confirming
    },

    get confirmingPrompt () {
      return this.labels.revokePrompt(this.confirmingReference)
    },

    // The identifier has to be typed out, so that confirming is a deliberate act rather than a
    // reflex on a button. The # is how the interface writes it, not part of it: a
    // reader typing the digits alone has typed the identifier and is not left facing a disabled
    // button with no reason given.
    get confirmMatches () {
      if (this.confirming === null) return false
      const typed = this.confirmText.trim().replace(/^#/, '')
      return typed === String(this.confirming)
    },

    // Said once the reader has typed about as much as the identifier holds, not from the first
    // keystroke, when every prefix is still a mismatch.
    get confirmHint () {
      if (this.confirming === null || this.confirmMatches) return ''
      const typed = this.confirmText.trim().replace(/^#/, '')
      if (typed.length < String(this.confirming).length) return ''
      return this.labels.revokeMismatch(this.confirmingReference)
    },

    get confirmBlocked () {
      return !this.confirmMatches || this.revoking
    },

    get confirmFailed () {
      return this.confirmError !== ''
    },

    get confirmLabel () {
      return this.revoking ? this.labels.revoking : this.labels.revoke
    },

    // The link is worth putting in front of the reader whenever the API refused something:
    // whichever of the two causes it was, issuing a key with the right rules settles it.
    get offerRenewal () {
      return Boolean(this.error) && Boolean(this.managementKeyUrl)
    },

    get failed () {
      return this.error !== ''
    },

    get ready () {
      return !this.loading && this.error === ''
    },

    get hasRows () {
      return this.ready && this.matched.length > 0
    },

    get empty () {
      return this.ready && this.credentials.length > 0 && this.matched.length === 0
    },

    get countLabel () {
      return this.labels.shown(this.matched.length, this.credentials.length)
    },

    // Compact, pressable, and scannable in one pass: a label and its count. The sentence
    // that used to fill each row said the same thing at six times the size and read as an
    // alert rather than as a control; it is one hover away, and it is spelled out under the
    // row once a filter is on.
    get quickFilters () {
      const counts = this.summary.counts || {}
      return findingOrder
        .filter(code => counts[code] > 0)
        .map(code => {
          const finding = this.labels.findings[code]
          const selected = this.finding === code
          const classes = ['filter', this.severityOf(code)]
          if (selected) classes.push('selected')
          return {
            key: code,
            code,
            selected,
            label: finding.label,
            count: counts[code],
            hint: finding.clause(counts[code]),
            className: classes.join(' ')
          }
        })
    },

    get hasQuickFilters () {
      return this.summary.total > 0 && this.summary.flagged > 0
    },

    // What the chosen filter actually means. Shown only once one is on, so the row stays
    // quiet until the reader asks it something.
    get selectedHint () {
      const finding = this.labels.findings[this.finding]
      return finding ? finding.explanation : ''
    },

    // The two things that are statements rather than filters keep a line of their own.
    // Without the identity of the key in use, the marks and the offers that depend on it are
    // missing, and nothing else on the page would say so.
    get identityNotice () {
      return this.ready && this.current === null && this.credentials.length > 0 ? this.labels.identityUnknown : ''
    },

    get unreadableNotice () {
      const count = this.summary.unreadable || 0
      return count > 0 ? this.labels.unreadableKeys(count) : ''
    },

    get summaryNotice () {
      if (this.summary.total === 0) return this.labels.noKeys
      if (this.summary.flagged === 0) return this.labels.nothingToReport
      return ''
    },

    pickFilter () {
      const picked = this.filter.code
      this.finding = picked === this.finding ? '' : picked
    },

    // Whether anything is narrowing the list, so the way back out is offered only when
    // there is something to come back from.
    get filtering () {
      return this.search !== '' || this.status !== '' || this.application !== '' ||
        this.finding !== '' || this.band !== ''
    },

    // The metrics are the coarse filter, the findings below them the fine one. Each tile
    // carries a label and a shape beside its colour, so the band never rests on hue alone.
    get metrics () {
      const total = this.summary.total || 0
      const risk = this.summary.atRisk || 0
      const watch = Math.max((this.summary.flagged || 0) - risk, 0)

      return [
        this.metric('', total, this.labels.metricTotal, this.labels.bandAllHint, 'all'),
        this.metric('risk', risk, this.labels.metricAtRisk, this.labels.bandRiskHint, 'risk'),
        this.metric('watch', watch, this.labels.metricWatch, this.labels.bandWatchHint, 'watch'),
        this.metric('clean', Math.max((this.summary.examined || 0) - (this.summary.flagged || 0), 0), this.labels.metricClean, this.labels.bandCleanHint, 'clean')
      ]
    },

    metric (band, value, label, hint, tone) {
      const selected = this.band === band
      const classes = ['metric', tone]
      if (selected) classes.push('selected')
      if (!value) classes.push('empty')
      return { band, value, label, hint, selected, className: classes.join(' ') }
    },

    // The split of the account in one line: a cell per key, in the order of the bands, so the
    // share of keys that deserve attention reads at a glance. Keys the audit does not read sit
    // at the end, in grey. One cell per key rather than one sized bar per band, which would
    // need an inline style the content security policy refuses.
    get splitCells () {
      const risk = this.summary.atRisk || 0
      const watch = Math.max((this.summary.flagged || 0) - risk, 0)
      const clean = Math.max((this.summary.examined || 0) - (this.summary.flagged || 0), 0)
      const rest = Math.max((this.summary.total || 0) - risk - watch - clean, 0)

      const cells = []
      for (const [tone, count] of [['risk', risk], ['watch', watch], ['clean', clean], ['rest', rest]]) {
        for (let i = 0; i < count; i++) cells.push({ key: `${tone}-${i}`, className: `cell ${tone}` })
      }
      return cells
    },

    get hasSplit () {
      return (this.summary.total || 0) > 0
    },

    pickMetric () {
      const picked = this.tile.band
      this.band = picked === this.band ? '' : picked
    },

    // A release number is shown with a leading v, the way a tag is written, and a development
    // build under its own name. Nothing is shown until the session has answered: an empty
    // string is better than a wrong number.
    get versionLabel () {
      if (!this.version) return ''
      return /^\d/.test(this.version) ? 'v' + this.version : this.version
    },

    // A select holding a value looks like one holding its default, and the reader then has
    // to read every control to know what is narrowing the list. Sort is left out: it
    // reorders, it never hides anything.
    get statusFilterClass () {
      return this.status ? 'select on' : 'select'
    },

    get applicationFilterClass () {
      return this.application ? 'select on' : 'select'
    },

    get branchFilterClass () {
      return this.routeBranch ? 'select on' : 'select'
    },

    get methodFilterClass () {
      return this.routeMethod ? 'select on' : 'select'
    },

    get statusOptions () {
      const options = [{ value: '', label: this.labels.anyStatus }]
      for (const value of ['validated', 'pendingValidation', 'expired', 'refused']) {
        options.push({ value, label: this.labels.statuses[value] })
      }
      if (this.credentials.some(item => item.application.deleted)) {
        options.push({ value: 'orphaned', label: this.labels.orphanedStatus })
      }
      return options
    },

    // The status a key is filtered by is the one it is shown with: a key whose application
    // was deleted still reads as validated in the API, and opens nothing.
    statusOf (item) {
      return item.application.deleted ? 'orphaned' : item.status
    },

    get applicationOptions () {
      const names = new Set()
      for (const item of this.credentials) {
        names.add(this.applicationName(item))
      }

      const options = [{ value: '', label: this.labels.anyApplication }]
      for (const name of [...names].sort((a, b) => a.localeCompare(b, this.lang))) {
        options.push({ value: name, label: name })
      }
      return options
    },

    get sortOptions () {
      return [
        { value: 'attention', label: this.labels.sortAttention },
        { value: 'lastUse', label: this.labels.sortLastUse }
      ]
    },

    // Every key the filters keep, in order. The counts and the controls read this; the cards
    // drawn are the first of them only.
    get matched () {
      const needle = this.search.trim().toLowerCase()
      const matched = this.credentials.filter(item => this.matches(item, needle))

      if (this.sort === 'attention') {
        matched.sort((a, b) => this.weigh(b) - this.weigh(a) || this.used(b) - this.used(a))
      } else {
        matched.sort((a, b) => this.used(b) - this.used(a))
      }
      return matched
    },

    get visible () {
      return this.matched.slice(0, this.keyBudget).map(item => this.present(item))
    },

    get keysGrowing () {
      return this.hasRows && this.keyBudget < this.matched.length
    },

    // The three bands partition the usable keys: each is in exactly one. Showing overlapping
    // counts side by side is what made the old header read as more keys than the account
    // holds. An expired, refused or pending key is not audited, so it is in none of them:
    // counted as nothing flagged, a key that grants nothing was the reassuring figure.
    // A key whose application was deleted reads as validated and opens nothing.
    applicationName (item) {
      if (item.application.name) return item.application.name
      return item.application.deleted ? this.labels.deletedApplication : this.labels.unnamedApplication
    },

    bandOf (item) {
      if (item.status !== 'validated' || item.application.deleted) return 'unexamined'
      if (item.findings.some(finding => finding.severity === 'risk')) return 'risk'
      return item.findings.length ? 'watch' : 'clean'
    },

    severityOf (code) {
      for (const item of this.credentials) {
        for (const finding of item.findings) {
          if (finding.code === code) return finding.severity
        }
      }
      return 'note'
    },

    weigh (item) {
      let weight = 0
      for (const finding of item.findings) {
        weight += severityRank[finding.severity] || 0
      }
      return weight
    },

    used (item) {
      return item.lastUsedAt ? new Date(item.lastUsedAt).getTime() : 0
    },

    matches (item, needle) {
      if (this.status !== '' && this.statusOf(item) !== this.status) return false

      const name = this.applicationName(item)
      if (this.application !== '' && name !== this.application) return false

      if (this.finding !== '' && !item.findings.some(finding => finding.code === this.finding)) return false

      if (this.band !== '' && this.bandOf(item) !== this.band) return false

      if (needle === '') return true
      const haystack = [
        String(item.id),
        name,
        item.application.description || '',
        item.application.key || '',
        ...item.rules.map(rule => `${rule.method} ${rule.path}`),
        ...item.allowedIps
      ].join(' ').toLowerCase()
      return haystack.includes(needle)
    },

    present (item) {
      // The list view is for scanning, so it folds the rules away entirely and the count
      // becomes the way in. The card view shows the first few.
      const open = this.rulesOpen(item.id)
      const folded = this.view === 'list' ? 0 : collapsedRules
      const rules = open ? item.rules : item.rules.slice(0, folded)
      const orphaned = Boolean(item.application.deleted)
      const inert = item.status === 'expired' || item.status === 'refused' || orphaned
      const edit = item.editAddresses || { allowed: false, reason: 'inactive' }

      const classes = ['credential']
      if (item.self) classes.push('is-self')
      if (inert) classes.push('is-inert')

      return {
        id: item.id,
        self: item.self,
        external: Boolean(item.application.external),
        title: this.applicationName(item),
        reference: '#' + item.id,
        // A missing description is already a finding on a usable key; the sentence stands in
        // only where the audit said nothing, on a key it does not examine.
        description: orphaned
          ? ''
          : item.application.description ||
            (item.findings.some(finding => finding.code === 'no-description') ? '' : this.labels.noDescriptionText),
        orphaned,
        statusLabel: orphaned ? this.labels.orphanedStatus : this.labels.statuses[item.status] || item.status,
        statusClass: `pill status ${orphaned ? 'inactive' : statusTone(item.status)}`,
        cardClass: classes.join(' '),
        hasFindings: item.findings.length > 0,
        findings: item.findings.map(finding => ({
          code: finding.code,
          label: this.labels.findings[finding.code].label,
          expanded: this.explained[item.id] === finding.code ? 'true' : 'false',
          className: `finding ${finding.severity}`
        })),
        explanation: this.explained[item.id] ? this.labels.findings[this.explained[item.id]].explanation : '',
        reasonOpen: !item.revoke.allowed && Boolean(this.reasons[item.id]),
        reasonExpanded: this.reasons[item.id] ? 'true' : 'false',
        allowedIps: item.allowedIps.length ? item.allowedIps.join(', ') : this.labels.unrestricted,
        ipsClass: item.allowedIps.length ? '' : 'absent',
        created: this.relative(item.createdAt, this.labels.never),
        createdExact: this.exact(item.createdAt),
        expires: this.relative(item.expiresAt, this.labels.noExpiry),
        expiresExact: this.exact(item.expiresAt),
        expiresClass: item.expiresAt ? '' : 'absent',
        lastUsed: this.relative(item.lastUsedAt, this.labels.never),
        lastUsedExact: this.exact(item.lastUsedAt),
        rules: rules.map(rule => ({
          method: rule.method,
          path: rule.path,
          methodClass: `method method-${rule.method.toLowerCase()}`
        })),
        unneeded: (item.unneeded || []).map(rule => ({
          key: `${rule.method} ${rule.path}`,
          method: rule.method,
          path: rule.path,
          methodClass: `method method-${rule.method.toLowerCase()}`
        })),
        hasUnneeded: (item.unneeded || []).length > 0,
        revokeOffered: item.revoke.allowed,
        // The key in use is never offered the ordinary revocation: it gets the way out instead.
        revokeRefused: !item.revoke.allowed && !item.self,
        leaveOffered: item.self,
        revokeReason: this.labels.revokeUnavailableRule,
        addressList: item.allowedIps.join('\n'),
        addressesOffered: edit.allowed,
        // An inactive key is not offered the editor at all: there is nothing to explain.
        addressesRefused: !edit.allowed && edit.reason !== 'inactive',
        addressesReason: edit.reason === 'lookup-off' ? this.labels.addressesUnavailableLookup : this.labels.addressesUnavailableRule,
        addressReasonOpen: !edit.allowed && Boolean(this.addressReasons[item.id]),
        addressReasonExpanded: this.addressReasons[item.id] ? 'true' : 'false',
        addressRuleLinked: !edit.allowed && edit.reason === 'missing-rule' && Boolean(this.addressReasons[item.id]) && this.addressKeyUrl !== '',
        rulesLabel: this.labels.rulesCount(item.rules.length),
        collapsible: item.rules.length > folded,
        rulesExpanded: open ? 'true' : 'false',
        toggleLabel: open ? this.labels.showFewer : this.labels.showAll
      }
    },

    relative (value, fallback) {
      const parsed = this.parse(value)
      if (!parsed) return fallback

      const distance = parsed.getTime() - Date.now()
      const units = [['year', 31536000000], ['month', 2592000000], ['day', 86400000], ['hour', 3600000]]
      const format = new Intl.RelativeTimeFormat(this.lang, { numeric: 'auto' })

      for (const [unit, span] of units) {
        if (Math.abs(distance) >= span) return format.format(Math.round(distance / span), unit)
      }
      return format.format(Math.round(distance / 60000), 'minute')
    },

    day (value) {
      const parsed = this.parse(value)
      if (!parsed) return ''
      return new Intl.DateTimeFormat(this.lang, { dateStyle: 'long', timeZone: 'UTC' }).format(parsed)
    },

    exact (value) {
      const parsed = this.parse(value)
      if (!parsed) return ''
      return new Intl.DateTimeFormat(this.lang, { dateStyle: 'full', timeStyle: 'short' }).format(parsed)
    },

    parse (value) {
      if (!value) return null
      const parsed = new Date(value)
      return Number.isNaN(parsed.getTime()) ? null : parsed
    }
  }))
})
