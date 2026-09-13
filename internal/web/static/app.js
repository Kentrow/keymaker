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

function preferredLanguage () {
  const stored = preferences.read('keymaker.language', '')
  if (languages.some(language => language.code === stored)) return stored
  return navigator.language && navigator.language.startsWith('fr') ? 'fr' : 'en'
}

const findingOrder = ['broad-access', 'no-ip-restriction', 'no-expiry', 'never-used', 'dormant', 'no-description']

const severityRank = { risk: 3, caution: 2, note: 1 }

// Four API statuses, three ways to read them: one is usable, one may still become usable,
// and the rest are over. The label keeps the API's own word; only the tone is grouped.
const statusTone = status => {
  if (status === 'validated') return 'active'
  if (status === 'pendingValidation') return 'pending'
  return 'inactive'
}

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
    revokeMismatch: reference => `That is not ${reference}. Type the identifier of this key, with or without the #.`,
    revoking: 'Revoking...',
    cancel: 'Cancel',
    revoked: reference => `Key ${reference} revoked.`,
    revokeUnavailable: 'revocation unavailable',
    sweepHeadline: n => n === 1 ? '1 inactive key' : `${n} inactive keys`,
    sweepWhy: 'Expired or refused, they open nothing. Revoking them clears the inventory and cuts no access.',
    sweepAction: 'Revoke them',
    sweepTitle: 'Revoke the inactive keys?',
    sweepWarning: 'This cannot be undone. These keys grant nothing today, so nothing stops working; what goes is the record of them.',
    sweepConfirm: n => n === 1 ? 'Revoke 1 key' : `Revoke ${n} keys`,
    sweeping: 'Revoking...',
    sweepDone: n => n === 1 ? '1 key revoked.' : `${n} keys revoked.`,
    sweepPartly: (done, refused) => `${done} revoked, ${refused} refused. The ones refused are still listed, each with its reason.`,
    sweepNone: 'No key was revoked.',
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
    revokeUnavailableSelf: 'This is the key the tool authenticates with. Revoking it would lock you out of this screen.',
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
    noDescriptionText: 'No description.',
    rulesCount: n => n === 1 ? '1 access rule' : `${n} access rules`,
    showAll: 'show all',
    showFewer: 'show fewer',
    shown: (shown, total) => shown === total ? `${total} shown` : `${shown} of ${total} shown`,
    statuses: {
      validated: 'active',
      pendingValidation: 'pending validation',
      expired: 'expired',
      refused: 'refused'
    },
    nothingToReport: 'Nothing to report. Every usable key is scoped, restricted and dated.',
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
      }
    },
    renewKey: 'Issue a new management key',
    renewHint: 'Opens the OVHcloud page for your region with exactly the permissions this tool needs, already filled in. Validate it, then put the three values in your ovh.conf and restart. Drop the DELETE line on that page if you would rather run without revocation.',
    metricWatch: 'To watch',
    metricClean: 'Nothing flagged',
    bandRiskHint: 'Keys reaching the whole account. One of these leaking costs you everything you can do.',
    bandWatchHint: 'Keys with something worth knowing about, none of it reaching the whole account.',
    bandCleanHint: 'Usable keys this audit has no reservation about. It does not mean they are needed. Expired, refused and pending keys are not audited and are not counted here.',
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
    handoffBlocked: 'Choose at least one access rule in the explorer first.',
    rulesNone: 'No rule chosen yet. Open the explorer and pick the routes this key needs.',
    rulesEdit: 'Change them in the explorer',
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
    selectionTitle: 'Selected rules',
    selectionEmpty: 'Nothing selected. Choose an operation on a route to add it.',
    selectionCount: n => n === 1 ? '1 rule' : `${n} rules`,
    ruleRemove: 'Remove',
    rulesClear: 'Clear',
    rulesCopy: 'Copy',
    rulesCopied: 'Copied.',
    rulesCopyFailed: 'The browser refused to write to the clipboard.',
    broadRule: 'reaches the whole account',
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
      'missing-token': 'This request did not carry the token handed to the page. Reload and try again.'
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
    revokeMismatch: reference => `Ce n’est pas ${reference}. Saisissez l’identifiant de cette clé, avec ou sans le #.`,
    revoking: 'Révocation...',
    cancel: 'Annuler',
    revoked: reference => `Clé ${reference} révoquée.`,
    revokeUnavailable: 'révocation indisponible',
    sweepHeadline: n => n === 1 ? '1 clé inactive' : `${n} clés inactives`,
    sweepWhy: 'Expirées ou refusées, elles n’ouvrent plus rien. Les révoquer nettoie l’inventaire et ne coupe aucun accès.',
    sweepAction: 'Les révoquer',
    sweepTitle: 'Révoquer les clés inactives ?',
    sweepWarning: 'L’opération est irréversible. Ces clés n’accordent plus rien aujourd’hui : rien ne cesse de fonctionner, c’est leur trace qui disparaît.',
    sweepConfirm: n => n === 1 ? 'Révoquer 1 clé' : `Révoquer ${n} clés`,
    sweeping: 'Révocation...',
    sweepDone: n => n === 1 ? '1 clé révoquée.' : `${n} clés révoquées.`,
    sweepPartly: (done, refused) => `${done} révoquée${done > 1 ? 's' : ''}, ${refused} refusée${refused > 1 ? 's' : ''}. Celles refusées restent listées, chacune avec sa raison.`,
    sweepNone: 'Aucune clé n’a été révoquée.',
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
    revokeUnavailableSelf: 'C’est la clé avec laquelle l’outil s’authentifie. La révoquer vous couperait l’accès à cet écran.',
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
    noDescriptionText: 'Aucune description.',
    rulesCount: n => n <= 1 ? `${n} droit d’accès` : `${n} droits d’accès`,
    showAll: 'tout afficher',
    showFewer: 'réduire',
    shown: (shown, total) => shown === total ? `${total} affichée${total > 1 ? 's' : ''}` : `${shown} sur ${total} affichée${total > 1 ? 's' : ''}`,
    statuses: {
      validated: 'active',
      pendingValidation: 'en attente de validation',
      expired: 'expirée',
      refused: 'refusée'
    },
    nothingToReport: 'Rien à signaler. Chaque clé utilisable est restreinte, datée et limitée à ce qu’elle appelle.',
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
      }
    },
    renewKey: 'Émettre une nouvelle clé de gestion',
    renewHint: 'Ouvre la page OVHcloud de votre région avec exactement les droits dont cet outil a besoin, déjà remplis. Validez-la, puis placez les trois valeurs dans votre ovh.conf et redémarrez. Retirez la ligne DELETE sur cette page si vous préférez fonctionner sans révocation.',
    metricWatch: 'À surveiller',
    metricClean: 'Sans réserve',
    bandRiskHint: 'Clés qui atteignent l’ensemble du compte. Si l’une fuite, elle coûte tout ce que vous pouvez faire.',
    bandWatchHint: 'Clés qui méritent un coup d’œil, sans atteindre l’ensemble du compte.',
    bandCleanHint: 'Clés utilisables sur lesquelles cet audit n’a pas de réserve. Cela ne veut pas dire qu’elles sont utiles. Les clés expirées, refusées ou en attente ne sont pas auditées et ne sont pas comptées ici.',
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
    handoffBlocked: 'Choisissez d’abord au moins un droit d’accès dans l’explorateur.',
    rulesNone: 'Aucun droit retenu. Ouvrez l’explorateur et choisissez les routes dont cette clé a besoin.',
    rulesEdit: 'Les modifier dans l’explorateur',
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
    selectionTitle: 'Droits retenus',
    selectionEmpty: 'Rien de retenu. Choisissez une opération sur une route pour l’ajouter.',
    selectionCount: n => n <= 1 ? `${n} droit` : `${n} droits`,
    ruleRemove: 'Retirer',
    rulesClear: 'Vider',
    rulesCopy: 'Copier',
    rulesCopied: 'Copié.',
    rulesCopyFailed: 'Le navigateur a refusé l’écriture dans le presse-papiers.',
    broadRule: 'porte sur tout le compte',
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
      'missing-token': 'Cette requête ne portait pas le jeton remis à la page. Rechargez, puis réessayez.'
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
    notice: '',
    confirming: null,
    confirmText: '',
    confirmError: '',
    revoking: false,
    sweepAsked: false,
    replacing: null,
    sweeping: false,
    sweepError: '',
    expanded: {},
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
      for (const filter of ['routeSearch', 'routeBranch', 'routeMethod', 'routeDeprecated']) {
        this.$watch(filter, () => this.resetRoutes())
      }
      this.$watch('confirming', target => this.toggleDialog(this.$refs.revokeDialog, target !== null))
      this.$watch('sweepAsked', asked => this.toggleDialog(this.$refs.sweepDialog, asked))
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

    toggleRules () {
      this.expanded[this.row.id] = !this.expanded[this.row.id]
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
      } catch (failure) {
        this.confirmError = this.labels.unreachable
      } finally {
        this.revoking = false
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

    get inactiveHeadline () {
      return this.labels.sweepHeadline(this.inactiveKeys.length)
    },

    get sweepRows () {
      return this.inactiveKeys.map(item => ({
        key: item.id,
        reference: '#' + item.id,
        title: item.application.name || this.labels.unnamedApplication,
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

    clearFilters () {
      this.search = ''
      this.status = ''
      this.application = ''
      this.finding = ''
      this.band = ''
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
        const title = document.querySelector(`[data-screen-title="${screen}"]`)
        if (title) title.focus({ preventScroll: true })
      })
    },

    showInventory () {
      this.switchScreen('inventory')
    },

    // One reload for every screen. A button that appears and disappears moves the rest of
    // the header under the pointer, and reloading is meaningful on all three.
    refresh () {
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
        create: this.screen === 'create' ? 'segment chosen' : 'segment'
      }
    },

    get onInventory () {
      return this.screen === 'inventory'
    },

    get onExplorer () {
      return this.screen === 'explorer'
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
      const classes = ['method', `method-${operation.method.toLowerCase()}`]
      if (chosen) classes.push('chosen')
      if (operation.deprecated) classes.push('deprecated')
      return {
        method: operation.method,
        description: operation.description,
        deprecated: operation.deprecated,
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

    get handoffProblem () {
      if (this.handoffError) return this.handoffError
      return this.selection.length === 0 ? this.labels.handoffBlocked : ''
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
      return this.screen === 'create'
    },

    get labels () {
      return dictionaries[this.lang]
    },

    // The API answers with a code and an English sentence. The code is what gets worded
    // here; the sentence is only the fallback for a code this version does not know, which
    // is better than showing nothing at all.
    wordProblem (payload) {
      const known = this.labels.problems[payload && payload.code]
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
      return found ? (found.application.name || this.labels.unnamedApplication) : ''
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
      return this.ready && this.visible.length > 0
    },

    get empty () {
      return this.ready && this.credentials.length > 0 && this.visible.length === 0
    },

    get countLabel () {
      return this.labels.shown(this.visible.length, this.credentials.length)
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
      return options
    },

    get applicationOptions () {
      const names = new Set()
      for (const item of this.credentials) {
        names.add(item.application.name || this.labels.unnamedApplication)
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

    get visible () {
      const needle = this.search.trim().toLowerCase()
      const matched = this.credentials.filter(item => this.matches(item, needle))

      if (this.sort === 'attention') {
        matched.sort((a, b) => this.weigh(b) - this.weigh(a) || this.used(b) - this.used(a))
      } else {
        matched.sort((a, b) => this.used(b) - this.used(a))
      }
      return matched.map(item => this.present(item))
    },

    // The three bands partition the usable keys: each is in exactly one. Showing overlapping
    // counts side by side is what made the old header read as more keys than the account
    // holds. An expired, refused or pending key is not audited, so it is in none of them:
    // counted as nothing flagged, a key that grants nothing was the reassuring figure.
    bandOf (item) {
      if (item.status !== 'validated') return 'unexamined'
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
      if (this.status !== '' && item.status !== this.status) return false

      const name = item.application.name || this.labels.unnamedApplication
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
      const open = Boolean(this.expanded[item.id])
      const folded = this.view === 'list' ? 0 : collapsedRules
      const rules = open ? item.rules : item.rules.slice(0, folded)
      const inert = item.status === 'expired' || item.status === 'refused'

      const classes = ['credential']
      if (item.self) classes.push('is-self')
      if (inert) classes.push('is-inert')

      return {
        id: item.id,
        self: item.self,
        external: Boolean(item.application.external),
        title: item.application.name || this.labels.unnamedApplication,
        reference: '#' + item.id,
        // A missing description is already a finding on a usable key; the sentence stands in
        // only where the audit said nothing, on a key it does not examine.
        description: item.application.description ||
          (item.findings.some(finding => finding.code === 'no-description') ? '' : this.labels.noDescriptionText),
        statusLabel: this.labels.statuses[item.status] || item.status,
        statusClass: `pill status ${statusTone(item.status)}`,
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
        revokeOffered: item.revoke.allowed,
        revokeRefused: !item.revoke.allowed,
        revokeReason: item.revoke.reason === 'self' ? this.labels.revokeUnavailableSelf : this.labels.revokeUnavailableRule,
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
