# Warden — état d'avancement

Warden est un EDR autonome pour workstations Linux, écrit en Rust. Ce
fichier existe pour reprendre le projet proprement après une coupure de
session — le lire en entier avant de continuer.

L'utilisateur a donné le feu vert pour travailler en autonomie complète
(core, agents, DAST, SAST, GUI, tests réels en conteneurs, YARA/Sigma,
tout) sans notifier chaque avancée dans le chat — un point d'étape complet
suffit. Priorité explicite : **finir tous les agents de détection + le core
d'abord, GUI ensuite, `install.sh` en tout dernier.**

## Module réseau + SAST — faits et validés (reprise après pause)

**Module réseau** (`ebpf-probe/warden-network-ebpf` + `warden-network`,
même structure que le module exec) : hook sur le tracepoint
`sock:inet_sock_set_state`, ne traite que la transition vers
`TCP_SYN_SENT` (pas `TCP_ESTABLISHED` - cette dernière est souvent
atteinte de façon asynchrone dans un contexte softirq quand le SYN-ACK
arrive, où le pid "courant" n'est plus celui qui a initié la connexion).
Résout `/proc/<pid>/exe` côté userspace et applique la même heuristique de
localisation suspecte que le module exec (`warden_common::heuristics::is_suspicious_exec_location`,
maintenant partagée par les deux modules) - défense en profondeur : si un
process depuis `/tmp` ouvre une connexion sortante, tué + binaire
quarantiné, même si le module exec ne l'avait pas déjà attrapé au
lancement.

**Bug réel trouvé et corrigé par test** : le champ `common_pid` du
tracepoint (offset 4, documenté dans son propre format) donnait une valeur
absurde (négative, et IDENTIQUE pour deux process pourtant différents) une
fois lu côté eBPF - alors que `dport`/`daddr` lus depuis le même tracepoint
étaient corrects, écartant un bug d'offset généralisé. Remplacé par
`bpf_get_current_pid_tgid() >> 32`, lu depuis la tâche en cours plutôt que
depuis l'enregistrement de trace - l'approche standard qu'utilisent aussi
bcc/bpftrace pour ce tracepoint précis. Revalidé par test : pid correct
pour deux connexions simultanées distinctes.

**Bug structurel réel trouvé et corrigé dans `ebpf-probe/Cargo.toml`** :
un `cargo build`/`test`/`clippy` NU (sans `-p`) à la racine du workspace
tentait de compiler les crates `*-ebpf` (`#![no_std]`/`#![no_main]`) pour
la cible hôte par défaut - échec direct ("unwinding panics are not
supported without std" en build, "undefined symbol: main" en test), plus
une collision de nom de binaire de sortie entre `warden-exec` (userspace)
et le bin du crate `warden-exec-ebpf` qui porte le même nom. L'hypothèse
initiale ("un build nu ne les touche jamais, seul le build.rs les
compile") était fausse et corrigée en le testant réellement. Fix :
`default-members = ["warden-exec", "warden-network"]` dans
`ebpf-probe/Cargo.toml` - les crates `*-ebpf` restent des `members`
(donc toujours accessibles via `-p` explicite ou via le `build.rs`), mais
un `cargo build`/`test`/`clippy` sans arguments ne cible plus qu'elles.

**Testé en conditions réelles** (conteneur `--privileged --pid=host`,
tracefs monté, listener `nc -l` local) : connexion depuis `/usr/bin/nc`
(légitime) jamais flaguée ; le même binaire copié vers `/tmp` et utilisé
pour se connecter → détecté, tué, quarantiné en Enforce. `cargo test`
(9 tests sur tout `ebpf-probe/` : 6 exec + 3 network) et `cargo clippy`
propres sur les 4 crates (2 userspace + 2 kernel, ces derniers avec leur
target/toolchain propres).

**SAST intégré** : `cargo-audit` installé (persisté dans le volume
`warden-cargo-home`), `scripts/check-updates.sh` écrit et testé de bout
en bout - vérifie la correspondance LLVM/nightly (voir plus haut) ET lance
`cargo audit` sur les deux workspaces (le principal ET `ebpf-probe/`).
Résultat actuel : **0 vulnérabilité connue**, toolchain eBPF toujours
aligné (LLVM 23/LLVM 23). À relancer périodiquement, surtout après tout
`cargo update` ou changement de toolchain.

## Module privesc — fait, mais PAS en fanotify (limitation kernel réelle, pas un choix)

Nouveau crate `warden-privesc` (dans le workspace principal, pas
`ebpf-probe/` - pas besoin d'eBPF pour celui-ci). Détecte l'apparition
d'un bit setuid/setgid : sur un binaire système déjà connu (technique
GTFOBins, ex. `chmod +s /usr/bin/find`) → le bit est retiré (Enforce),
le binaire n'est jamais supprimé ; sur un fichier tout nouveau dans
`/tmp`, `/var/tmp`, `/dev/shm` ou `$HOME` (ex. copie de bash + `chmod +s`)
→ mis en quarantaine comme les autres modules "nouveau fichier".

**Tentative fanotify abandonnée après un vrai test, pas une supposition** :
`FAN_ATTRIB` échoue systématiquement avec `EINVAL`, quel que soit le scope
du mark (filesystem-wide OU un simple dossier non-récursif) - confirmé en
isolant le test (`FAN_MODIFY` marche en contrôle, `FAN_ATTRIB` échoue
systématiquement, y compris combiné à `FAN_EVENT_ON_CHILD`/`FAN_ONDIR`).
Raison : `FAN_ATTRIB` fait partie des "directory entry events" du kernel
qui nécessitent que le groupe fanotify soit initialisé avec
`FAN_REPORT_FID` - un flag que les bindings `nix` 0.31.3 n'exposent PAS
dans `InitFlags` (vérifié dans le source de la crate). Contourner ça
demanderait soit des appels syscall bruts (et `nix` ne sait de toute façon
pas parser le format d'event FID différent que ça produirait), soit un
hook eBPF sur la famille de syscalls `chmod`. Les deux sont plus lourds
que ce qu'une surface privesc (pas aussi time-critique qu'un ransomware
actif ou un exec/connexion en direct) justifie pour une première version.

**Solution retenue : polling toutes les 5 secondes.** Plus simple, correct,
sans acrobaties sur les syscalls. Modèle d'état à deux ensembles :
`baseline` (immuable, établi une fois au démarrage - tout ce qui est déjà
setuid/setgid à ce moment-là est présumé légitime pour toujours) et
`already_flagged` (mutable, évite de re-notifier à chaque tick de 5s pour
une même anomalie non résolue, réinitialisé dès que le fichier disparaît
du scan - une vraie ré-infection après remédiation redevient un incident
neuf).

**Bug réel trouvé et corrigé en testant** : `/bin` et `/sbin` sont des
symlinks vers `/usr/bin`/`/usr/sbin` sur toute distro usr-merge (la
plupart des distros modernes). Sans déduplication, le même fichier
physique était scanné deux fois sous deux chemins différents,
produisant deux détections pour un seul `chmod +s` (`/usr/bin/find` ET
`/bin/find` flagués séparément, vu en pratique). Corrigé en canonicalisant
et dédupliquant les dossiers de watch avant le scan (`known_suid_sgid`
est passé de 22 à 11 après le fix - preuve que le doublon existait bel et
bien, pas juste une hypothèse).

**Testé en conditions réelles** (conteneur `--privileged`, `mode=enforce`) :
- Binaire déjà setuid au démarrage (`/usr/bin/passwd`) re-touché →
  jamais flagué (baseline).
- Binaire système gagnant le bit pour la première fois
  (`chmod +s /usr/bin/find`, technique GTFOBins) → détecté Critical, bit
  retiré, binaire toujours présent et fonctionnel.
- Nouveau fichier setuid dans `/tmp` (bash copié + `chmod +s`) → détecté
  Critical, **mis en quarantaine** (jamais de kill pour ce module : le
  polling ne fournit aucun PID, contrairement à fanotify), fichier
  effectivement retiré de `/tmp`.

**`warden-core/src/main.rs` refactorisé** : avec un 3ème module, dupliquer
le pattern manuel "spawn + oneshot ready + branche `select!`" par module
devenait source d'erreurs (exactement le genre de bug que je viens de
corriger dans la logique privesc elle-même). Remplacé par un superviseur
générique basé sur `tokio::task::JoinSet<(&'static str, Result<()>)>` +
une fonction `spawn_module` réutilisable - le nom du module transite dans
la valeur de retour de la tâche elle-même, donc `JoinSet::join_next`
identifie directement quel module vient de se terminer sans table de
correspondance séparée à tenir à jour.

## Module YARA — fait et validé

Nouveau crate `warden-yara` (workspace principal), même pattern fanotify
que ransomware (`FAN_CLOSE_WRITE`, mount-dedup, filtrage userspace) mais
scanne le fichier fermé avec `yara-x` (réimplémentation pure Rust de YARA,
compile les conditions de règles en WASM exécuté via `wasmtime` en interne
- pas quelque chose qu'on pilote directement) au lieu de calculer
l'entropie. Watch dirs par défaut : `Downloads`, `Desktop`, `Documents`
sous `$HOME`, + `/tmp`. Jamais de kill (contrairement à ransomware) : le
process qui a fermé le fichier (navigateur, `curl`, gestionnaire de
téléchargement) n'a fait qu'écrire le contenu, il ne l'exécute pas -
`response::handle_file_only_detection` (quarantine seule) suffit et évite
de tuer un programme par ailleurs parfaitement légitime.

**Règles intégrées** (`warden-yara/rules/builtin.yar`, testées
individuellement contre des échantillons réalistes avant intégration, pas
juste écrites à l'aveugle) : fichier de test EICAR (le standard de
l'industrie AV, inoffensif par design), reverse shell bash
(`/dev/tcp`+`exec`), reverse shell netcat (`-e`), reverse shell Python
(`socket`+`dup2`+`pty.spawn`), webshell PHP obfusqué
(`eval`/`system`+`base64_decode`+`$_POST`), pipe base64→shell. Extensible
via `/etc/warden/yara-rules/*.yar` (custom_rules_dir configurable),
compilés en plus du set intégré au démarrage.

**Dépendances allégées, un vrai souci trouvé et corrigé** : les features
par défaut de `yara-x` tirent les modules PE/Mach-O/.NET/DEX/CRX/LNK
(parsers de formats binaires Windows/macOS/Android) et leur crypto
associée (RSA, X.509, ECDSA, DSA) - rien de pertinent pour un EDR
workstation Linux dont les règles ne référencent que du texte/regex.
Compilé avec `default-features = false` + seulement
`constant-folding, exact-atoms, fast-regexp, generate-proto-code,
elf-module, string-module, hash-module, math-module, time-module` -
confirmé par test que ça retire bien `rsa`/`x509-parser`/`ecdsa`/`dsa`/
`zip`/`uuid`/`roxmltree` de l'arbre de dépendances sans casser la
compilation ni les règles. `wasmtime` reste : ce n'est pas un module
optionnel, c'est le moteur d'exécution central de yara-x pour TOUTE
condition de règle, impossible à retirer.

**Finding SAST réel traité, pas juste ignoré** : `cargo audit` a remonté
`RUSTSEC-2026-0222` (wasmtime "Stores can mix up type indices between
engines", CVSS 3.8 bas, `AV:L/AC:H/PR:H/UI:R` - accès local, complexité
et privilèges élevés ET interaction utilisateur requis) tiré
transitivement par `yara-x` 1.19.0 (déjà la dernière version disponible,
pas de fix à obtenir en bumpant). Le bug ne se manifeste que si
l'application mélange plusieurs instances `wasmtime::Engine` - yara-x
n'en utilise qu'une en interne, donc pas atteignable via notre usage.
Décision documentée (pas un silence) dans `.cargo/audit.toml` avec le
raisonnement complet et un rappel de réévaluer dès qu'une nouvelle
version de `yara-x` sort. Un warning "unmaintained" séparé sur `bincode`
(transitif via wasmtime aussi) reste affiché mais ne fait pas échouer le
check (politique par défaut de `cargo audit` pour les advisories de type
"warning").

**Testé en conditions réelles** (conteneur, `mode=enforce`) : fichier
EICAR déposé dans `Downloads` → détecté (`Eicar_Test_File`), quarantiné,
retiré du dossier. Script reverse-shell bash déposé → détecté
(`Bash_Dev_Tcp_Reverse_Shell`), quarantiné. Fichier texte ordinaire →
jamais touché. Confirmé aussi que plusieurs modules fanotify indépendants
(ransomware ET yara, groupes fanotify séparés) peuvent surveiller le même
mount avec des masques d'events différents sans conflit - le honeypot de
ransomware (`.warden_canary`) reste intact et non perturbé par le module
yara tournant en parallèle sur le même dossier.

## Règle absolue de workflow

**Rien ne compile ni ne s'exécute jamais sur l'hôte.** Le code est écrit et
édité ici, dans `/home/user/warden`, mais :
- **build** → uniquement dans le conteneur `warden-build:rockylinux`
- **run/test** → uniquement dans les conteneurs de test par distro

Commande de build de référence (3 volumes persistants à toujours monter
ensemble pour ne pas perdre rustup/clippy/le registry cargo entre les
runs) :
```
docker run --rm -v /home/user/warden:/build \
  -v warden-cargo-registry:/usr/local/cargo/registry \
  -v warden-cargo-home:/usr/local/cargo \
  -v warden-rustup-home:/usr/local/rustup \
  -w /build warden-build:rockylinux cargo build --release
```
Clippy (une fois par volume neuf) : `rustup component add clippy` puis
`cargo clippy --release --all-targets`.

## Architecture générale

Workspace Cargo principal à 6 crates (plus le workspace séparé
`ebpf-probe/` pour les modules exec/network, voir plus bas) :
- `warden-common` — types partagés (`DetectionEvent`, `Severity`, `Mode`),
  et les briques réutilisables par tout module de détection :
  `process::stop_then_kill`, `quarantine::Quarantine`,
  `permissions::strip_setuid_setgid`, `heuristics` (localisations
  suspectes, partagé entre plusieurs modules), `target::resolve` (résolution
  de l'utilisateur cible), `response::handle_detection` (réponse avec PID,
  kill+quarantine), `response::handle_file_only_detection` (réponse SANS
  PID, quarantine seule — voir point 6 ci-dessous), `notify::Notifier`.
- `warden-ransomware` — détection ransomware par fanotify, porté et adapté
  de RansomShield (`/home/user/ransomshield`, projet séparé, jamais modifié
  par Warden).
- `warden-persistence` — détection de persistance par inotify (bashrc,
  cron, autostart XDG, unités systemd, sudoers, authorized_keys,
  ld.so.preload). Détails complets plus bas.
- `warden-privesc` — détection SUID/SGID par polling (pas fanotify, voir
  section dédiée plus haut pour pourquoi).
- `warden-yara` — scan YARA (`yara-x`) des fichiers nouvellement écrits
  dans Downloads/Desktop/Documents/tmp, par fanotify.
- `warden-core` — binaire `warden` : config TOML, résolution de
  l'utilisateur cible, orchestrateur multi-module (`tokio::task::JoinSet`),
  dispatcher d'events.

### Décisions d'architecture importantes (et pourquoi)

1. **Réponse synchrone dans le module détecteur, jamais via le channel
   async.** Un module qui a besoin d'agir vite (tuer un process, mettre en
   quarantaine) le fait directement dans son propre thread bloquant, puis
   construit un `DetectionEvent` envoyé au dispatcher *seulement* pour
   log/notif/historique futur. Un design où le module "proposerait" une
   action exécutée plus tard par le dispatcher via channel async a été
   rejeté : latence inacceptable face à une menace active.

2. **fanotify (ransomware) marque tout le mount, filtré en userspace.**
   `$HOME` d'une workstation est presque toujours sur la partition racine,
   donc `FAN_MARK_FILESYSTEM` watche tout `/`. On filtre en userspace
   (`fanotify_monitor::is_under_watch_dirs`) pour ne traiter que les events
   sous les dossiers réellement configurés (canonicalisés, `~` expansé
   manuellement puisque TOML n'est pas un shell).

3. **inotify (persistence) watche des DOSSIERS, jamais des fichiers
   directement.** De nombreux éditeurs sauvegardent en écrivant un fichier
   temporaire puis en le renommant à la place de l'original — ça remplace
   l'inode et invaliderait silencieusement un watch posé sur le fichier
   lui-même. On watche systématiquement le dossier parent (`$HOME`,
   `~/.ssh`, `/etc`, `/etc/cron.d`, etc.) et on filtre par nom de fichier
   côté userspace, exactement le même principe que le filtrage fanotify.

4. **Notification desktop via zbus, connexion explicite au bus de session
   de l'utilisateur cible** (`unix:path=/run/user/<uid>/bus`), jamais de
   découverte auto via `DBUS_SESSION_BUS_ADDRESS` (pointerait vers rien
   pour un service root). Testé : échoue proprement (log warn, pas de
   crash) sans session graphique — comportement attendu, pas encore
   revalidé avec un vrai DE simulé.

5. **`target_user` explicite en config, pas d'auto-détection.** Root n'a
   pas de `$HOME` personnel à protéger. Résolu via
   `nix::unistd::User::from_name` → uid + home dir.

6. **Persistence n'a JAMAIS de PID et ne tue donc jamais de process.**
   Contrairement à fanotify, inotify ne rapporte pas le PID de l'auteur
   d'un changement. `warden_common::response::handle_file_only_detection`
   existe spécifiquement pour ça : jamais d'appel à `stop_then_kill`.
   Piège explicitement évité : passer un PID factice comme `0` à un chemin
   qui tue des process aurait envoyé le signal à *tout le groupe de
   process appelant* (sémantique POSIX de `kill(0, sig)`) — potentiellement
   Warden lui-même. Le champ `pid` de `DetectionEvent` est un `Option<i32>`
   précisément pour ça (pas de sentinelle `0`/`-1` ambiguë dans les types
   partagés ; `-1` n'apparaît que comme valeur opaque dans le nom de
   fichier de quarantaine, jamais passé à un signal).

7. **Persistence distingue `Dotfile` (report-only, toujours) de `UnitDir`
   (quarantinable si nouveau fichier, en mode Enforce).** Éditer
   `~/.bashrc`/`authorized_keys`/`/etc/sudoers` en place n'est jamais
   automatiquement annulé (risque de casser une vraie modification
   utilisateur, et pour sudoers : un revert raté peut verrouiller tous les
   admins hors de sudo). Un *nouveau* fichier apparaissant dans un
   `UnitDir` (cron.d, sudoers.d, autostart, unités systemd) est en
   revanche sûr à mettre en quarantaine tel quel : rien de légitime n'y
   stocke de vrai travail, le fichier EST le mécanisme de persistance ou
   il ne l'est pas.

8. **Capacités systemd : `CAP_SYS_ADMIN`, `CAP_KILL`, `CAP_DAC_OVERRIDE`.**
   Le troisième a été ajouté après un vrai bug trouvé en testant en
   conteneur : `$HOME` est en `0700` par défaut (`useradd -m`), et sans
   `CAP_DAC_OVERRIDE`, même root reçoit `EACCES`. Ne pas retirer cette
   capability sans re-tester contre un `$HOME` en 0700.

## Bugs réels trouvés et corrigés en testant (pas juste écrits puis oubliés)

- **`CAP_DAC_OVERRIDE` manquante** → root ne pouvait pas lire un `$HOME` en
  0700 (mode par défaut de `useradd -m` sur toute distro). Trouvé en
  testant dans un conteneur Debian réel, pas en relisant le code.
- **Duplication de détections persistence** : une seule opération d'écriture
  (`printf ... > f`) déclenche plusieurs events inotify (IN_CREATE puis
  IN_MODIFY/IN_CLOSE_WRITE) souvent regroupés dans le même batch
  `read_events()`. Traiter chaque event indépendamment produisait deux
  détections différentes (contenu partiel puis complet) pour un seul
  changement ressenti par l'utilisateur. Corrigé par dédoublonnage par
  chemin au sein d'un même batch (`seen_this_batch`), en relisant toujours
  le contenu final sur disque au moment du traitement.
- **Faux-négatif de sécurité en mode Enforce (le plus sérieux)** : le tout
  premier event pour un nouveau fichier (IN_CREATE, fichier encore vide à
  0 octet car le contenu n'a pas encore été flush par l'écrivain) était
  traité, produisait un diff vide, et **committait quand même une entrée
  baseline vide** avant de passer au event suivant. Ça marquait
  silencieusement le chemin comme "déjà connu", donc l'event suivant
  (contenu réel complet) était traité comme une *édition* d'un fichier
  préexistant plutôt que sa vraie première apparition — pour un `UnitDir`,
  ça faisait sauter la quarantaine automatique en Enforce. Reproduit de
  façon fiable (fichier autostart malveillant jamais mis en quarantaine),
  corrigé en ne committant la baseline pour un chemin encore inconnu que
  si le contenu lu est non-vide. Revalidé par test après le fix : le même
  scénario met désormais correctement le fichier en quarantaine.

## Ce qui est fait et validé par test (pas juste écrit)

Testé dans `docker/Dockerfile.test.debian` (conteneur Debian, utilisateur
`tester` avec `$HOME` en 0700, binaire lancé directement avec
`--cap-add SYS_ADMIN --cap-add KILL --cap-add DAC_OVERRIDE --cap-drop ALL`) :

**Ransomware :**
- Mode Monitor : rafale de 5 fichiers haute-entropie par un seul process
  (Perl, un seul PID — un test avec `head` en boucle bash avait d'abord
  donné un faux négatif car chaque `head` est un PID différent, confirmant
  que le tracking per-PID marche comme prévu) → détection, event au
  dispatcher, notif desktop échoue proprement (pas de session graphique).
- Mode Enforce : process attaquant simulé tué après exactement 5 fichiers
  sur 20 prévus (exit code 137), 5 fichiers quarantainés + manifest JSONL.
- Re-testé après l'ajout du module persistence (non-régression) : toujours
  OK.

**Persistence :**
- `.bashrc` : injection de ligne `curl | bash` → détectée High, jamais
  quarantainée (Dotfile), même en Enforce.
- `authorized_keys` : ajout de clé SSH inconnue → détectée High,
  report-only.
- `/etc/ld.so.preload` : apparition → détectée High, report-only.
- `/etc/cron.d/*` nouveau fichier (y compris rafale de 5 fichiers
  simultanés) → détecté, quarantainé en Enforce.
- `~/.config/autostart/*.desktop` nouveau, `Exec=` pointant vers `/tmp/` →
  détecté High (motif "chemin d'exécution suspect"), quarantainé en
  Enforce.
- `~/.config/systemd/user/*.service` nouveau avec `ExecStart=curl|bash` →
  détecté High, quarantainé en Enforce.
- `/etc/sudoers.d/*` nouveau fichier → détecté Critical, quarantainé en
  Enforce (seulement si le dossier existe déjà au démarrage - voir gaps).
- Édition anodine (`alias gs="git status"`) → détectée Medium générique,
  pas de faux "High".

`cargo test` (10 tests unitaires : 3 entropy + 4 heuristics persistence + 3
diff persistence) : OK. `cargo clippy --all-targets` sur tout le workspace :
propre, 0 warning après corrections.

## Toolchain eBPF — validé de bout en bout (docker/Dockerfile.build-ebpf)

Le blocage initial était côté HÔTE uniquement (pas de rustup) ; aucun
blocage réel dans un conteneur Docker dédié. Toolchain fonctionnel construit
et **validé par un chargement réel dans le kernel**, pas juste compilé :

- Base Debian bookworm, LLVM 23 installé via `apt.llvm.org` (script `llvm.sh
  23`), rustup avec toolchain stable (pour `bpf-linker`) + nightly +
  `rust-src` (pour compiler la cible `bpfel-unknown-none` via `-Z
  build-std=core`), `cargo install bpf-linker --no-default-features
  --features llvm-23`.
- **Piège découvert par test, pas évident à l'avance** : `bpf-linker` doit
  être lié contre la MÊME version majeure de LLVM que celle embarquée dans
  le rustc nightly actif (`rustup run nightly rustc --version --verbose` →
  `LLVM version: 23.1.0`), sinon erreur cryptique `ERROR llvm: Invalid
  record` au link. Comme les toolchains nightly changent de version LLVM
  interne au fil du temps, **revérifier cette correspondance avant de
  réutiliser cette image après une longue pause** (voir section
  "Maintenance" plus bas).
- **Piège Docker découvert par test** : ne jamais monter les volumes
  `warden-cargo-home`/`warden-rustup-home` (ceux du conteneur RockyLinux
  stable) sur le conteneur `warden-build:ebpf` — ça masque le nightly +
  bpf-linker installés dans l'image avec un volume vide d'un autre
  toolchain. Pour ce conteneur, monter uniquement `warden-cargo-registry`
  (cache de paquets, sans rapport avec le toolchain, sans risque).
- Crates : `aya` 0.14.0 / `aya-ebpf` 0.2.1 / `aya-build` 0.2.0 (gère la
  compilation croisée de la crate eBPF via `build.rs`, voir
  `ebpf-probe/warden-exec/build.rs`).
- **`aya-log`/`aya-log-ebpf` (0.3.0/0.2.0) cassent le chargement** :
  `BPF_PROG_LOAD` échoue avec `fd 10 is not pointing to valid bpf_map`
  (vérifié par test, pas juste supposé). Contournement adopté pour la
  probe de validation : pas de `aya-log`, une simple map `Array<u64>`
  incrémentée côté kernel et lue en polling côté userspace. Marche
  parfaitement. À creuser avant d'utiliser `aya-log` dans un vrai module
  (bug de version, ou map créée dans le mauvais ordre - pas encore
  diagnostiqué).
## Module exec (`ebpf-probe/`) — implémenté et validé end-to-end

`ebpf-probe/` reste un **workspace séparé** de celui principal de warden
(voir "Pourquoi `ebpf-probe/` reste un workspace séparé" plus bas pour la
raison structurelle - ce n'est pas un oubli). Deux crates :

- `warden-exec-ebpf` (programme kernel) : tracepoint
  `sched:sched_process_exec`, parse le champ `__data_loc filename` du
  format tracepoint (vérifié via `/sys/kernel/tracing/events/sched/
  sched_process_exec/format` - offset 8 = `__data_loc` du filename, offset
  12 = pid) via `bpf_probe_read_kernel_str_bytes` (pas la variante
  `bpf_probe_read_kernel_str`, dépréciée), pousse `{pid, filename}` dans
  une `RingBuf`.
- `warden-exec` (loader userspace) : charge/attache la probe, lit la
  `RingBuf` en async via `tokio::io::unix::AsyncFd`, résout `target_user`
  (config TOML partagée avec le `warden` principal - seuls `mode` et
  `target_user` sont lus, le reste ignoré par serde), flague toute
  exécution depuis un chemin suspect (`warden_common::heuristics`,
  factorisé et réutilisé aussi par le module persistence) ou depuis
  `~/Downloads` du `target_user`, puis appelle
  `warden_common::response::handle_detection` (kill + quarantine du
  binaire exécuté) - **contrairement à persistence, ce module A un PID
  fiable** (fourni par le tracepoint), donc peut légitimement tuer le
  process, pas juste observer.

**Testé en conditions réelles**, pas juste compilé :
- `cargo test -p warden-exec` : 6/6 (parsing d'event, détection de
  chemin suspect).
- `cargo clippy` propre sur les deux crates (le crate kernel avec son
  toolchain/target propres : `rustup run nightly cargo clippy --target
  bpfel-unknown-none -Z build-std=core`, sinon clippy tente de le
  compiler pour l'hôte et échoue - "unwinding panics are not supported
  without std", pas un vrai bug).
- Chargé dans un vrai conteneur privilégié avec `/sys/kernel/debug` et
  `/sys/kernel/tracing` montés : exécution d'un faux malware depuis
  `/tmp` → tué + binaire quarantiné en quelques millisecondes ; exécutions
  normales (`whoami`, `ls`, `cat`) jamais touchées.
- **Piège de test découvert et documenté** : sans `--pid=host` sur le
  conteneur de test, le kill échoue avec `ESRCH` - eBPF rapporte le PID
  *global de l'hôte* (le kernel n'est pas namespace-aware pour les
  tracepoints), alors que le process warden-exec tournant dans un
  conteneur voit son PROPRE PID namespace. Sur un vrai déploiement
  (systemd sur la machine hôte, sans conteneur), ce problème n'existe pas
  puisqu'il n'y a qu'un seul PID namespace - mais tout test futur de ce
  module doit utiliser `--pid=host` pour être représentatif.

**Capacités utilisées pour le test** : `--privileged` (large, pour aller
vite). Pas encore réduit à l'ensemble minimal réel (`CAP_BPF` +
`CAP_PERFMON` + `CAP_KILL` + accès tracefs probablement suffisant sur
kernel 5.8+) - à déterminer avant d'écrire l'unit systemd de ce module.

**`aya-log` toujours cassé** (voir plus haut, `fd 10 is not pointing to
valid bpf_map`) - non utilisé, pas nécessaire pour ce module qui pousse
des données structurées via sa propre `RingBuf`, pas des logs texte.

### Pourquoi `ebpf-probe/` reste un workspace séparé (pas un oubli)

`warden-exec-ebpf` est `#![no_std]` et ne peut être compilé QUE pour la
cible `bpfel-unknown-none` via nightly + `-Z build-std=core` - le
compiler pour la cible hôte (ce qu'un `cargo build --release` nu à la
racine d'un workspace ferait pour TOUS ses membres) échoue purement et
simplement. Si `warden-exec-ebpf`/`warden-exec` rejoignaient le workspace
principal (celui de `warden-build:rockylinux`, toolchain stable
uniquement, pas de nightly/bpf-linker), la commande de build habituelle
`cargo build --release` casserait. `warden-exec` dépend bien de
`warden-common` par chemin relatif (`../../warden-common`) et se compile
très bien avec le toolchain stable de `warden-build:ebpf` (Debian
bookworm a aussi un rustc stable normal) - seul le crate kernel a besoin
du nightly, via le `build.rs` de `warden-exec` (`aya-build`) qui shell-out
vers `rustup run nightly cargo build --target bpfel-unknown-none`,
une invocation cargo totalement séparée qui ne pollue jamais la
résolution du workspace principal.

**Prochaine étape** : soit garder `warden-exec` comme binaire/service
systemd autonome (notifie via son propre `Notifier`, pas de bus
d'événements partagé avec `warden-core` pour l'instant - duplication
mineure et acceptée pour l'instant), soit construire un bus d'événements
local (socket Unix, JSON ligne par ligne) une fois que 2-3 modules eBPF
de plus existent et que la duplication commence à peser - pas fait
maintenant, noté comme refacto propre à venir.

## Maintenance et mises à jour (question posée par l'utilisateur, à traiter sérieusement)

Warden aura besoin d'un vrai cycle de maintenance, pas d'un build unique :
- **Dépendances Rust** : `Cargo.lock` est committé exprès pour des builds
  reproductibles ; toute mise à jour doit être délibérée (bump +
  re-test complet sur la matrice de conteneurs), jamais un `cargo update`
  aveugle sur un outil qui tourne en root. `aya` est encore pré-1.0 (0.14.x)
  et casse son API entre versions mineures - étudier le changelog avant de
  bumper.
- **Pin LLVM/nightly pour le toolchain eBPF** : le plus fragile des deux
  toolchains. Avant de reconstruire `warden-build:ebpf` après une longue
  pause, revérifier `rustup run nightly rustc --version --verbose` contre
  la version LLVM installée dans le Dockerfile - un nightly plus récent
  peut embarquer une version LLVM différente et recasser `bpf-linker`.
- **Tâche restant à faire** (demandée explicitement par l'utilisateur) :
  un mécanisme simple pour vérifier rapidement "y a-t-il une mise à jour à
  appliquer" et l'appliquer vite. Idée pas encore implémentée : un script
  `scripts/check-updates.sh` qui lance `cargo outdated`/`cargo audit` sur
  le workspace principal ET sur `ebpf-probe/`, et vérifie la correspondance
  LLVM/nightly ci-dessus automatiquement (compare la version LLVM du
  nightly actif à celle indiquée dans `Dockerfile.build-ebpf`). Pas encore
  écrit - à faire.
- Module privesc : **fait pour SUID/SGID** (voir plus haut, polling 5s -
  fanotify `FAN_ATTRIB` s'est révélé impossible avec les bindings `nix`
  actuels, pas juste "pas encore évalué"). Pas encore couvert :
  capabilities Linux via `setcap` (`getcap`/`setcap` sur un binaire,
  vecteur privesc équivalent au SUID mais orthogonal, même limitation
  fanotify probable), transitions uid inattendues (nécessiterait eBPF,
  voir le module exec pour le pattern à réutiliser).
- Module réseau : **fait** (voir plus haut) - couvre les connexions TCP
  sortantes (IPv4/IPv6) depuis un binaire en localisation suspecte. Pas
  encore couvert : UDP, connexions entrantes/écoute (utile pour détecter
  un binaire malveillant qui ouvre un port en backdoor), et une liste
  blanche pour les faux positifs légitimes (ex. un vrai outil de backup
  qui tournerait depuis un chemin inhabituel).
- YARA / Sigma / signatures binaires — pas commencé (explicitement
  "si trop difficile, on skip" selon l'utilisateur, mais à tenter).
- Détection fileless (navigateur, documents piégés) — **partiellement
  couvert** par les modules exec + réseau (exécution et connexions
  sortantes depuis `/tmp`, `/dev/shm`, `~/Downloads`). Ce qui manque
  encore : visibilité sur la chaîne parent→enfant (ex. navigateur qui
  spawn un shell) et sur le contenu réellement piégé d'un document avant
  exécution (couverture a priori, pas juste a posteriori).
- Gap connu et documenté (pas un bug) : un dossier persistence qui
  n'existe pas au démarrage (`/etc/cron.d`, `/etc/sudoers.d`, etc. sur un
  système qui ne les a pas encore) n'est surveillé qu'après un redémarrage
  du service, pas rétroactivement. Confirmé par test explicite. Contrairement
  au module ransomware, ce module ne crée jamais de dossier manquant
  lui-même (créer `/etc/sudoers.d` serait too invasif pour un EDR).
- `install.sh` — **volontairement repoussé en tout dernier**, après GUI,
  sur directive explicite de l'utilisateur ("faire en sorte que tous les
  agents et le core soient parfaits, puis la GUI, puis le script"). Un
  premier brouillon existe déjà (`/home/user/warden/install.sh`, inspiré de
  celui de RansomShield) mais n'est pas la priorité tant que les modules
  de détection ne sont pas exhaustifs.
- Dockerfiles de test pour les 6 autres distros de la matrice (Ubuntu,
  Fedora, RockyLinux, AlmaLinux, Arch, openSUSE Tumbleweed) — seul Debian
  existe, et en version simplifiée (binaire lancé direct, pas de systemd
  PID1 complet comme RansomShield le fait). Vrai test systemd multi-distro
  à faire une fois `install.sh` repris.
- Test de la notif desktop avec une vraie session graphique/DE simulée —
  seul le cas "pas de session" (échec propre) a été testé.
- SAST : **fait pour cargo-audit** (voir plus haut,
  `scripts/check-updates.sh`). `cargo-deny` (licences + bans de crates,
  au-delà des seules CVE) pas encore ajouté - amélioration possible mais
  pas critique.
- GUI de contrôle — explicitement après les agents/core.
- Intégration GitHub (repo distant, CI) — pas abordé.

## Images et volumes Docker déjà créés sur cette machine

- `warden-build:rockylinux` — conteneur de build principal (rustc 1.97.1
  stable, clippy + **cargo-audit** installés dans le volume
  `warden-rustup-home`/`warden-cargo-home`)
- `warden-build:ebpf` — conteneur de build eBPF (Debian bookworm, nightly +
  rust-src + bpf-linker(LLVM 23) + clippy pour les deux toolchains,
  baked-in dans l'image elle-même, ne PAS monter
  `warden-cargo-home`/`warden-rustup-home` dessus - voir la section
  toolchain eBPF plus haut pour pourquoi)
- `warden-test:debian` — smoke test (reconstruire après tout changement de
  code : `docker build -t warden-test:debian -f docker/Dockerfile.test.debian .`)
- volumes : `warden-cargo-registry` (partagé, sans risque sur tous les
  conteneurs), `warden-cargo-home` + `warden-rustup-home` (réservés à
  `warden-build:rockylinux`, jamais montés sur `warden-build:ebpf`)
- Images de distro déjà disponibles pour construire les futurs Dockerfiles
  de test : debian, ubuntu, fedora, rockylinux, almalinux, archlinux,
  opensuse/tumbleweed sont toutes déjà pull. Alpine dispo mais hors
  périmètre officiel (musl + OpenRC, pas systemd).

## Vision GUI de l'utilisateur (à garder en tête, pas encore commencé)

Décrite explicitement par l'utilisateur : une appli GUI **séparée** du
démon (démon = root, GUI = utilisateur normal), qui apparaît dans le menu
applications/recherche du DE (fichier `.desktop`), montre l'état/historique,
permet des actions live (quarantaine manuelle, whitelist, changement de
mode). Les notifications desktop doivent être **actionnables** : cliquer
dessus ouvre la GUI directement sur le détail de cet incident précis, puis
on peut revenir au tableau de bord et naviguer vers d'autres menus.

Trois prérequis côté démon identifiés (pas encore construits) avant de
pouvoir attaquer la vraie GUI :
1. **Socket de contrôle** (`/run/warden/control.sock`) - la GUI doit
   pouvoir interroger le démon root et déclencher des actions. Bien
   restreindre les permissions à l'utilisateur cible.
2. **Notifications actionnables** - `Notifier` ne fait actuellement que
   `Notify()` fire-and-forget. Il faudra écouter le signal D-Bus
   `ActionInvoked` du serveur de notifications et faire le lien avec
   l'ID de l'incident correspondant.
3. **Historique persistant des events** - actuellement chaque détection
   part dans les logs journald uniquement. Il faut un stockage
   (SQLite ou JSONL) alimenté par le dispatcher pour que la GUI ait
   quelque chose à interroger.

Toolkit GUI pas encore tranché - GTK4/libadwaita pressenti pour un look
natif GNOME, à confirmer quand on y sera vraiment.

**Branding — fait et validé par l'utilisateur.** 4 pistes explorées via
un canvas de design (bouclier plein+serrure, contour minimal, écrou
hexagonal "clin d'œil Rust", lockup+palette). L'utilisateur a choisi :
- **Logo officiel** = concept 1 "Solid + Keyhole" (bouclier rouge plein,
  serrure ambre au centre) → `branding/logo.svg` + `branding/logo.png`.
- **Bannière** = concept 4 "Lockup" (le logo + wordmark "WARDEN" en
  JetBrains Mono + tagline "AUTONOMOUS LINUX EDR") → `branding/banner.svg`
  + `branding/banner.png`.

Palette retenue : `#8c1f1b` (fond de tuile), `#c33a2e` (bouclier),
`#d9a441` (accent ambre/serrure), `#101114` (fond sombre). Les 4 concepts
explorés restent dans `branding/` sous leurs noms d'origine
(`1-solid-keyhole`, `2-outline`, `3-rustnod`, `4-lockup`) pour référence/
archivage. Pas encore fait : export multi-résolutions (16/32/48/64/128/256
px) pour l'icône d'appli GNOME/KDE - à faire quand la GUI sera vraiment
attaquée, pas urgent maintenant.

## Prochaine session : par où reprendre

1. Évaluer une détection Sigma simplifiée (YARA fait, voir plus haut).
2. Privesc : capabilities Linux (`setcap`) en complément du SUID/SGID.
3. Commencer les 3 prérequis GUI ci-dessus (socket de contrôle,
   notifications actionnables, historique persistant) - c'est encore du
   "core", pas la GUI elle-même, donc compatible avec la priorité
   "agents + core d'abord".
4. GUI de contrôle proprement dite (après le point 3). Logo déjà prêt
   (`branding/logo.svg`), à intégrer comme icône d'appli à ce moment-là.
5. `install.sh` finalisé + Dockerfiles de test systemd pour les 7 distros
   (repoussé en tout dernier sur directive explicite de l'utilisateur).
6. `cargo-deny` en complément de `cargo-audit` (licences, bans de crates).
